from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import base64
import json
import httpx
import logging
import pandas as pd
import os
import rsa

app = FastAPI()

# Setup logging
logging.basicConfig(level=logging.DEBUG, filename='app.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

#interface

class DataDescription(BaseModel):
        codeType: str
        encryptCode: str
        zipCode: str

class Data(BaseModel):
        content: str
        signature: str
        dataDescription: DataDescription

class ExtendField(BaseModel):
        responseDateFormat: str
        responseTimeFormat: str
        referenceNo: str
        operatorName: str
        offlineInvoiceException: Optional[dict]

class GlobalInfo(BaseModel):
        appId: str
        version: str
        dataExchangeId: str
        interfaceCode: str
        requestCode: str
        requestTime: str
        responseCode: str
        userName: str
        deviceMAC: str
        deviceNo: str
        tin: str
        brn: str
        taxpayerID: str
        longitude: str
        latitude: str
        agentType: str
        extendField: ExtendField

class ReturnStateInfo(BaseModel):
        returnCode: str
        returnMessage: str


        # Additional fields from the JSON structure if any
        # Add them here as needed

class ResponseModel(BaseModel):
        data: Data
        globalInfo: GlobalInfo
        returnStateInfo: ReturnStateInfo


#environment variables 
AES_KEY = bytes.fromhex(os.getenv('AES_KEY'))
IV = bytes.fromhex(os.getenv('IV'))
DeviceNo = bytes.fromhex(os.getenv('deviceNumber'))

class InputNumber(BaseModel):
    oriInvoiceNo: str
    invoiceNo: str
    deviceNo: str
    buyerTin: str
    buyerNinBrn: str
    buyerLegalName: str
    combineKeywords: str
    invoiceType: str
    invoiceKind: str
    isInvalid: str
    isRefund: str
    startDate: datetime
    endDate: datetime
    pageNo: int
    pageSize: int
    referenceNo: str
    branchName: str
    queryType: str
    dataSource: str
    sellerTinOrNin: str
    sellerLegalOrBusinessName: str

class NumberDetails(BaseModel):
    dateFormat: str
    nowTime: datetime
    pageCount: int
    pageNo: int
    pageSize: int
    totalSize: int
    records: List[dict]

number_details_list = []

def load_keys():
    with open("public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    with open("private.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    return public_key, private_key

# Function to encrypt data using AES and sign using RSA
async def encrypt_and_sign(data: str, private_key) -> dict:
    IV = get_random_bytes(AES.block_size)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    
    # Generate RSA signature for integrity verification
    signature = rsa.sign(encrypted_data, private_key, 'SHA-256')
    combined_data = {
        "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
        "iv": base64.b64encode(IV).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8')
    }
    
    return combined_data

# Function to verify RSA signature and decrypt data using AES
async def verify_and_decrypt(combined_data: dict, public_key) -> str:
    try:
        encrypted_data = base64.b64decode(combined_data["encrypted_data"])
        iv = base64.b64decode(combined_data["iv"])
        signature = base64.b64decode(combined_data["signature"])
        
        # Verify RSA signature
        rsa.verify(encrypted_data, signature, public_key)
        
        # Decrypt AES encrypted data
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode('utf-8')
        
        return decrypted_data
    except rsa.VerificationError:
        raise ValueError("Signature verification failed")
    except (ValueError, TypeError) as e:
        raise ValueError(f"Failed to decrypt: {e}")

async def send_number_to_external_system(interface_json_data) -> NumberDetails:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post("https://external-system-url/api", json={"number": interface_json_data})
            response.raise_for_status()
            data = await verify_and_decrypt(response.json())
            return NumberDetails(**data)
        except (httpx.HTTPStatusError, httpx.RequestError) as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=str(exc))

@app.post("/process-number/")
async def process_number(input_number: InputNumber):
    data = {
        "oriInvoiceNo": "00000000002",
        "invoiceNo": input_number.invoiceNo,
        "deviceNo": DeviceNo,
        "buyerTin": "7777777777",
        "buyerNinBrn": "00000000001",
        "buyerLegalName": "lisi",
        "combineKeywords": "7777777",
        "invoiceType": "1",
        "invoiceKind": "1",
        "isInvalid": "1",
        "isRefund": "1",
        "startDate": "2019-06-14",
        "endDate": "2019-06-15",
        "pageNo": "1",
        "pageSize": "10",
        "referenceNo": "425502528294126235",
        "branchName": "Mr. HENRY KAMUGISHA",
        "queryType": "1",
        "dataSource": "101",
        "sellerTinOrNin": "1009837013",
        "sellerLegalOrBusinessName": "CLASSY TRENDS BOUTIQUE"
    }
    
    input_json_data = json.dumps(data)
    encrypt_number = await encrypt_and_sign(input_json_data)
    
    logger.info(f"Item {encrypt_number} requested")
    interface_json_data= json.dumps()
    try:
        number_details = await send_number_to_external_system(interface_json_data)
        number_details_list.append(number_details.dict())
    except HTTPException as exc:
        return exc
    else:
        return number_details_list

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)


# interface_data = {
#         "data": {
#             "content": encrypt_number,
#             "signature": "JKQWJK34K32JJEK2JQWJ5678",
#             "dataDescription": {
#                 "codeType": "0",
#                 "encryptCode": "1",
#                 "zipCode": "0"
#             }
#         },
#         "globalInfo": {
#             "appId": "AP01",
#             "version": "1.1.20191201",
#             "dataExchangeId": "9230489223014123",
#             "interfaceCode": "T101",
#             "requestCode": "TP",
#             "requestTime": "2019-06-11 17:07:07",
#             "responseCode": "TA",
#             "userName": "admin",
#             "deviceMAC": "FFFFFFFFFFFF",
#             "deviceNo": "00022000634",
#             "tin": "1009830865",
#             "brn": "",
#             "taxpayerID": "1",
#             "longitude": "116.397128",
#             "latitude": "39.916527",
#             "agentType": "0",
#             "extendField": {
#                 "responseDateFormat": "dd/MM/yyyy",
#                 "responseTimeFormat": "dd/MM/yyyy HH:mm:ss",
#                 "referenceNo": "21PL010020807",
#                 "operatorName": "administrator",
#                 "offlineInvoiceException": {
#                     "errorCode": "",
#                     "errorMsg": ""
#                 }
#             }
#         },
#         "returnStateInfo": {
#             "returnCode": "",
#             "returnMessage": ""
#         }
#     }