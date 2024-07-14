
# Import statements remain the same
from dataclasses import Field, dataclass
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Any, List, Optional
from datetime import datetime
from uuid import UUID
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES
import base64
import json
import httpx
import logging
import pandas as pd
import os
import rsa
from dotenv import load_dotenv
load_dotenv()

app = FastAPI()

# Setup logging
logging.basicConfig(level=logging.DEBUG, filename='app.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

number_details_list = []


#interface body
@dataclass
class Data:
    content: str
    signature: str
    dataDescription: 'DataDescription'

    @staticmethod
    def from_dict(obj: Any) -> 'Data':
        _content = str(obj.get("content"))
        _signature = str(obj.get("signature"))
        _dataDescription = DataDescription.from_dict(obj.get("dataDescription"))
        return Data(_content, _signature, _dataDescription)

@dataclass
class DataDescription:
    codeType: str
    encryptCode: str
    zipCode: str

    #staticmethod
    def from_dict(obj: Any) -> 'DataDescription':
        _codeType = str(obj.get("codeType"))
        _encryptCode = str(obj.get("encryptCode"))
        _zipCode = str(obj.get("zipCode"))
        return DataDescription(_codeType, _encryptCode, _zipCode)

@dataclass
class ExtendField:
    responseDateFormat: str
    responseTimeFormat: str
    referenceNo: str
    operatorName: str
    offlineInvoiceException: 'OfflineInvoiceException'

    @staticmethod
    def from_dict(obj: Any) -> 'ExtendField':
        _responseDateFormat = str(obj.get("responseDateFormat"))
        _responseTimeFormat = str(obj.get("responseTimeFormat"))
        _referenceNo = str(obj.get("referenceNo"))
        _operatorName = str(obj.get("operatorName"))
        _offlineInvoiceException = OfflineInvoiceException.from_dict(obj.get("offlineInvoiceException"))
        return ExtendField(_responseDateFormat, _responseTimeFormat, _referenceNo, _operatorName, _offlineInvoiceException)

@dataclass
class GlobalInfo:
    appId: str #= "AP04"
    version: str #= "1.1.20191201"
    dataExchangeId: UUID
    interfaceCode: str
    requestCode: str
    requestTime: datetime
    responseCode: str
    userName: str
    deviceMAC: str #="FFFFFFFFFFFF"
    deviceNo: str 
    tin: str 
    brn: str
    taxpayerID: str
    longitude: float 
    latitude: float 
    agentType: str
    extendField: ExtendField

    @staticmethod
    def from_dict(obj: Any) -> 'GlobalInfo':
        _appId = str(obj.get("appId"))
        _version = str(obj.get("version"))
        _dataExchangeId = str(obj.get("dataExchangeId"))
        _interfaceCode = str(obj.get("interfaceCode"))
        _requestCode = str(obj.get("requestCode"))
        _requestTime = str(obj.get("requestTime"))
        _responseCode = str(obj.get("responseCode"))
        _userName = str(obj.get("userName"))
        _deviceMAC = str(obj.get("deviceMAC"))
        _deviceNo = str(obj.get("deviceNo"))
        _tin = str(obj.get("tin"))
        _brn = str(obj.get("brn"))
        _taxpayerID = str(obj.get("taxpayerID"))
        _longitude = str(obj.get("longitude"))
        _latitude = str(obj.get("latitude"))
        _agentType = str(obj.get("agentType"))
        _extendField = ExtendField.from_dict(obj.get("extendField"))
        return GlobalInfo(_appId, _version, _dataExchangeId, _interfaceCode, _requestCode, _requestTime, _responseCode, _userName, _deviceMAC, _deviceNo, _tin, _brn, _taxpayerID, _longitude, _latitude, _agentType, _extendField)

@dataclass
class OfflineInvoiceException:
    errorCode: str
    errorMsg: str

    @staticmethod
    def from_dict(obj: Any) -> 'OfflineInvoiceException':
        _errorCode = str(obj.get("errorCode"))
        _errorMsg = str(obj.get("errorMsg"))
        return OfflineInvoiceException(_errorCode, _errorMsg)

@dataclass
class ReturnStateInfo:
    returnCode: str
    returnMessage: str

    @staticmethod
    def from_dict(obj: Any) -> 'ReturnStateInfo':
        _returnCode = str(obj.get("returnCode"))
        _returnMessage = str(obj.get("returnMessage"))
        return ReturnStateInfo(_returnCode, _returnMessage)

@dataclass
class Inter_Face(BaseModel):
    data: Data
    globalInfo: GlobalInfo
    returnStateInfo: ReturnStateInfo

    #staticmethod
    def from_dict(obj: Any) -> 'Inter_Face':
        _data = Data.from_dict(obj.get("data"))
        _globalInfo = GlobalInfo.from_dict(obj.get("globalInfo"))
        _returnStateInfo = ReturnStateInfo.from_dict(obj.get("returnStateInfo"))
        return Inter_Face(_data, _globalInfo, _returnStateInfo)


#Request Body
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
    startDate: str
    endDate: str
    pageNo: str
    pageSize: str
    referenceNo: str
    branchName: str
    queryType: str
    dataSource: str
    sellerTinOrNin: str
    sellerLegalOrBusinessName: str

    @staticmethod
    def from_dict(obj):
        _oriInvoiceNo = str(obj.get("oriInvoiceNo"))
        _invoiceNo = str(obj.get("invoiceNo"))
        _deviceNo = str(obj.get("deviceNo"))
        _buyerTin = str(obj.get("buyerTin"))
        _buyerNinBrn = str(obj.get("buyerNinBrn"))
        _buyerLegalName = str(obj.get("buyerLegalName"))
        _combineKeywords = str(obj.get("combineKeywords"))
        _invoiceType = str(obj.get("invoiceType"))
        _invoiceKind = str(obj.get("invoiceKind"))
        _isInvalid = str(obj.get("isInvalid"))
        _isRefund = str(obj.get("isRefund"))
        _startDate = str(obj.get("startDate"))
        _endDate = str(obj.get("endDate"))
        _pageNo = str(obj.get("pageNo"))
        _pageSize = str(obj.get("pageSize"))
        _referenceNo = str(obj.get("referenceNo"))
        _branchName = str(obj.get("branchName"))
        _queryType = str(obj.get("queryType"))
        _dataSource = str(obj.get("dataSource"))
        _sellerTinOrNin = str(obj.get("sellerTinOrNin"))
        _sellerLegalOrBusinessName = str(obj.get("sellerLegalOrBusinessName"))
        # return InputNumber(_oriInvoiceNo, _invoiceNo, _deviceNo, _buyerTin, _buyerNinBrn, _buyerLegalName, _combineKeywords, _invoiceType, _invoiceKind, _isInvalid, _isRefund, _startDate, _endDate, _pageNo, _pageSize, _referenceNo, _branchName, _queryType, _dataSource, _sellerTinOrNin, _sellerLegalOrBusinessName)
        return _oriInvoiceNo, _invoiceNo, _deviceNo, _buyerTin, _buyerNinBrn, _buyerLegalName, _combineKeywords, _invoiceType, _invoiceKind, _isInvalid, _isRefund, _startDate, _endDate, _pageNo, _pageSize, _referenceNo, _branchName, _queryType, _dataSource, _sellerTinOrNin, _sellerLegalOrBusinessName



class Page(BaseModel):
    pageCount: int
    pageNo: int
    pageSize: int
    totalSize: int

    @staticmethod
    def from_dict(obj: Any) -> 'Page':
        _pageCount = int(obj.get("pageCount"))
        _pageNo = int(obj.get("pageNo"))
        _pageSize = int(obj.get("pageSize"))
        _totalSize = int(obj.get("totalSize"))
        return Page(_pageCount, _pageNo, _pageSize, _totalSize)

@dataclass
class Record:
    branchId: str
    branchName: str
    businessName: str
    buyerBusinessName: str
    buyerLegalName: str
    buyerTin: str
    currency: str
    dataSource: str
    dateFormat: str
    deviceNo: str
    grossAmount: str
    id: str
    invoiceIndustryCode: str
    invoiceKind: str
    invoiceNo: str
    invoiceType: str
    isInvalid: str
    isRefund: str
    issuedDate: str
    issuedDateStr: str
    legalName: str
    nowTime: str
    operator: str
    pageIndex: int
    pageNo: int
    pageSize: int
    referenceNo: str
    taxAmount: str
    uploadingTime: str
    userName: str

    @staticmethod
    def from_dict(obj: Any) -> 'Record':
        _branchId = str(obj.get("branchId"))
        _branchName = str(obj.get("branchName"))
        _businessName = str(obj.get("businessName"))
        _buyerBusinessName = str(obj.get("buyerBusinessName"))
        _buyerLegalName = str(obj.get("buyerLegalName"))
        _buyerTin = str(obj.get("buyerTin"))
        _currency = str(obj.get("currency"))
        _dataSource = str(obj.get("dataSource"))
        _dateFormat = str(obj.get("dateFormat"))
        _deviceNo = str(obj.get("deviceNo"))
        _grossAmount = str(obj.get("grossAmount"))
        _id = str(obj.get("id"))
        _invoiceIndustryCode = str(obj.get("invoiceIndustryCode"))
        _invoiceKind = str(obj.get("invoiceKind"))
        _invoiceNo = str(obj.get("invoiceNo"))
        _invoiceType = str(obj.get("invoiceType"))
        _isInvalid = str(obj.get("isInvalid"))
        _isRefund = str(obj.get("isRefund"))
        _issuedDate = str(obj.get("issuedDate"))
        _issuedDateStr = str(obj.get("issuedDateStr"))
        _legalName = str(obj.get("legalName"))
        _nowTime = str(obj.get("nowTime"))
        _operator = str(obj.get("operator"))
        _pageIndex = int(obj.get("pageIndex"))
        _pageNo = int(obj.get("pageNo"))
        _pageSize = int(obj.get("pageSize"))
        _referenceNo = str(obj.get("referenceNo"))
        _taxAmount = str(obj.get("taxAmount"))
        _uploadingTime = str(obj.get("uploadingTime"))
        _userName = str(obj.get("userName"))
        return Record(_branchId, _branchName, _businessName, _buyerBusinessName, _buyerLegalName, _buyerTin, _currency, _dataSource, _dateFormat, _deviceNo, _grossAmount, _id, _invoiceIndustryCode, _invoiceKind, _invoiceNo, _invoiceType, _isInvalid, _isRefund, _issuedDate, _issuedDateStr, _legalName, _nowTime, _operator, _pageIndex, _pageNo, _pageSize, _referenceNo, _taxAmount, _uploadingTime, _userName)

@dataclass
class NumberDetails(BaseModel):
    dateFormat: str
    nowTime: str
    page: Page
    records: List[Record]

    @staticmethod
    def from_dict(obj: Any) -> 'NumberDetails':
        _dateFormat = str(obj.get("dateFormat"))
        _nowTime = str(obj.get("nowTime"))
        _page = Page.from_dict(obj.get("page"))
        _records = [Record.from_dict(y) for y in obj.get("records")]
        return NumberDetails(_dateFormat, _nowTime, _page, _records)

def load_keys():
    with open("public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    with open("private.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    return public_key, private_key
    
AES_KEY = bytes.fromhex(os.getenv('AES_KEY', ''))
# AES_KEY = os.getenv('AES_KEY', '')
IV = bytes.fromhex(os.getenv('IV', ''))
# IV = os.getenv('IV', '')
deviceNumber = '12312'
# deviceNumber = bytes.fromhex(os.getenv('deviceNumber', ''))

# Function to encrypt data using AES-CBC mode
def encrypt_data(data: str, aes_key: bytes, iv: bytes) -> dict:
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    
    combined_data = {
        "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8')
    }
    return combined_data

# Signing function corrected
def sign_data(encrypted_data: str, private_key) -> str:
    encrypted_bytes = base64.b64decode(encrypted_data)
    signed = rsa.sign(encrypted_bytes, private_key, 'SHA-256')
    return signed

# Decryption and verification functions corrected
def decrypt_data(encrypted_data: bytes, iv: bytes, aes_key: bytes) -> str:
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode('utf-8')
    return decrypted_data

def verify_signature(encrypted_data: str, signature: str, public_key) -> None:
    encrypted_bytes = base64.b64decode(encrypted_data)
    signature_bytes = base64.b64decode(signature)
    rsa.verify(encrypted_bytes, signature_bytes, public_key)

async def send_number_to_external_system(Interface_json_data_sent) -> NumberDetails:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post("https://external-system-url/api", json=Interface_json_data_sent)
            response.raise_for_status()
            
            if response.status_code == 200:
                response_data = response.json()
                encrypted_data = response_data["data"]["content"]
                response_data_signature = response_data["data"]["signature"]

                # Verify the signature
                if not verify_signature(encrypted_data, response_data_signature):
                    raise ValueError("Signature verification failed. The data may be tampered with.")
                
                else:
                    decrypted_data = decrypt_data(encrypted_data)

                    # Parse the decrypted data to the appropriate data class
                    number_details = NumberDetails.from_dict(json.loads(decrypted_data))
                    return number_details
                
            else:
                raise ValueError(f"Unexpected status code: {response.status_code}. No valid response from the external system.")
    
        except httpx.HTTPStatusError as e:
            print(f"Unexpected HTTP status: {e.response.status_code}")



@app.get("/process-get-number/")
async def process_get_number():
    response_data = {
        "status": "success",
        "message": "Number processed successfully",
        "data": {
            "number": "00000000001",
            "details": "Some details about the number"
        }
    }
    return response_data
    

@app.post("/process-number/")
def process_number(request: Request):
    request_data = request.json()
    # oriInvoince = request_data.get('oriInvoince')
    import pdb;pdb.set_trace()
    # request_data = 
    {
    "oriInvoiceNo": "00000000002",
    "invoicenumberNo": "00000000001",
    "deviceNo": "00031000092",
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
    input_number_dict = InputNumber.from_dict(request_data)

    input_json_data = json.dumps(input_number_dict, indent=2)

    # Load RSA keys
    _, private_key = load_keys()

    # Encrypt and sign the data
    encrypted_data = encrypt_data(input_json_data, AES_KEY, IV)
    encrypted_string_data = encrypted_data.get('encrypted_data', '')
    signed_data = sign_data(encrypted_string_data, private_key)
    # encrypted_string_data = base64.b64encode(encrypted_string_data).decode('utf-8')
    # encrypted_string_data = base64.b64encode(encrypted_string_data.encode('utf-8')).decode('utf-8')
    
    # Create the interface data
    interface_data = {
        "data": {
            "content": encrypted_string_data,
            "signature": signed_data,
            "dataDescription": {
                "codeType": "1",
                "encryptCode": "2",
                "zipCode": "0"
            }
        },
        "globalInfo": {
            "appId": "AP04",
            "version": "1.1.20191201",
            "dataExchangeId": 9230489223014123,
            "interfaceCode": "T101",
            "requestCode": "TP",
            "requestTime": "2019-06-11 17:07:07",
            "responseCode": "TA",
            "userName": "admin",
            "deviceMAC": "FFFFFFFFFFFF",
            "deviceNo": "00022000634",
            "tin": "1009830865",
            "brn": "",
            "taxpayerID": "1",
            "longitude": 116.397128,
            "latitude": 39.916527,
            "agentType": "0",
            "extendField": {
                "responseDateFormat": "dd/MM/yyyy",
                "responseTimeFormat": "dd/MM/yyyy HH:mm:ss",
                "referenceNo": "21PL010020807",
                "operatorName": "administrator",
                "offlineInvoiceException": {
                    "errorCode": "",
                    "errorMsg": ""
                }
            },
            "returnStateInfo": {
                "returnStateInfo": {
                "returnCode": "",
                "returnMessage": ""
                }
            }
        }
    }

    return {
            "status": "success", 
            "message": "Number processed successfully", 
            "data": "it will leave here"}
    # try:
    #     response = send_number_to_external_system(interface_data)
    #     number_details_list.append(response.model_dump())
    #     df = pd.DataFrame(number_details_list)
    #     data_in_table_format = df.to_dict(orient='records')
    # except HTTPException as exc:
    #     logger.error(f"Error processing number: {exc}")
    #     return {"status": "error", "message": str(exc)}
    # else:
    #     return {
    #         "status": "success", 
    #         "message": "Number processed successfully", 
    #         "data": data_in_table_format}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)
