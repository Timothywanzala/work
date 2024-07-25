import base64
import logging
from fastapi import logger
import httpx
import json
from encryption_decryption import decrypt_data, verify_signature
from models import NumberDetails

logging.basicConfig(level=logging.DEBUG, filename='app.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__) 

async def send_number_to_external_system(Interface_json_data_sent:str):
    logger.debug('Sending number with data: %s', Interface_json_data_sent)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post("https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation", 
                                         json=Interface_json_data_sent,  timeout=60.0)
            response.raise_for_status()
            
            if response.status_code == 200:
                response_data = response.json()
                encrypted_string_data= response_data["data"]["content"]
                response_signature = response_data["data"]["signature"]
                encrypted_data = base64.b64encode(encrypted_string_data).decode('ascii')
                response_data_signature = base64.b64encode(response_signature).decode('ascii')
                # Verify the signature
                # import pdb; pdb.set_trace()
                if not verify_signature(encrypted_data, response_data_signature):
                    raise ValueError("Signature verification failed. The data may be tampered with.")
                
                else:
                    decrypted = decrypt_data(encrypted_data)
                    decrypted_data = decrypted

                    # Parse the decrypted data to the appropriate data class
                    number_details = NumberDetails.from_dict(json.loads(decrypted_data))
                    return number_details
                
            else:
                raise ValueError(f"Unexpected status code: {response.status_code}. No valid response from the external system.")
    
        # except httpx.HTTPStatusError as e:
        #     print(f"Unexpected HTTP status: {e.response.status_code}")
        # except httpx.ConnectError as e:
        #      print(f"Connect error occurred: {str(e)}")
        # except httpx.ConnectTimeout:
        #     print("Request timed out")
        except httpx.HTTPStatusError as e:
            logger.debug(e)
            return None