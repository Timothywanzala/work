import json
import logging
import pandas as pd
import uvicorn
from fastapi import FastAPI, Request, logger
from interface_data import create_interface_data
from send_number import send_number_to_external_system
from encryption_decryption import AES_KEY, IV, encrypt_data, load_keys, sign_data
import base64

logging.basicConfig(level=logging.DEBUG, filename='app.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

number_details_list = []

@app.post("/process-number/{refno}")
async def get_reference_details(request: Request, refNo: str):
    refNo_data = refNo
    refNo_json = json.dumps(refNo_data, indent=2)

#  Encrypt and sign the data
    private_key= load_keys()

    encrypted_data = encrypt_data(refNo_json, AES_KEY, IV)
    encrypted_string = encrypted_data.get('encrypted_data', '')
    signed_data= sign_data(encrypted_string, private_key)
    # logger.debug('Sending number to external system with data: %s', type(signed_data))

    encrypted_string_data = base64.b64encode(encrypted_string).decode('utf-8')
    signed_bytes = base64.b64encode(signed_data).decode('utf-8')


    interface_data = create_interface_data(encrypted_string_data, signed_bytes)
    
    
    response = await send_number_to_external_system(interface_data)
    import pdb; pdb.set_trace()
    logger.debug('Received response: %s', response )
    # import pdb;pdb.set_trace()
    if response is None:
        number_details_list.append("No Data On Number")
    else:
        number_details_list.append(response)
         
        # if response is not None:
        #     try:
        #         number_details_list.append(response.model_dump())

        #     except AttributeError:
        #         print("Response does not have model_dump method")
        # else:
        #     print("No Number Details")
        # number_details_list.append(response.model_dump())
    df = pd.DataFrame(number_details_list)
        # import pdb;pdb.set_trace()
    data_in_table_format = df.to_dict(orient='records')
    # import pdb;pdb.set_trace()
    # except HTTPException as exc:
        # logger.error(f"Error processing number: {exc}")
        # return {"status": "error", "message": str(exc)}
    # else:
    return {
            "status": "success", 
            "message": "Number processed successfully", 
            "data": data_in_table_format}  
if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8000)