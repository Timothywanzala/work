from fastapi import FastAPI, HTTPException, Request
import httpx
import pandas as pd
import json
from datetime import datetime

app = FastAPI()

# Array to store details
number_details_list = []

public_key, private_key = load_keys()

# Load interface JSON structure from file
with open('interface.json', 'r') as f:
    interface_json_template = json.load(f)

# Send the encrypted number to the external system and receive details
async def send_number_to_external_system(interface_json: dict) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.post("https://external-system-url/api", json=interface_json)
        if response.status_code == 200:
            response_data = response.json()
            encrypted_response = bytes.fromhex(response_data["data"]["content"])
            response_signature = bytes.fromhex(response_data["data"]["signature"])
            decrypted_data = verify_and_decrypt(encrypted_response, response_signature, public_key, private_key)
            return json.loads(decrypted_data)
        else:
            raise HTTPException(status_code=response.status_code, detail="Failed to get details from external system")

# Endpoint to receive number and process it
@app.post("/process-number/")
async def process_number(request: Request):
    input_data = await request.json()
    
    # Convert input data to JSON string
    input_data_json = json.dumps(input_data)
    
    # Encrypt the input data and sign it
    encrypted_data, signature = encrypt_and_sign(input_data_json, public_key, private_key)
    
    # Create interface JSON by updating the template
    interface_json = interface_json_template.copy()
    interface_json['data']['content'] = encrypted_data.hex()
    interface_json['data']['signature'] = signature.hex()
    interface_json['globalInfo']['requestTime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Send the encrypted data to the external system and get the details
    number_details = await send_number_to_external_system(interface_json)
    
    # Append the received details to the list
    number_details_list.append(number_details)

    # Convert the list of details to a pandas DataFrame
    df = pd.DataFrame(number_details_list)
    
    # Convert the DataFrame to a dictionary with records orientation
    data_in_table_format = df.to_dict(orient='records')
    
    # Return the data in table format
    return data_in_table_format

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)
