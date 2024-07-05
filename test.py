from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List,Optional
from uuid import    UUID, uuid4
import rsa

app = FastAPI()

class InputNumber(BaseModel):
    number:str

#json.laod()jsom.dump then hook
#hook
class NumberDetails(BaseModel):
    name: str
    invoice_number: str
    product: List[str]
    price: List[str]
    date: str

number_details_list=[]

public_key, private_key = rsa.newkeys(1024)





async def encrypt_number(number: str) -> str:

    encrypted_number = cipher.encrypt(number.encode())
    return encrypted_number.decode()

async def dencrypt_number(encrypt_number: str) -> str:

    dencrypted_number = cipher.dencrypt(encrypted_number.encode())
    return dencrypted_number.decode()

async def send_number_to_external_system(encrypted_number: str) -> NumberDetails:
    
    async with httpx.AsyncClient() as client:
        response = await client.post("https://external-system-url/api", json={"number":encrypted_number})
       
        if response.status_code == 200:
            data =response.json()
            return NumberDetails(**data)
       
        else:
            return HTTPException(status_code=404, detail="Task not found")

@app.post("/process-number/")
async def process_number(input_number:InputNumber):

    encrypt_number = encrypt_number(input_number.number)

    number_details = await send_number_to_external_system(encrypt_number)

    number_details_list.append(number_details.dict())

    df = pd.DataFrame(number_details_list)

    data_in_table_format = df.to_dict(orient='records')

    return data_in_table_format


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(app, host="localhost", port=8000)



