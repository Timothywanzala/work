from urllib import response
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List,Optional
from uuid import    UUID, uuid4
import httpx
import pandas as pd
import rsa

#create public and private key files 

#public_key, private_key  = rsa.newKeys(1024)

"""with open("public.pen", "wb") as f:
    f.write(public_key.save_pkcs1("PEM"))

with open("Private.pen", "wb") as f:
    f.write(private_key.save_pkcs1("PEM"))
"""
class encryption():
    with open("public_pen", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    with open("private_pen", "rb") as f:
        private_key = rsa.PublicKey.load_pkcs1(f.read())

    with open("test.py", ) as f:
        message = InputNumber(number).f

    #encrypte message here

    ecrypted_message = rsa.encrypt(message.encode(), public_key)

    with open("encrypted_message", "wb") as f:
        f.write(ecrypted_message)


    #signature
    signature = rsa.sign(ecrypted_message.encode(), private_key, "SHA-256") 


    with open("signature", "wb") as f:
        f.write(signature)

    async def send_number_to_external_system(signature: str):
        async with httpx.AsyncClient() as client:
            response = await client.post("https://external-system-url/api", json={"number":signature})
            if response.status_code == 200:
                return response
            
            else:
                raise HTTPException(status_code=response.status_code, detail="Failed to get details from external system")

    data = response.read()