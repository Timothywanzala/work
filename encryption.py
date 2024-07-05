import rsa

with open("public.pen", "wb") as f:
    f.write(public_key.save_pkcs1("PEM"))

with open("Private.pen", "wb") as f:
    f.write(private_key.save_pkcs1("PEM"))


with open("public_pen", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open("private_pen", "rb") as f:
    private_key = rsa.PublicKey.load_pkcs1(f.read())

message = #number to encrypt

encrypted_message = open("encrypted.message", "rb").read()


#ecrypted_message = rsa.encrypt(message.encode(), public_key)

#with open("encrypted_message", "wb") as f:
    f.write(ecrypted_message)

clear_message = rsa.decrypt(encrypted_message, private_key)
print(clear_message.decode())

#signature
signature = rsa.sign(message.encode(), private_key, "SHA-256") 


with open("signature", "wb") as f:
    f.write(signature)


with open("signature", "rb") as f:
    signature = f.read()

rsa.verify(message.encode(), signature, public_key)
