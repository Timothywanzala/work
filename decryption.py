import rsa

class decryption():
    with open("public_pen", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    with open("private_pen", "rb") as f:
        private_key = rsa.PublicKey.load_pkcs1(f.read())


    with open("encryption", "rb") as f:
        received_message = json.loads(data)


    #confirm message by senders signature
    with open("signature", "rb") as f:
        received_signature = f.read()


    varify_signature = rsa.verify(received_message.encode(), received_signature, public_key)

    if varify_signature != KeyError:
        print ("Varified")
    else:
        print ("Not Varified")

    #decrypt message here 

    encrypted_message = open("encrypted.received_message", "rb").read()

    clear_message = rsa.decrypt(received_message, private_key)
    decrypted_message = clear_message.decode()




