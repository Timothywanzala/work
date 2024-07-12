# encryption.py

import rsa

def load_keys():
    with open("public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    with open("private.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    return public_key, private_key

def encrypt_and_sign(data: str, public_key, private_key):
    encrypted_data = rsa.encrypt(data.encode(), public_key)
    signature = rsa.sign(encrypted_data, private_key, 'SHA-256')
    return encrypted_data, signature

def verify_and_decrypt(encrypted_data, signature, public_key, private_key):
    try:
        rsa.verify(encrypted_data, signature, public_key)
        decrypted_data = rsa.decrypt(encrypted_data, private_key).decode()
        return decrypted_data
    except rsa.VerificationError:
        raise ValueError("Signature verification failed")
