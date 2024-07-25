import logging
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES
import base64
import os
import rsa
from dotenv import load_dotenv
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.DEBUG, filename='app.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


load_dotenv()

def load_keys():
    with open("private.crt", "rb") as f:
        private_key_data = f.read()
        private_key = rsa.PrivateKey.load_pkcs1(private_key_data)
        # private_key = rsa.PrivateKey.load_pkcs1(f.read())
    with open("_.ura.go.ug.crt", "rb") as cert_file:
        cert_data = cert_file.read()
        # Load the certificate
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        # Extract the public key
        public_key = cert.public_key()
    
    return private_key, public_key   


AES_KEY = bytes.fromhex(os.getenv('AES_KEY', ''))
# AES_KEY = os.getenv('AES_KEY', '')
IV = bytes.fromhex(os.getenv('IV', ''))
# IV = os.getenv('IV', '')

# deviceNumber = bytes.fromhex(os.getenv('deviceNumber', ''))

# Function to encrypt data using AES-CBC mode
def encrypt_data(data: str, aes_key: bytes, iv: bytes) -> dict:
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    
    combined_data = {
        "encrypted_data": encrypted_data,
        "iv": iv
    }
    return combined_data

# Signing function corrected
def sign_data(encrypted_data: str, private_key) -> str:
    private_key, public_key = load_keys()
    signed = rsa.sign(encrypted_data, private_key, 'SHA-256')
    return signed

# Decryption and verification functions corrected
def decrypt_data(encrypted_data: bytes, iv: bytes, aes_key: bytes) -> str:
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode('utf-8')
    return decrypted_data

def verify_signature(encrypted_data: bytes, signature: bytes) -> bool:
    logger.debug('Verifying signature')
    logger.debug('Encrypted data: %s', base64.b64encode(encrypted_data).decode('utf-8'))
    logger.debug('Signature: %s', base64.b64encode(signature).decode('utf-8'))

    public_key=load_keys()

    try:
        rsa.verify(encrypted_data, signature, public_key)
        logger.debug('Signature verification succeeded')
        return True
    except rsa.pkcs1.VerificationError as e:
        logger.debug('Signature verification failed: %s', str(e))
        return False
