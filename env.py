import os
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES

# Generate a random AES key and IV
AES_KEY = get_random_bytes(32)  # 32 bytes for AES-256
IV = get_random_bytes(16)  # Always 16 bytes for AES

# Convert bytes to hexadecimal strings for storage as environment variables
AES_KEY_HEX = AES_KEY.hex()
IV_HEX = IV.hex()

# Set environment variables
os.environ['AES_KEY'] = AES_KEY_HEX
os.environ['IV'] = IV_HEX

# Example device number (replace with actual logic to get the number from efris)
deviceNumber = "number from efris"
deviceNumber_HEX = deviceNumber.encode().hex()

os.environ['deviceNumber'] = deviceNumber_HEX
