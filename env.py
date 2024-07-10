import os
from crypto.Random import get_random_bytes
from crypto.Cipher import AES

# Generate a random AES key and IV
AES_KEY = get_random_bytes(AES.block_size)
IV = get_random_bytes(AES.block_size)

# Convert bytes to hexadecimal strings for storage as environment variables
AES_KEY_HEX = AES_KEY.hex()
IV_HEX = IV.hex()

# Set environment variables
os.environ['AES_KEY'] = AES_KEY_HEX
os.environ['IV'] = IV_HEX

deviceNumber = "number from efris"

deviceNumber_HEX = deviceNumber.HEX()

os.environ['deviceNumber'] = deviceNumber_HEX