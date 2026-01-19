# Assignment 2 Task 2

from task1.CBC import *
from task1.EBC import *

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

from urllib.parse import unquote
from urllib.parse import quote

AES_BLOCK_SIZE = 16  # bytes (128 bits) for AES

KEY = get_random_bytes(16)

PREFIX = "userid=456;userdata="
SUFFIX = ";session-id=31337"

def submit(string: str) -> bytes:


    # URL encode any ‘;’ and ‘=’ characters that appear in the user provided string; 
    safe_string = quote(string, safe="")

    # prepend and append to user provided string
    message_str = PREFIX + safe_string + SUFFIX

    # convert to bytes for crypto
    message = message_str.encode("utf-8")

    # pad for PKCS#7
    padded = pad_pkcs7(message, AES_BLOCK_SIZE)

    ciphertext = ecb_encrypt(padded, KEY)
    return ciphertext

def pkcs7_unpad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:

    if len(data) == 0 or (len(data) % block_size) != 0:
        raise ValueError("invalid padded length")
    
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("invalid PKCS#7 padding bytes")
    
    return data[:-pad_len]


def verify(ciphertext: bytes) -> bool:

    try:

        # create a cipher object with the same key used for encryption
        cipher = AES.new(KEY, AES.MODE_ECB)


        # decrypt to get padded plaintext bytes 
        padded = cipher.decrypt(ciphertext)

        # remove PKCS#7 padding 
        plaintext = pkcs7_unpad(padded, AES_BLOCK_SIZE)

        # parse string for the pattern and return true if string exists
        text = plaintext.decode("utf-8", errors="ignore")

        return ";admin=true;" in text

    # return false if string doesnt exist
    except Exception:

        return False
    
    




