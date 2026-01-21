# Assignment 2 Task 1: CBC

"""
Docstring for CBC:

This module implements Cipher Block Chaining (CBC) encryption
"""

# some functions completed with Github Copilot assistance
# AES usage based on PyCryptodome documentation: 
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

AES_BLOCK_SIZE = 16  # bytes (128 bits) for AES

def readfile() -> bytes:
    # GitHub Copilot assisted implementation
    with open("mustang.bmp", "rb") as file:
        plaintext = file.read()
    return plaintext

def split_hbmp_header(plaintext: bytes, header_size: int = 54) -> tuple[bytes, bytes]:
    if len(plaintext) < header_size:
        raise ValueError("Plaintext is smaller than the specified header size.")
    
    # GitHub Copilot assisted implementation
    header = plaintext[:header_size]
    body = plaintext[header_size:]
    return header, body

def pkcs7_padding(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be between 1 and 255 for PKCS#7.")
    
    # GitHub Copilot assisted implementation
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def xor_bytes(a: bytes, b: bytes) -> bytes:
    # ChatGPT assisted implementation
    if len(a) != len(b):
        raise ValueError("Byte sequences must be of equal length to XOR.")
    
    return bytes(x ^ y for x, y in zip(a, b))

def key_gen() -> bytes:
    return get_random_bytes(AES_BLOCK_SIZE)

def iv_gen() -> bytes:
    return get_random_bytes(AES_BLOCK_SIZE)

def cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != AES_BLOCK_SIZE:
        raise ValueError("AES-128 key must be 16 bytes.")
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes.")
    if len(data) % AES_BLOCK_SIZE != 0:
        raise ValueError("Data must be padded to a multiple of 16 bytes before CBC encryption.")
    
    aes = AES.new(key, AES.MODE_ECB)

    ciphertext_blocks = []
    prev = iv

    # GitHub Copilot assisted loop implementation
    # variables renamed and loop logic verified
    for i in range(0, len(data), AES_BLOCK_SIZE):
        block = data[i:i + AES_BLOCK_SIZE]
        xored = xor_bytes(block, prev)
        cblock = aes.encrypt(xored)
        ciphertext_blocks.append(cblock)
        prev = cblock

    return b"".join(ciphertext_blocks)

def main():
    plaintext = readfile()
    header, body = split_hbmp_header(plaintext)
    padded_body = pkcs7_padding(body)
    key = key_gen()
    iv = iv_gen()
    ciphertext = cbc_encrypt(padded_body, key, iv)
    with open("cbc_encrypted_image.bmp", "wb") as file:
        file.write(header + iv + ciphertext)

if __name__ == "__main__":
    main()