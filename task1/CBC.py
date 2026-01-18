"""
Docstring for CBC:

This module implements Cipher Block Chaining (CBC) encryption
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

AES_BLOCK_SIZE = 16  # bytes (128 bits) for AES

def readfile() -> bytes:
    with open("sample.bnp", "rb") as file:
        plaintext = file.read()
    return plaintext

def split_hbmp_header(plaintext: bytes, header_size: int = 54) -> tuple[bytes, bytes]:
    if len(plaintext) < header_size:
        raise ValueError("Plaintext is smaller than the specified header size.")
    
    header = plaintext[:header_size]
    body = plaintext[header_size:]
    return header, body

def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be between 1 and 255 for PKCS#7.")
    
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Byte sequences must be of equal length to XOR.")
    
    return bytes(x ^ y for x, y in zip(a, b))

def key_gen() -> bytes:
    return get_random_bytes(AES_BLOCK_SIZE)

def iv_gen() -> bytes:
    return get_random_bytes(AES_BLOCK_SIZE)

def main():
    plaintext = readfile()
    header, body = split_hbmp_header(plaintext)
    padded_body = pad_pkcs7(body)
    main()