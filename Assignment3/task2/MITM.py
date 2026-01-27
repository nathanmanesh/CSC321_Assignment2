# Assignment 3 Task 1

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import randint


def int_to_bytes(n: int) -> bytes:
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, "big")




# derive a 16 byte AES key from Diffie-Hellman shared secret
def aes_key_from_shared_secret(s: int) -> bytes:

    #  hash shared secret and truncate to 16 bytes for AES128
    hash_bytes = SHA256.new(int_to_bytes(s)).digest()

    return hash_bytes[:16]

# encrypt a message using AES in CBC mode
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv = iv)

    return cipher.encrypt(pad(plaintext, AES.block_size))

# decrypt a message using AES in CBC mode
def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv = iv)

    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# diffie-hellman key generate
# used ChatGPT to help with some code generation

def diffie_hellman_generate(q: int, a: int):


    # alice (A) and bob (B) pick private secret
    xA = randint(1, q - 2)
    xB = randint(1, q -2)


    # alice and bob compute public key
    yA = pow(a, xA, q)
    yB = pow(a, xB, q)

    return (xA, yA) , (xB, yB)


def diffie_hellman_compute_shared_secret(mysecret_x: int, other_public_y: int, q: int) -> int:

    #  s = (other_public_y) ^ (mysecret_x) mode q
    return pow(other_public_y, mysecret_x, q)



def demo(q: int, a: int):

    # fixed iv
    iv = b"\x00" * 16 

    (xA, yA), (xB, yB) = diffie_hellman_generate(q, a)

    # mallory tampers with exchange.
    # mallory sends q to Bob instead of yA, and q to Alice instead of yB

    yA_to_bob = q
    yB_to_alice = q

    # alice and bob compute shared secret using tampered values
    sA = diffie_hellman_compute_shared_secret(xA, yB_to_alice, q)
    sB = diffie_hellman_compute_shared_secret(xB, yA_to_bob, q)

    # derive AES keys from shared secret

    kA = aes_key_from_shared_secret(sA)
    kB = aes_key_from_shared_secret(sB)

    # alice encrypts to bob, bob encrypts to alice

    message_alice = b"Hi Bob, my name is Alice!"
    ciphertext_alice = aes_cbc_encrypt(kA, iv, message_alice)
    
    message_bob = b"Hi Alice, my name is Bob!"
    ciphertext_bob = aes_cbc_encrypt(kB, iv, message_bob)
    

    # mallory can determine shared secret:
    # if other_public_y = q, then other_public_y mod q = 0, so s = 0 ^ x mod q = 0

    shared_m = 0
    kM = aes_key_from_shared_secret(shared_m)

    leaked_message_alice = aes_cbc_decrypt(kM, iv, ciphertext_alice)
    leaked_message_bob = aes_cbc_decrypt(kM, iv, ciphertext_bob)




    print("Mallory decrypts message from alice:", leaked_message_alice)
    print("Mallory decrypts message from bob:", leaked_message_bob)





if __name__ == "__main__":
    q = "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 " \
        "9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 " \
        "13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 " \
        "98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 " \
        "A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 " \
        "DF1FB2BC 2E4A4371"
        
        
    a = "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F" \
            "D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213" \
            "160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1" \
            "909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A" \
            "D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24" \
            "855E6EEB 22B3B2E5"
        

    q_int = int (q.replace(" ", ""), 16)
    a_int  = int (a.replace(" ", ""), 16)

    demo(q_int, a_int)







