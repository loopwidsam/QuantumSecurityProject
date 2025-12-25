import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, plaintext):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt(key, nonce, ciphertext):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
