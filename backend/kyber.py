from pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt

def kyber_generate():
    pk, sk = generate_keypair()
    return pk, sk

def kyber_encapsulate(pk: bytes):
    ct, ss = encrypt(pk)
    return ct, ss

def kyber_decapsulate(ct: bytes, sk: bytes):
    ss = decrypt(ct, sk)
    return ss
