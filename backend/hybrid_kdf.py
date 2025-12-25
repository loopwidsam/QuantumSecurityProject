from cryptography.hazmat.primitives import hashes

def derive_hybrid_key(ecdh_secret: bytes, kyber_secret: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(ecdh_secret)
    digest.update(kyber_secret)
    return digest.finalize()  # 32 bytes
