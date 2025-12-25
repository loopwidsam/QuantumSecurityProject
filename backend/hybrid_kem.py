from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ---------------- SERVER KEY GENERATION ----------------
def generate_server_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


# ---------------- HYBRID ENCRYPT (CLIENT SIDE) ----------------
def hybrid_encrypt(server_public_key_bytes: bytes, plaintext: str):
    server_public_key = x25519.X25519PublicKey.from_public_bytes(
        server_public_key_bytes
    )

    plaintext_bytes = plaintext.encode()

    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    shared_secret = ephemeral_private.exchange(server_public_key)

    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=len(plaintext_bytes),
        salt=None,
        info=b"hybrid-kem"
    ).derive(shared_secret)

    ciphertext = bytes(a ^ b for a, b in zip(plaintext_bytes, symmetric_key))

    # 🔑 IMPORTANT: return BOTH together
    return ephemeral_public.public_bytes_raw() + ciphertext


# ---------------- HYBRID DECRYPT (SERVER SIDE) ----------------
def hybrid_decrypt(server_private_key, encrypted_data: bytes):
    ephemeral_public_bytes = encrypted_data[:32]
    ciphertext = encrypted_data[32:]

    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
        ephemeral_public_bytes
    )

    shared_secret = server_private_key.exchange(ephemeral_public)

    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=len(ciphertext),
        salt=None,
        info=b"hybrid-kem"
    ).derive(shared_secret)

    plaintext = bytes(a ^ b for a, b in zip(ciphertext, symmetric_key))
    return plaintext
