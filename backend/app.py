from flask import Flask, jsonify, request
import base64

from ecdh import generate_keypair, derive_shared_secret
from kdf import derive_key
from aead import decrypt

app = Flask(__name__)

# Generate server ECDH keypair once
server_private_key, server_public_bytes = generate_keypair()

@app.route("/")
def home():
    return jsonify({"status": "Backend running"})

@app.route("/getPublicKey", methods=["GET"])
def get_public_key():
    return jsonify({
        "server_public_key": base64.b64encode(server_public_bytes).decode()
    })
@app.route("/sendEncryptedKey", methods=["POST"])
def receive_encrypted_key():
    data = request.get_json(force=True)

    client_pub = base64.b64decode(data["client_public_key"])
    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])

    shared_secret = derive_shared_secret(server_private_key, client_pub)
    session_key = derive_key(shared_secret)

    plaintext = decrypt(session_key, nonce, ciphertext)

    print("🔐 Decrypted secret message:", plaintext.decode())
    return jsonify({"status": "success"})

if __name__ == "__main__":
    app.run(debug=False)
