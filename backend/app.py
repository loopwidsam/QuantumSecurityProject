from flask import Flask, request, jsonify
from hybrid_kem import generate_server_keys, hybrid_decrypt
from logging.handlers import RotatingFileHandler
import hashlib
import base64
import logging
import os

app = Flask(__name__)

# ---------------- LOGGING ----------------
os.makedirs("logs", exist_ok=True)

handler = RotatingFileHandler(
    "logs/security.log",
    maxBytes=1024 * 1024,
    backupCount=5
)

formatter = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s"
)

handler.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.handlers.clear()
logger.addHandler(handler)

# ---------------- SERVER KEYS ----------------
server_private_key, server_public_key = generate_server_keys()
logger.info("Server key pair generated")

# ---------------- ROUTES ----------------

@app.route("/getPublicKey", methods=["GET"])
def get_public_key():
    pub_bytes = server_public_key.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode()

    logger.info("Public key requested")
    return jsonify({"public_key": pub_b64})


@app.route("/sendEncryptedKey", methods=["POST"])
def receive_encrypted_key():
    data = request.get_json()

    encrypted_b64 = data.get("encrypted_key")
    if not encrypted_b64:
        return jsonify({"error": "Invalid request"}), 400

    encrypted_data = base64.b64decode(encrypted_b64)

    try:
        plaintext = hybrid_decrypt(server_private_key, encrypted_data)
        key_hash = hashlib.sha256(plaintext).hexdigest()

        logger.info(f"Decryption successful | KeyHash={key_hash}")
        return jsonify({"status": "success"})

    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return jsonify({"status": "failure"}), 500


# ---------------- START ----------------
if __name__ == "__main__":
    print("🚀 Flask backend running at http://127.0.0.1:5000")
    app.run(debug=True)
