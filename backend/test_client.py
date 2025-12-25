import requests
import base64
from hybrid_kem import hybrid_encrypt

SERVER = "http://127.0.0.1:5000"

try:
    print("⏳ Requesting server public key...")
    r = requests.get(f"{SERVER}/getPublicKey")
    r.raise_for_status()

    server_pub = base64.b64decode(r.json()["public_key"])
    print("✔ Server public key received")

    product_key = "PRODUCT-KEY-1234"

    encrypted_data = hybrid_encrypt(server_pub, product_key)

    payload = {
        "encrypted_key": base64.b64encode(encrypted_data).decode()
    }

    print("⏳ Sending encrypted key...")
    r2 = requests.post(f"{SERVER}/sendEncryptedKey", json=payload)
    print("✔ Server response:", r2.json())

except Exception as e:
    print("❌ Error:", e)
  