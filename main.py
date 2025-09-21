import uuid
import time
import threading
from typing import List, Optional
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request
import jwt
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# --- Key Management Classes ---

class KeyPair:
    def __init__(self, private_key, public_key, kid: str, expiry: datetime):
        self.private_key = private_key
        self.public_key = public_key
        self.kid = kid
        self.expiry = expiry

    def is_expired(self):
        return datetime.now(timezone.utc) > self.expiry

    def to_jwk(self): # Converts the public key to JWK format
        numbers = self.public_key.public_numbers()
        n = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('ascii')
        e = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('ascii')
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": n,
            "e": e,
            "exp": int(self.expiry.timestamp())
        }

    def private_pem(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

class KeyManager: # Class to manages keys
    def __init__(self):
        self.keys: List[KeyPair] = []
        self.key_ttl = timedelta(seconds=30)  # Key expires after 30s
        self.retention = timedelta(minutes=5)  # Retain expired keys for 5 minutes

    def generate_keypair(self) -> KeyPair: # Generates a new RSA key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        kid = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + self.key_ttl
        return KeyPair(private_key, public_key, kid, expiry)

    def add_new_key(self): # Adds new key to the list
        new_key = self.generate_keypair()
        self.keys.append(new_key)

    def get_active_keys(self) -> List[KeyPair]: # Returns all non-expired keys
        return [k for k in self.keys if not k.is_expired()]

    def get_latest_active_key(self) -> Optional[KeyPair]: # Returns the most recent non-expired key
        for k in reversed(self.keys):
            if not k.is_expired():
                return k
        return None

    def get_expired_key(self) -> Optional[KeyPair]: # Returns the first expired key
        for k in self.keys:
            if k.is_expired():
                return k
        return None

    def cleanup_old_keys(self): # Removes keys that have been expired longer than retention period
        now = datetime.now(timezone.utc)
        self.keys = [
            k for k in self.keys
            if now < k.expiry + self.retention
        ]

    def start_rotation(self): # Starts a background thread to rotate keys
        def loop():
            self.add_new_key()
            while True:
                time.sleep(20)
                self.add_new_key()
                self.cleanup_old_keys()
        t = threading.Thread(target=loop, daemon=True)
        t.start()

# --- Flask App ---

app = Flask(__name__)
key_manager = KeyManager()
key_manager.start_rotation()

@app.route("/jwks", methods=["GET"]) # Endpoint to get current JWKS
def jwks():
    keys = [k.to_jwk() for k in key_manager.get_active_keys()]
    return jsonify({"keys": keys})

@app.route("/auth", methods=["POST"]) # Endpoint to get a JWT
def auth():
    expired = request.args.get("expired")
    if expired:
        key = key_manager.get_expired_key()
        if not key:
            return jsonify({"error": "No expired key available"}), 400
        exp = int(key.expiry.timestamp())
    else:
        key = key_manager.get_latest_active_key()
        if not key:
            return jsonify({"error": "No active key available"}), 500
        # JWT expires 10 seconds before key expiry
        exp = min(int(time.time()) + 20, int(key.expiry.timestamp()) - 10)
    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": exp,
        "kid": key.kid
    }
    token = jwt.encode(
        payload,
        key.private_pem(),
        algorithm="RS256",
        headers={"kid": key.kid}
    )
    return jsonify({"token": token})

@app.route("/.well-known/jwks.json", methods=["GET"]) 
def well_known_jwks():
    """
    Returns the JWKS (all active keys) as a JSON file.
    If a 'kid' query parameter is provided, checks if a valid JWK with that kid exists.
    """
    keys = [k.to_jwk() for k in key_manager.get_active_keys()]
    kid = request.args.get("kid")
    if kid:
        for key in keys:
            if key.get("kid") == kid:
                return jsonify({"valid": True, "key": key}), 200
        return jsonify({"valid": False, "error": "No valid JWK with that kid"}), 404
    return jsonify({"keys": keys}), 200

if __name__ == "__main__":
    print("Server running at http://127.0.0.1:8080")
    app.run(debug=True, port=8080)
