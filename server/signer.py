import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, "keys")

def load_or_generate_keys():
    """Generates an Ed25519 key pair if it doesn't exist, otherwise loads them."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    priv_path = os.path.join(KEYS_DIR, "private_key.pem")
    pub_path = os.path.join(KEYS_DIR, "public_key.pem")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key

    # Generate new key pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Save private key securely
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

def sign_data(private_key, data: bytes) -> bytes:
    """Signs bytes using the Ed25519 private key."""
    return private_key.sign(data)

def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
    """Verifies a signature given the public key, returns True if valid."""
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False
