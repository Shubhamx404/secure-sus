import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def verify_signature(public_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """Verifies an Ed25519 signature using a PEM-encoded public key."""
    try:
        public_key = serialization.load_pem_public_key(public_bytes)
        public_key.verify(signature, data)
        return True
    except Exception as e:
        return False

def verify_file_hash(filepath: str, expected_sha256: str) -> bool:
    """Verifies that a local file exactly matches the expected SHA256 hash."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest() == expected_sha256
