import json
import hashlib
import os
import base64
from typing import Dict, Any
from .signer import load_or_generate_keys, sign_data

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
METADATA_DIR = os.path.join(BASE_DIR, "data", "server_metadata")
os.makedirs(METADATA_DIR, exist_ok=True)

def calculate_sha256(filepath: str) -> str:
    """Calculates the SHA256 of a file efficiently by reading it in chunks."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_file_metadata(filepath: str, version: int) -> Dict[str, Any]:
    """Generates the TUF target structure metadata for a given file."""
    filename = os.path.basename(filepath)
    size = os.path.getsize(filepath)
    file_hash = calculate_sha256(filepath)

    metadata = {
        "filename": filename,
        "version": version,
        "size": size,
        "hashes": {
            "sha256": file_hash
        }
    }
    return metadata

def create_and_sign_metadata(filepath: str, version: int) -> Dict[str, Any]:
    """Generates and signs the JSON metadata, then saves it to disk."""
    metadata = generate_file_metadata(filepath, version)
    
    # Serialize to standard JSON bytes - must use deterministic sort!
    metadata_bytes = json.dumps(metadata, separators=(',', ':'), sort_keys=True).encode('utf-8')
    
    # Sign the bytes
    private_key, _ = load_or_generate_keys()
    signature_bytes = sign_data(private_key, metadata_bytes)
    signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

    signed_payload = {
        "signatures": [
            {
                "keyid": "master-ed25519",
                "method": "ed25519",
                "sig": signature_b64
            }
        ],
        "signed": metadata
    }

    # Save metadata to disk
    meta_name = f"{metadata['filename']}.meta.json"
    meta_path = os.path.join(METADATA_DIR, meta_name)
    with open(meta_path, "w") as f:
        json.dump(signed_payload, f, indent=4)
    
    return signed_payload
