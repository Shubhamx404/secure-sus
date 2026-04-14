import os
import pytest
from fastapi.testclient import TestClient
import json
import base64

from server.main import app
from server.signer import load_or_generate_keys
from client.verifier import verify_signature, verify_file_hash

client = TestClient(app)

def test_full_system_flow():
    """Validates the End-to-End lifecycle of the TUF update prototype."""
    
    # 1. Ensure keys correctly spin up
    load_or_generate_keys()

    # 2. Upload a file securely to backend
    test_content = b"Automated Integration Test Payload"
    test_filename = "integration_test.txt"
    
    response = client.post(
        "/upload?version=1",
        files={"file": (test_filename, test_content, "text/plain")}
    )
    assert response.status_code == 200, "Server upload failure"
    assert "Successfully uploaded" in response.json()["message"]
    
    # 3. Client grabs the cryptographic public key context
    pk_resp = client.get("/public_key")
    assert pk_resp.status_code == 200
    public_key_pem = pk_resp.json()["public_key"].encode('utf-8')
    assert b"BEGIN PUBLIC KEY" in public_key_pem
    
    # 4. Client fetches the manifest Metadata and Verifies Signature
    meta_resp = client.get(f"/metadata/{test_filename}")
    assert meta_resp.status_code == 200
    meta_payload = meta_resp.json()
    
    signed_meta = meta_payload["signed"]
    signatures = meta_payload["signatures"]
    
    # Serialize strictly to deterministically verify signature the same way server produced it
    meta_bytes = json.dumps(signed_meta, separators=(',', ':'), sort_keys=True).encode('utf-8')
    sig_bytes = base64.b64decode(signatures[0]["sig"])
    
    is_valid = verify_signature(public_key_pem, sig_bytes, meta_bytes)
    assert is_valid is True, "CRITICAL: Cryptographic signature verification failed!"
    
    # 5. Client Fetches Payload and explicitly Verifies the SHA256 Hash
    dl_resp = client.get(f"/download/{test_filename}")
    assert dl_resp.status_code == 200
    assert dl_resp.content == test_content
    
    # Simulate saving to disk to run the client verifier hashing
    temp_path = "temp_dl_test_file.txt"
    with open(temp_path, "wb") as f:
        f.write(dl_resp.content)
        
    expected_hash = signed_meta["hashes"]["sha256"]
    hash_valid = verify_file_hash(temp_path, expected_hash)
    assert hash_valid is True, "CRITICAL: Payload has mismatch verification failure!"
    
    os.remove(temp_path)
    print("All Integration Tests completely passed. The architecture is stable!")
