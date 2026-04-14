import os
import sys
import json
import base64
import argparse
import requests
from .verifier import verify_signature, verify_file_hash

SERVER_URL = "http://127.0.0.1:8000"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOWNLOAD_DIR = os.path.join(BASE_DIR, "data", "client_downloads")
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def fetch_public_key() -> bytes:
    """Fetches the root public key from the server.
    Note: In real TUF, root keys are pre-distributed securely. For this prototype, we fetch it."""
    response = requests.get(f"{SERVER_URL}/public_key")
    response.raise_for_status()
    return response.json()["public_key"].encode('utf-8')

def download_and_verify(filename: str):
    """Securely downloads the metadata, verifies its authenticity, then downloads and verifies the payload."""
    print(f"[*] Starting secure download process for '{filename}'...")
    
    # 1. Fetch public key
    try:
        public_key_bytes = fetch_public_key()
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to fetch public key: {e}")
        sys.exit(1)

    # 2. Fetch metadata
    print("[*] Fetching signed metadata...")
    try:
        meta_response = requests.get(f"{SERVER_URL}/metadata/{filename}")
        meta_response.raise_for_status()
        metadata_payload = meta_response.json()
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to fetch metadata: {e}")
        sys.exit(1)

    # 3. Verify metadata signature
    print("[*] Verifying cryptographic signature of metadata...")
    signed_meta = metadata_payload["signed"]
    signatures = metadata_payload["signatures"]
    
    # Re-serialize deterministically to obtain verbatim bytes for signature check
    meta_bytes = json.dumps(signed_meta, separators=(',', ':'), sort_keys=True).encode('utf-8')
    
    # Get raw signature bytes
    sig_b64 = signatures[0]["sig"]
    sig_bytes = base64.b64decode(sig_b64)

    is_valid = verify_signature(public_key_bytes, sig_bytes, meta_bytes)
    if not is_valid:
        print("[!] CRITICAL: Signature verification failed. The metadata has been tampered with or corrupted!")
        sys.exit(1)
    
    print("[+] Signature verification successful. Metadata is authentic.")

    # 4. Download file
    print("[*] Downloading file payload...")
    file_path = os.path.join(DOWNLOAD_DIR, filename)
    try:
        with requests.get(f"{SERVER_URL}/download/{filename}", stream=True) as r:
            r.raise_for_status()
            with open(file_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to download file: {e}")
        sys.exit(1)

    # 5. Verify file integrity against authenticated metadata
    print("[*] Verifying file payload integrity using SHA256...")
    expected_hash = signed_meta["hashes"]["sha256"]
    
    if verify_file_hash(file_path, expected_hash):
        print("[+] File integrity verified successfully. The payload is safe and untampered.")
        print(f"[+] Download located at: {file_path}")
    else:
        print("[!] CRITICAL: File hash mismatch! The payload was corrupted in transit or maliciously altered.")
        os.remove(file_path) # Automatically destroy dangerous payload
        sys.exit(1)

def upload_file(filepath: str, version: int = 1):
    """Uploads a file administratively to the server."""
    print(f"[*] Admin context: Uploading '{filepath}' to server as version {version}...")
    filename = os.path.basename(filepath)
    url = f"{SERVER_URL}/upload?version={version}"
    
    try:
        with open(filepath, "rb") as f:
            files = {"file": (filename, f)}
            response = requests.post(url, files=files)
            response.raise_for_status()
            print("[+] Successfully uploaded, hashed, and signed file on the server.")
            print(f"[+] Server response: {response.json()['message']}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to upload file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Mini-TUF Secure Update Client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Download command
    download_parser = subparsers.add_parser("download", help="Securely download a verified file")
    download_parser.add_argument("filename", help="Name of the file to download")

    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Upload a new file payload to the backend")
    upload_parser.add_argument("filepath", help="Path to the local file to upload")
    upload_parser.add_argument("--version", type=int, default=1, help="Version of the target")

    args = parser.parse_args()

    if args.command == "download":
        download_and_verify(args.filename)
    elif args.command == "upload":
        upload_file(args.filepath, args.version)

if __name__ == "__main__":
    main()
