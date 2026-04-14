import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from .metadata import create_and_sign_metadata
from .signer import load_or_generate_keys
from cryptography.hazmat.primitives import serialization

app = FastAPI(title="Secure Update Server (Mini-TUF)")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_DIR = os.path.join(BASE_DIR, "data", "server_files")
METADATA_DIR = os.path.join(BASE_DIR, "data", "server_metadata")
os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(METADATA_DIR, exist_ok=True)

# Generate Server Keys on startup if they don't already exist
load_or_generate_keys()

@app.get("/public_key")
def get_public_key():
    """Serves the cryptographic public key for clients to verify signatures."""
    _, public_key = load_or_generate_keys()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {"public_key": pem.decode('utf-8')}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), version: int = 1):
    """Uploads a file, hashes it securely, and generates signed metadata."""
    file_path = os.path.join(STORAGE_DIR, file.filename)
    
    with open(file_path, "wb") as buffer:
        while content := await file.read(4096):
            buffer.write(content)
            
    # Generate and sign the metadata
    signed_meta = create_and_sign_metadata(file_path, version)
    
    return {
        "message": f"Successfully uploaded and signed {file.filename}",
        "metadata": signed_meta
    }

@app.get("/metadata/{filename}")
def get_metadata(filename: str):
    """Returns the signed cryptographic metadata for a specific payload."""
    meta_path = os.path.join(METADATA_DIR, f"{filename}.meta.json")
    if not os.path.exists(meta_path):
        raise HTTPException(status_code=404, detail="Metadata not found")
        
    return FileResponse(meta_path, media_type="application/json")

@app.get("/download/{filename}")
def download_file(filename: str):
    """Serves the actual file payload to end clients."""
    file_path = os.path.join(STORAGE_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
        
    return FileResponse(file_path, media_type="application/octet-stream")
