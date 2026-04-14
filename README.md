# Secure Software Update System (Mini-TUF)

This project is a secure update/download system inspired by The Update Framework (TUF). It implements robust file verification using cryptographic signatures and hashes, ensuring that clients only download and execute trusted updates without fear of tampering or rollback attacks.

## Resume Description
> Developed a secure software update system inspired by TUF, implementing metadata signing, file integrity verification using SHA256, and public-key cryptography (RSA/Ed25519). Built a FastAPI-based backend and CLI client to ensure secure and authenticated file distribution, preventing tampering and rollback attacks.

## Architecture & Project Structure
- `/server`: FastAPI backend that generates keys, signs metadata, and servers files.
  - `signer.py`: Ed25519 Key generation and signing.
  - `metadata.py`: Target hashing and signed JSON generation. 
  - `main.py`: FastAPI routes to upload files, fetch metadata, and download files.
- `/client`: CLI application for standard client behavior.
  - `verifier.py`: Signature and file hash cryptographic verification.
  - `client.py`: CLI to interface with the server.
- `/keys`: Storage for generated cryptographic keys.
- `/data`: Server file storage repository and Client secure download location.

## Quick Start
### 1. Installation
Ensure you have Python 3.9+ installed.

```bash
# Set up a virtual environment
python -m venv venv
# Activate the environment
# Windows:
.\venv\Scripts\Activate.ps1
# Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```
