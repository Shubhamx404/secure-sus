# Secure Software Update System (Mini-TUF)

## Overview
This project is a secure software update system inspired by The Update Framework (TUF). It implements robust file verification using cryptographic signatures and hashing algorithms, ensuring that clients only download and execute trusted updates without fear of tampering or rollback attacks.

## Architecture and Components

The architecture is divided into a centralized distribution backend and a local client tool.

### Backend Application (Server)
Located in `/server`, the backend is built using FastAPI. It manages the following responsibilities:
- **Keys Management (`signer.py`)**: Automatically generates and stores an Ed25519 key pair used for creating non-repudiable cryptographic signatures.
- **Metadata Management (`metadata.py`)**: Hashes the requested file payloads via SHA256, determines payload size, and packs all parameters into a deterministic JSON format representing TUF target metadata. The JSON is then mathematically signed and stored.
- **API Endpoints (`main.py`)**:
    - `POST /upload`: Securely uploads target payloads for distribution, instantly generating the required signed cryptographic metadata manifest.
    - `GET /public_key`: Serves the cryptographic public key mapping so clients have a source of truth for signature verification.
    - `GET /metadata/{filename}`: Delivers the standalone metadata manifest, allowing clients to independently verify the signature without requiring the target binary file.
    - `GET /download/{filename}`: Delivers the raw unauthenticated file payload.

### CLI Application (Client)
Located in `/client`, the command-line interface interacts with the backend to perform security assessments prior to storing data on disk.
- **Cryptographic Verification (`verifier.py`)**: Core mechanism to verify the Ed25519 signatures of the JSON manifest against the known public key as well as the independent SHA256 integrity map.
- **CLI Commands (`client.py`)**: Exposes sub-modules to administratively upload payloads and securely download requested files. During a download, the client mandates signature validation of the metadata first, explicitly fetches the payload, and validates that the hash of the downloaded payload maps correctly to the authenticated metadata entry. The client strictly terminates if tampering is detected.

## System Dependencies
- Python 3.9+
- FastAPI and Uvicorn for asynchronous server hosting
- Cryptography library for Ed25519 implementation
- Requests library for robust client HTTP handling
- Pytest for integration testing

## Installation and Setup

1. Create and configure a Python virtual environment:
```shell
python -m venv venv
```

2. Activate the virtual environment:
    - Windows: `.\venv\Scripts\Activate.ps1`
    - Unix/MacOS: `source venv/bin/activate`

3. Install system requirements:
```shell
pip install -r requirements.txt
```

## Running the Application

### 1. Launching the Backend Server
Start the centralized distribution backend locally via uvicorn. The server runs securely on port 8000.
```shell
uvicorn server.main:app --port 8000
```
Upon startup, the server automatically generates the required Ed25519 keys inside the `keys/` directory if they do not already exist.

### 2. Client Operations
The integrated CLI provides secure operational controls:

**Upload a Target Payload (Admin Command):**
Securely index and distribute a file to the backend server.
```shell
python -m client.client upload my_target_file.txt
```

**Download a Verified Payload (Client Command):**
Request a payload cleanly from the backend and execute the strict cryptographic verification routine.
```shell
python -m client.client download my_target_file.txt
```

Downloaded artifacts that successfully pass all verification parameters are securely stored inside `data/client_downloads/`.

## Automated Testing
An automated test suite exists to systematically prove system stability and guarantee cryptographic assurances. Run the comprehensive integration test suite via Pytest:
```shell
pip install pytest httpx
pytest test_system.py -v
```

## Containerization
A `Dockerfile` is provided for immediate containerized deployment into cloud environments.
```shell
docker build -t secure-update-system .
docker run -p 8000:8000 secure-update-system
```
