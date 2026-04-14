# Use an official Python lightweight runtime
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy requirement files and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server application
COPY server /app/server
COPY keys /app/keys
COPY data /app/data

# Expose port for FastAPI
EXPOSE 8000

# Start FastAPI application
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
