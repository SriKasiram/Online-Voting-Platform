# API image. docker-compose runs only PostgreSQL; this image runs the API on its own.
# VULN-04: no key, certificate, backup or .env goes into the image (.dockerignore). The container
# starts through the SR-10 TLS launcher, with the certificate and keys mounted read-only at run
# time: see "Run the API in a container" in README.md.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# VULN-04: listen on the container's own interface, the only way the published port reaches the
# server, with the certificate and key from the read-only mount at /app/certs
ENV SERVER_HOST=0.0.0.0 \
    TLS_CERT_FILE=/app/certs/dev-cert.pem \
    TLS_KEY_FILE=/app/certs/dev-key.pem

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Run as an ordinary user, not root
RUN useradd --create-home --uid 10001 api
USER api

# VULN-04: the single HTTPS port (SR-10: TLS 1.3 only, no plaintext listener), never plain uvicorn
EXPOSE 8443
CMD ["python", "-m", "app.serve"]
