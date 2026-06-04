# SecureVault

SecureVault is a **self‑hosted, zero‑knowledge password manager** that provides both a modern web API (FastAPI) and a convenient command‑line interface. All secrets are encrypted client‑side using strong cryptography before they ever touch the database, ensuring the server never sees plaintext passwords.

---

## Features

- End‑to‑end encryption with per‑user keys derived from the master password.
- RESTful API built with FastAPI (OpenAPI docs automatically generated).
- CLI powered by Click for quick local management.
- SQLite backend via SQLModel (easy to replace with PostgreSQL, MySQL, etc.).
- JWT‑based authentication with configurable expiration.
- Comprehensive error handling and input validation.
- Extensible architecture: add additional credential types or integrations.

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/SecureVault.git
cd SecureVault

# Create a virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Initialise the database
python -c "from models import init_db; init_db()"

# Run the API server
uvicorn main:app --host 0.0.0.0 --port 8000
```

The API docs will be available at `http://localhost:8000/docs`.

---

## CLI Usage

```bash
# Register a new user (you will be prompted for a master password)
python cli.py register --username alice

# Login and obtain a JWT token (stored in ~/.securevault/token)
python cli.py login --username alice

# Add a credential
python cli.py add --service "GitHub" --login "aliceGH" --password "s3cr3t"

# Retrieve a credential
python cli.py get --service "GitHub"
```

---

## Security Considerations

- **Zero‑Knowledge**: The server stores only ciphertext. The master password never leaves the client process.
- **Key Derivation**: PBKDF2‑HMAC‑SHA256 with 200 000 iterations and a per‑user salt.
- **Transport**: Always run behind TLS (e.g., use a reverse proxy like Nginx with HTTPS).
- **Token Handling**: JWTs are signed with a strong secret (`SECRET_KEY` env var). Rotate regularly.

For a full security model see `SECURITY.md`.

---

## Contributing

Contributions are welcome! Please read `SECURITY.md` before reporting vulnerabilities and follow the standard GitHub pull‑request workflow.

---

## License

MIT – see `LICENSE` for details.
