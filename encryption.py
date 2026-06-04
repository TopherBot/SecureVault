import os
import base64
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Key derivation (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------
def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=iterations,
        dklen=32,
    )

# ---------------------------------------------------------------------------
# Encryption / Decryption helpers using AES‑GCM (authenticated encryption)
# ---------------------------------------------------------------------------
def encrypt_data(plaintext: str, key: bytes) -> bytes:
    # Initialise AESGCM with a 256‑bit key
    aesgcm = AESGCM(key)
    # 12‑byte nonce for GCM – generated securely per operation
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    # Store nonce||ciphertext for later decryption
    return nonce + ct

def decrypt_data(ciphertext: bytes, key: bytes) -> str:
    if len(ciphertext) < 12:
        raise ValueError("Ciphertext too short – missing nonce")
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    except Exception as exc:
        raise ValueError("Decryption failed or data tampered") from exc
    return pt.decode("utf-8")

# ---------------------------------------------------------------------------
# Helper to generate a per‑user master key (stored encrypted on the server)
# ---------------------------------------------------------------------------
def generate_user_master_key(master_password: str) -> bytes:
    # Use a random 16‑byte salt per user – stored alongside the hash
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    # Store salt||key so we can re‑derive later
    return salt + key

def extract_user_key(stored: bytes, master_password: str) -> bytes:
    if len(stored) < 16:
        raise ValueError("Stored key is malformed")
    salt = stored[:16]
    return derive_key(master_password, salt)
