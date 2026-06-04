import os
import logging
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from models import User, Credential, init_db, get_engine
from auth import create_access_token, get_current_user, verify_password, hash_password
from encryption import encrypt_data, decrypt_data

# ---------------------------------------------------------------------------
# Proactive configuration and logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me-in-production")
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("TOKEN_EXPIRE_MINUTES", "60"))

app = FastAPI(title="SecureVault API", version="0.1.0")

# Ensure the database exists before handling any request
@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Database initialised")

# ---------------------------------------------------------------------------
# Dependency to get a DB session
# ---------------------------------------------------------------------------
def get_session():
    with Session(get_engine()) as session:
        yield session

# ---------------------------------------------------------------------------
# Authentication endpoints
# ---------------------------------------------------------------------------
@app.post("/register", summary="Create a new user")
def register(username: str, master_password: str, session: Session = Depends(get_session)):
    if session.exec(select(User).where(User.username == username)).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    user = User(username=username, password_hash=hash_password(master_password))
    session.add(user)
    session.commit()
    session.refresh(user)
    logger.info("Registered new user %s", username)
    return {"msg": "User registered successfully"}

@app.post("/token", summary="Obtain JWT access token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(
        data={"sub": user.username},
        secret_key=SECRET_KEY,
        expires_delta_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
    )
    logger.info("User %s logged in", user.username)
    return {"access_token": access_token, "token_type": "bearer"}

# ---------------------------------------------------------------------------
# Credential management endpoints (protected)
# ---------------------------------------------------------------------------
@app.post("/credentials", summary="Add a new credential")
def add_credential(
    service: str,
    login: str,
    password: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    # Encrypt the password with the user's derived key (derived from master password)
    encrypted_pwd = encrypt_data(password, current_user.master_key)
    cred = Credential(service=service, login=login, password_encrypted=encrypted_pwd, owner_id=current_user.id)
    session.add(cred)
    session.commit()
    session.refresh(cred)
    logger.info("Credential added for service %s by user %s", service, current_user.username)
    return {"msg": "Credential stored successfully"}

@app.get("/credentials/{service}", summary="Retrieve a credential for a service")
def get_credential(
    service: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    cred = session.exec(
        select(Credential).where(
            Credential.service == service, Credential.owner_id == current_user.id
        )
    ).first()
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    decrypted_pwd = decrypt_data(cred.password_encrypted, current_user.master_key)
    logger.info("Credential retrieved for service %s by user %s", service, current_user.username)
    return {"service": cred.service, "login": cred.login, "password": decrypted_pwd}

# ---------------------------------------------------------------------------
# Health check endpoint
# ---------------------------------------------------------------------------
@app.get("/health", summary="Simple health check")
def health_check():
    return {"status": "ok"}
