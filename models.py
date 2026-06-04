from pathlib import Path
from typing import Optional

from sqlmodel import Field, SQLModel, create_engine, Session

# ---------------------------------------------------------------------------
# Database configuration
# ---------------------------------------------------------------------------
DB_PATH = Path(__file__).parent / "securevault.db"
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)

def get_engine():
    return engine

def init_db():
    SQLModel.metadata.create_all(engine)

# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    # The master_key is derived from the master password (PBKDF2) and stored
    # encrypted with the server secret; for simplicity we store it directly
    # here (real deployments should use a hardware security module).
    master_key: bytes = Field(sa_column_kwargs={"type_": "BLOB"})

# ---------------------------------------------------------------------------
# Credential model
# ---------------------------------------------------------------------------
class Credential(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    service: str = Field(index=True)
    login: str
    password_encrypted: bytes = Field(sa_column_kwargs={"type_": "BLOB"})
    owner_id: int = Field(foreign_key="user.id")
