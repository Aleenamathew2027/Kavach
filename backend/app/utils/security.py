from datetime import datetime, timedelta, timezone
import os
import secrets
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.bcrypt import BcryptHasher
from sqlalchemy.orm import Session

from app.database.connection import SessionLocal
from app.models.user import User

load_dotenv()

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "kavach_default_secret_key_please_set_in_env")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# Password hashing with bcrypt
pwd_context = PasswordHash((BcryptHasher(),))

http_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Hash a plain text password or code using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain text password or code against a stored hash or legacy plain text."""
    if not plain_password or not hashed_password:
        return False
    if hashed_password.startswith(("$2b$", "$2a$", "$2y$", "$argon2")):
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception:
            return False
    # Fallback for unhashed legacy passwords
    return secrets.compare_digest(plain_password, hashed_password)


def generate_guardian_code() -> str:
    """Generate a cryptographically secure 6-digit numeric access code."""
    digits = "".join(secrets.choice("0123456789") for _ in range(6))
    return digits


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token with role and subject."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Validate JWT access token and return the authenticated User model."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    user_id_str: str = payload.get("sub")
    if user_id_str is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = int(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_role(allowed_roles: List[str]):
    """FastAPI dependency factory to enforce role-based access control."""
    normalized_allowed = [r.lower().strip() for r in allowed_roles]

    def role_dependency(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
        db: Session = Depends(get_db),
    ) -> Dict[str, Any]:
        if credentials is None or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication credentials were not provided",
                headers={"WWW-Authenticate": "Bearer"},
            )

        payload = decode_access_token(credentials.credentials)
        token_role = str(payload.get("role", "")).lower().strip()

        if not token_role or token_role not in normalized_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: requires one of the following roles: {allowed_roles}",
            )

        user_id_str = payload.get("sub")
        user = None
        if user_id_str:
            try:
                user = db.query(User).filter(User.id == int(user_id_str)).first()
            except ValueError:
                pass

        if token_role != "guardian" and user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User associated with token no longer exists",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return {
            "user": user,
            "payload": payload,
            "role": token_role,
        }

    return role_dependency
