import os
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.user_schema import (
    Token,
    UserChangePassword,
    UserCreate,
    UserLogin,
    UserRegisterResponse,
    UserResponse,
    UserUpdate,
)
from app.utils.security import (
    create_access_token,
    get_current_user,
    get_db,
    hash_password,
    verify_password,
)

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


@router.post(
    "/register",
    response_model=UserRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new standard user"
)
def register(
    user: UserCreate,
    db: Session = Depends(get_db)
):
    normalized_email = user.email.lower().strip()
    admin_email = os.getenv("ADMIN_EMAIL", "admin@kavach.com").lower().strip()

    # Disallow normal registration with admin email
    if normalized_email == admin_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot register as administrator. Please use a different email."
        )

    # Check if email is already registered
    existing_user = db.query(User).filter(User.email == normalized_email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered. Please use another email or log in."
        )

    # Hash the plain text password securely with bcrypt
    hashed_pwd = hash_password(user.password)

    # Normal users always receive role="user"
    new_user = User(
        full_name=user.full_name.strip(),
        email=normalized_email,
        password=hashed_pwd,
        role="user"
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed due to a database error."
        )

    return {
        "message": "User Registered Successfully",
        "id": new_user.id
    }


@router.post(
    "/login",
    response_model=Token,
    summary="User or Admin login with JWT token"
)
def login(
    credentials: UserLogin,
    db: Session = Depends(get_db)
):
    normalized_email = credentials.email.lower().strip()

    # Find user by email
    user = db.query(User).filter(User.email == normalized_email).first()

    # Check against database user
    if not user or not verify_password(credentials.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # If user password in DB was legacy unhashed, upgrade it now to bcrypt
    if not user.password.startswith(("$2b$", "$2a$", "$2y$", "$argon2")):
        try:
            user.password = hash_password(credentials.password)
            db.commit()
        except Exception:
            db.rollback()

    # Create JWT access token with user id as subject and explicit role
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "role": user.role,
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role,
    }


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user profile"
)
def get_me(
    current_user: User = Depends(get_current_user)
):
    return current_user


@router.put(
    "/me",
    response_model=UserResponse,
    summary="Update current authenticated user profile"
)
def update_profile(
    body: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    normalized_email = body.email.lower().strip()
    admin_email = os.getenv("ADMIN_EMAIL", "admin@kavach.com").lower().strip()

    # If email changed, check for duplicate and disallow admin email
    if normalized_email != current_user.email:
        if current_user.role != "admin" and normalized_email == admin_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot use administrator email address."
            )
        existing = db.query(User).filter(User.email == normalized_email, User.id != current_user.id).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address is already in use by another account."
            )
        current_user.email = normalized_email

    current_user.full_name = body.full_name.strip()

    try:
        db.commit()
        db.refresh(current_user)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile due to database error."
        )

    return current_user


@router.post(
    "/change-password",
    summary="Change authenticated user password"
)
def change_password(
    body: UserChangePassword,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verify current password
    if not verify_password(body.current_password, current_user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect."
        )

    # Check that new password and confirmation match
    if body.new_password != body.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirmation password do not match."
        )

    # Hash new password securely with bcrypt
    hashed_pwd = hash_password(body.new_password)
    current_user.password = hashed_pwd

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password due to database error."
        )

    return {
        "message": "Password changed successfully."
    }