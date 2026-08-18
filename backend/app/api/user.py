import os
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.user_schema import (
    GoogleLoginRequest,
    Token,
    UserChangePassword,
    UserCreate,
    UserLogin,
    UserRegisterResponse,
    UserResponse,
    UserUpdate,
)
from app.services.google_auth_service import verify_google_token
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
        "user": user,
    }


@router.post(
    "/google-login",
    response_model=Token,
    summary="Authenticate or register standard user via verified Google ID Token"
)
def google_login(
    body: GoogleLoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticates a user via verified Google OAuth ID token.
    - If Google account already exists: logs the user in.
    - If Google email exists as a normal user: links the Google identity safely.
    - If account does not exist: registers a new KAVACH USER account (role='user').
    - If email belongs to an Admin: rejects Google login to preserve admin password authentication.
    - Issues standard KAVACH JWT access token.
    """
    # 1. Verify Google identity token with Google official services
    try:
        google_info = verify_google_token(body.credential)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(val_err),
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to verify Google authentication token.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    google_id = google_info["google_id"]
    email = google_info["email"]
    name = google_info["name"]
    picture = google_info.get("picture")
    admin_email = os.getenv("ADMIN_EMAIL", "admin@kavach.com").lower().strip()

    # 2. Check if user already exists by google_id
    user = db.query(User).filter(User.google_id == google_id).first()

    if user:
        # Check if existing user is admin
        if user.role == "admin" or user.email == admin_email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrator accounts must authenticate using the secure Administrator credentials."
            )
        # Update avatar/name if changed
        if picture and not user.avatar_url:
            user.avatar_url = picture
            db.commit()
    else:
        # 3. Check if user already exists by verified email
        user_by_email = db.query(User).filter(User.email == email).first()

        if user_by_email:
            if user_by_email.role == "admin" or email == admin_email:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Administrator accounts must authenticate using the secure Administrator credentials."
                )

            # Link Google identity to existing user account safely
            user_by_email.google_id = google_id
            user_by_email.auth_provider = "google"
            if picture and not user_by_email.avatar_url:
                user_by_email.avatar_url = picture
            db.commit()
            db.refresh(user_by_email)
            user = user_by_email
        else:
            # 4. Create a new standard KAVACH USER account
            # Disallow creating admin accounts via Google
            if email == admin_email:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Administrator accounts must authenticate using the secure Administrator credentials."
                )

            user = User(
                full_name=name,
                email=email,
                password=None,
                role="user",  # Strict: New Google accounts ALWAYS receive role="user"
                auth_provider="google",
                google_id=google_id,
                avatar_url=picture,
            )
            try:
                db.add(user)
                db.commit()
                db.refresh(user)
            except Exception:
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create user account from Google profile."
                )

    # 5. Issue the standard KAVACH JWT access token
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
        "user": user,
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