from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.user_schema import (
    Token,
    UserCreate,
    UserLogin,
    UserRegisterResponse,
    UserResponse,
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
    summary="Register a new user"
)
def register(
    user: UserCreate,
    db: Session = Depends(get_db)
):
    normalized_email = user.email.lower().strip()

    # Check if email is already registered
    existing_user = db.query(User).filter(User.email == normalized_email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered. Please use another email or log in."
        )

    # Hash the plain text password securely with bcrypt
    hashed_pwd = hash_password(user.password)

    new_user = User(
        full_name=user.full_name.strip(),
        email=normalized_email,
        password=hashed_pwd
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
    summary="User login with JWT token"
)
def login(
    credentials: UserLogin,
    db: Session = Depends(get_db)
):
    normalized_email = credentials.email.lower().strip()

    # Find user by email
    user = db.query(User).filter(User.email == normalized_email).first()

    # Verify user exists and password hash matches
    if not user or not verify_password(credentials.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Create JWT access token with user id as subject
    access_token = create_access_token(data={"sub": str(user.id)})

    return {
        "access_token": access_token,
        "token_type": "bearer"
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