from datetime import datetime
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

NAME_REGEX = re.compile(r"^[a-zA-Z\s.'-]+$")
CODE_REGEX = re.compile(r"^\d{6}$")



class UserCreate(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, description="Full name of the user")
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=6, max_length=128, description="Password (minimum 6 characters)")

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 2:
            raise ValueError("Full name must be at least 2 characters long")
        if not NAME_REGEX.match(clean):
            raise ValueError("Full name must only contain letters, spaces, hyphens, periods, and apostrophes (numbers and symbols like @, #, $ are not allowed)")
        return clean

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters long")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class UserResponse(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    role: str
    auth_provider: Optional[str] = "local"
    avatar_url: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class UserUpdate(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, description="Updated full name")
    email: EmailStr = Field(..., description="Updated email address")

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 2:
            raise ValueError("Full name must be at least 2 characters long")
        if not NAME_REGEX.match(clean):
            raise ValueError("Full name must only contain letters, spaces, hyphens, periods, and apostrophes (numbers and symbols like @, #, $, ! are not allowed)")
        return clean


class UserChangePassword(BaseModel):
    current_password: str = Field(..., min_length=1, description="Current user password")
    new_password: str = Field(..., min_length=6, max_length=128, description="New password (minimum 6 characters)")
    confirm_password: str = Field(..., min_length=6, max_length=128, description="Confirm new password")

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("New password must be at least 6 characters long")
        return v


class GoogleLoginRequest(BaseModel):
    credential: str = Field(..., min_length=10, description="Google OAuth / OpenID Connect ID Token (JWT)")


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user: Optional[UserResponse] = None


class UserRegisterResponse(BaseModel):
    message: str
    id: int


class GuardianCodeGenerateResponse(BaseModel):
    message: str
    code: str
    expires_at: datetime


class GuardianCodeVerifyRequest(BaseModel):
    code: str = Field(..., description="6-digit numeric guardian access code")

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        clean = v.strip()
        if not CODE_REGEX.match(clean):
            raise ValueError("Guardian access code must contain exactly 6 digits (numbers only)")
        return clean


class GuardianDashboardResponse(BaseModel):
    message: str
    role: str = "guardian"
    guarded_user: Dict[str, Any]
    security_status: str
    overall_status: str = "SAFE"
    security_summary: Optional[Dict[str, Any]] = None
    recent_alerts: Optional[List[Dict[str, Any]]] = None
    protection_modules: List[str]
    authorized_until: datetime


class UserDashboardResponse(BaseModel):
    message: str
    user: UserResponse
    security_status: str
    active_threat_level: str
    active_guardian_codes: int


class AdminDashboardResponse(BaseModel):
    message: str
    admin_email: str
    role: str = "admin"
    total_users: int
    active_guardian_links: int
    system_status: str