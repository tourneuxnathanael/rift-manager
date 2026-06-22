"""Schémas Pydantic pour les requêtes/réponses liées à l'authentification."""

from pydantic import BaseModel, EmailStr
from datetime import datetime


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    email: str
    plan: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanHistoryItem(BaseModel):
    id: int
    target: str
    score: int
    grade: str
    created_at: datetime

    class Config:
        from_attributes = True


class UpdateProfileRequest(BaseModel):
    email: EmailStr | None = None
    current_password: str | None = None
    new_password: str | None = None
