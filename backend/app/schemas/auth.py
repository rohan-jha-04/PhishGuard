from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict

class UserRegister(BaseModel):
    email: EmailStr = Field(..., description="Valid institutional or personal email address")
    full_name: str = Field(..., min_length=2, max_length=100, description="Full name of researcher/student")
    password: str = Field(..., min_length=6, max_length=128, description="Secure user password")

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None

