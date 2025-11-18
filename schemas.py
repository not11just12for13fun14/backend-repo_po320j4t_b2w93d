"""
Database Schemas for FoodReview

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercased class name (e.g., User -> "user").
"""
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr, HttpUrl


class User(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: EmailStr
    password_hash: str = Field(..., description="Hashed password (bcrypt)")
    role: str = Field("user", description="user | admin")
    profile_image: Optional[str] = Field(None, description="URL to profile image")
    about: Optional[str] = Field(None, max_length=280)


class Restaurant(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(None, max_length=1000)
    location: Optional[str] = Field(None, max_length=200)
    cuisine_type: Optional[str] = Field(None, max_length=60)
    average_rating: float = Field(0, ge=0, le=5)
    images: List[str] = Field(default_factory=list)


class Review(BaseModel):
    user_id: str = Field(..., description="ObjectId as string")
    restaurant_id: str = Field(..., description="ObjectId as string")
    rating: int = Field(..., ge=1, le=5)
    review_text: Optional[str] = Field(None, max_length=2000)
    images: List[str] = Field(default_factory=list, description="Image URLs")
    # Optional breakdown fields
    taste: Optional[int] = Field(None, ge=1, le=5)
    ambience: Optional[int] = Field(None, ge=1, le=5)
    service: Optional[int] = Field(None, ge=1, le=5)
