import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import User as UserSchema, Restaurant as RestaurantSchema, Review as ReviewSchema

import bcrypt
import jwt

JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALG = "HS256"
TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

app = FastAPI(title="FoodReview API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()


# -------------------- Models --------------------
class SignupRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RestaurantCreate(RestaurantSchema):
    pass


class ReviewCreate(ReviewSchema):
    pass


# -------------------- Helpers --------------------

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def create_access_token(sub: str) -> str:
    payload = {
        "sub": sub,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        # fetch user
        from bson import ObjectId
        user_doc = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user_doc:
            raise HTTPException(status_code=401, detail="User not found")
        user_doc["_id"] = str(user_doc["_id"]) 
        return user_doc
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


# -------------------- Health --------------------
@app.get("/")
def root():
    return {"name": "FoodReview API", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


# -------------------- Auth --------------------
@app.post("/api/auth/signup", response_model=TokenResponse)
def signup(payload: SignupRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    # unique email
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = UserSchema(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role="user",
        profile_image=None,
        about=None,
    )
    user_id = create_document("user", user)
    token = create_access_token(user_id)
    return TokenResponse(access_token=token)


@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user_doc = db["user"].find_one({"email": payload.email})
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user_doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(str(user_doc["_id"]))
    return TokenResponse(access_token=token)


@app.get("/api/auth/me")
def me(current_user=Depends(get_current_user)):
    return current_user


# -------------------- Restaurants --------------------
@app.get("/api/restaurants")
def list_restaurants(q: Optional[str] = None, cuisine: Optional[str] = None, location: Optional[str] = None):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    filt = {}
    if q:
        # basic regex search
        filt["name"] = {"$regex": q, "$options": "i"}
    if cuisine:
        filt["cuisine_type"] = {"$regex": f"^{cuisine}$", "$options": "i"}
    if location:
        filt["location"] = {"$regex": location, "$options": "i"}
    docs = get_documents("restaurant", filt, limit=None)
    for d in docs:
        d["_id"] = str(d["_id"])  # serialize
    return {"items": docs}


@app.get("/api/restaurants/{rid}")
def get_restaurant(rid: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    from bson import ObjectId
    doc = db["restaurant"].find_one({"_id": ObjectId(rid)})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    doc["_id"] = str(doc["_id"]) 
    return doc


@app.post("/api/restaurants")
def create_restaurant(payload: RestaurantCreate, current_user=Depends(get_current_user)):
    # simple role check
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    rid = create_document("restaurant", payload)
    return {"id": rid}


# -------------------- Reviews --------------------
@app.get("/api/restaurants/{rid}/reviews")
def restaurant_reviews(rid: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    docs = list(db["review"].find({"restaurant_id": rid}).sort("created_at", -1))
    for d in docs:
        d["_id"] = str(d["_id"]) 
    return {"items": docs}


@app.post("/api/reviews")
def add_review(payload: ReviewCreate, current_user=Depends(get_current_user)):
    # enforce identity
    payload.user_id = str(current_user["_id"]) if isinstance(current_user["_id"], str) else current_user["_id"]
    # limit images
    if payload.images and len(payload.images) > 5:
        raise HTTPException(status_code=400, detail="Max 5 images")
    rid = create_document("review", payload)
    # recompute average rating
    try:
        _recompute_restaurant_avg(payload.restaurant_id)
    except Exception:
        pass
    return {"id": rid}


@app.put("/api/reviews/{review_id}")
def update_review(review_id: str, payload: ReviewCreate, current_user=Depends(get_current_user)):
    from bson import ObjectId
    doc = db["review"].find_one({"_id": ObjectId(review_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    if str(doc.get("user_id")) != str(current_user["_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    update = payload.model_dump()
    update["updated_at"] = datetime.now(timezone.utc)
    db["review"].update_one({"_id": ObjectId(review_id)}, {"$set": update})
    try:
        _recompute_restaurant_avg(payload.restaurant_id)
    except Exception:
        pass
    return {"status": "ok"}


@app.delete("/api/reviews/{review_id}")
def delete_review(review_id: str, current_user=Depends(get_current_user)):
    from bson import ObjectId
    doc = db["review"].find_one({"_id": ObjectId(review_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    if str(doc.get("user_id")) != str(current_user["_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    db["review"].delete_one({"_id": ObjectId(review_id)})
    try:
        _recompute_restaurant_avg(doc.get("restaurant_id"))
    except Exception:
        pass
    return {"status": "ok"}


# -------------------- Uploads --------------------
@app.post("/api/uploads")
async def upload_image(file: UploadFile = File(...), current_user=Depends(get_current_user)):
    # For this environment, we'll store file to local tmp and return a pseudo URL.
    # In production, integrate Cloudinary/S3.
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Max file size 5MB")
    filename = f"{datetime.now().timestamp()}_{file.filename}"
    path = f"/tmp/{filename}"
    with open(path, "wb") as f:
        f.write(content)
    # Return a dev URL placeholder
    return {"url": f"/uploads/{filename}"}


# -------------------- Utilities --------------------

def _recompute_restaurant_avg(restaurant_id: str):
    """Recompute and store average rating for a restaurant"""
    from bson import ObjectId
    cur = db["review"].find({"restaurant_id": restaurant_id}, {"rating": 1})
    ratings = [doc.get("rating", 0) for doc in cur]
    avg = round(sum(ratings) / len(ratings), 2) if ratings else 0
    db["restaurant"].update_one({"_id": ObjectId(restaurant_id)}, {"$set": {"average_rating": avg}})


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
