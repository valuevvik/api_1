from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, List
import uuid, jwt, hashlib

SECRET = "secret"
ALGO = "HS256"

app = FastAPI()
security = HTTPBearer(auto_error=False)

users = {}
ads = {}

def hash_pw(p): return hashlib.sha256(p.encode()).hexdigest()

class UserCreate(BaseModel):
    username: str
    password: str
    group: str = "user"

class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    group: Optional[str] = None

class User(BaseModel):
    id: str
    username: str
    group: str

class LoginRequest(BaseModel):
    username: str
    password: str

class AdCreate(BaseModel):
    title: str
    description: str
    price: float
    author: str

class AdUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    author: Optional[str] = None

class Ad(BaseModel):
    id: str
    title: str
    description: str
    price: float
    author: str
    created_at: datetime
    owner_id: str

def get_current_user(cred: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if cred is None:
        return None
    try:
        payload = jwt.decode(cred.credentials, SECRET, algorithms=[ALGO])
    except jwt.PyJWTError:
        return None
    return users.get(payload.get("sub"))

def require_user(user = Depends(get_current_user)):
    if not user:
        raise HTTPException(401, "unauthorized")
    return user