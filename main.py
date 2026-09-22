# app.py
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional, List
import hashlib
import secrets
import uuid

import jwt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# ---------------- Config ----------------
SECRET_KEY = "change-me-in-production-please"
ALGORITHM = "HS256"
TOKEN_LIFETIME_HOURS = 48
PBKDF2_ITERATIONS = 100_000

# ---------------- Storage ----------------
users: dict[str, "User"] = {}
ads: dict[str, "Ad"] = {}


# ---------------- Enums ----------------
class UserGroup(str, Enum):
    user = "user"
    admin = "admin"


# ---------------- Pydantic models ----------------
class UserCreate(BaseModel):
    username: str
    password: str
    group: UserGroup = UserGroup.user


class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    group: Optional[UserGroup] = None


class User(BaseModel):
    id: str
    username: str
    password_hash: str
    group: UserGroup
    created_at: datetime


class UserPublic(BaseModel):
    id: str
    username: str
    group: UserGroup
    created_at: datetime


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class AdCreate(BaseModel):
    title: str
    description: str
    price: float


class AdUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None


class Ad(BaseModel):
    id: str
    title: str
    description: str
    price: float
    author: str
    owner_id: str
    created_at: datetime


# ---------------- Password helpers ----------------
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS
    ).hex()
    return f"{salt}${pwd_hash}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, pwd_hash = hashed.split("$", 1)
    except ValueError:
        return False
    check = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS
    ).hex()
    return secrets.compare_digest(check, pwd_hash)


# ---------------- JWT helpers ----------------
def create_token(user: "User") -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.id,
        "username": user.username,
        "group": user.group.value,
        "iat": now,
        "exp": now + timedelta(hours=TOKEN_LIFETIME_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# ---------------- Auth dependencies ----------------
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[User]:
    """Возвращает пользователя, если передан валидный Bearer-токен, иначе None."""
    if credentials is None:
        return None

    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")

    user_id = payload.get("sub")
    user = users.get(user_id) if user_id else None
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user


def get_current_user(user: Optional[User] = Depends(get_current_user_optional)) -> User:
    """Требует авторизацию. Иначе 401."""
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.group != UserGroup.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin privileges required")
    return user


# ---------------- Lifespan: создать дефолтного админа ----------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    if not any(u.group == UserGroup.admin for u in users.values()):
        admin_id = str(uuid.uuid4())
        users[admin_id] = User(
            id=admin_id,
            username="admin",
            password_hash=hash_password("admin"),
            group=UserGroup.admin,
            created_at=datetime.now(timezone.utc),
        )
    yield


app = FastAPI(title="Advertisement API", lifespan=lifespan)


# ================== LOGIN ==================
@app.post("/login", response_model=TokenResponse)
def login(data: LoginRequest):
    user = next((u for u in users.values() if u.username == data.username), None)
    if user is None or not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid username or password"
        )
    token = create_token(user)
    return TokenResponse(
        access_token=token,
        expires_in=TOKEN_LIFETIME_HOURS * 3600,
    )


# ================== USERS ==================
@app.post("/user", response_model=UserPublic, status_code=201)
def create_user(
    data: UserCreate,
    current: Optional[User] = Depends(get_current_user_optional),
):
    # Создавать админов может только админ
    if data.group == UserGroup.admin and (
        current is None or current.group != UserGroup.admin
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only admin can create admin users"
        )

    if any(u.username == data.username for u in users.values()):
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists")

    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        username=data.username,
        password_hash=hash_password(data.password),
        group=data.group,
        created_at=datetime.now(timezone.utc),
    )
    users[user_id] = user
    return UserPublic(**user.model_dump(exclude={"password_hash"}))


@app.get("/user", response_model=List[UserPublic])
def list_users(_: User = Depends(require_admin)):
    """Список всех пользователей — только для admin."""
    return [
        UserPublic(**u.model_dump(exclude={"password_hash"}))
        for u in users.values()
    ]


@app.get("/user/{user_id}", response_model=UserPublic)
def get_user(user_id: str):
    """Доступно анонимно."""
    user = users.get(user_id)
    if user is None:
        raise HTTPException(404, "not found")
    return UserPublic(**user.model_dump(exclude={"password_hash"}))


@app.patch("/user/{user_id}", response_model=UserPublic)
def update_user(
    user_id: str,
    data: UserUpdate,
    current: User = Depends(get_current_user),
):
    user = users.get(user_id)
    if user is None:
        raise HTTPException(404, "not found")

    is_admin = current.group == UserGroup.admin
    is_self = current.id == user_id

    if not is_admin and not is_self:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Cannot modify other users"
        )

    update_data = data.model_dump(exclude_unset=True)

    # Менять группу может только admin
    if "group" in update_data and not is_admin:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only admin can change group"
        )

    if "username" in update_data and update_data["username"] != user.username:
        if any(
            u.username == update_data["username"] and u.id != user.id
            for u in users.values()
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists")
        user.username = update_data["username"]

    if "password" in update_data and update_data["password"] is not None:
        user.password_hash = hash_password(update_data["password"])

    if "group" in update_data and update_data["group"] is not None:
        user.group = update_data["group"]

    users[user_id] = user
    return UserPublic(**user.model_dump(exclude={"password_hash"}))


@app.delete("/user/{user_id}")
def delete_user(
    user_id: str,
    current: User = Depends(get_current_user),
):
    user = users.get(user_id)
    if user is None:
        raise HTTPException(404, "not found")

    is_admin = current.group == UserGroup.admin
    is_self = current.id == user_id

    if not is_admin and not is_self:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Cannot delete other users"
        )

    del users[user_id]
    return {"status": "deleted"}


# ================== ADVERTISEMENTS ==================
@app.post("/advertisement", response_model=Ad, status_code=201)
def create_ad(data: AdCreate, current: User = Depends(get_current_user)):
    ad_id = str(uuid.uuid4())
    ad = Ad(
        id=ad_id,
        author=current.username,
        owner_id=current.id,
        created_at=datetime.now(timezone.utc),
        **data.model_dump(),
    )
    ads[ad_id] = ad
    return ad


@app.get("/advertisement/{advertisement_id}", response_model=Ad)
def get_ad(advertisement_id: str):
    """Доступно анонимно."""
    ad = ads.get(advertisement_id)
    if not ad:
        raise HTTPException(404, "not found")
    return ad


@app.patch("/advertisement/{advertisement_id}", response_model=Ad)
def update_ad(
    advertisement_id: str,
    data: AdUpdate,
    current: User = Depends(get_current_user),
):
    ad = ads.get(advertisement_id)
    if not ad:
        raise HTTPException(404, "not found")

    is_admin = current.group == UserGroup.admin
    is_owner = current.id == ad.owner_id

    if not is_admin and not is_owner:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Cannot modify other users' ads"
        )

    updated = ad.model_copy(
        update={k: v for k, v in data.model_dump().items() if v is not None}
    )
    ads[advertisement_id] = updated
    return updated


@app.delete("/advertisement/{advertisement_id}")
def delete_ad(
    advertisement_id: str,
    current: User = Depends(get_current_user),
):
    ad = ads.get(advertisement_id)
    if not ad:
        raise HTTPException(404, "not found")

    is_admin = current.group == UserGroup.admin
    is_owner = current.id == ad.owner_id

    if not is_admin and not is_owner:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Cannot delete other users' ads"
        )

    del ads[advertisement_id]
    return {"status": "deleted"}


@app.get("/advertisement", response_model=List[Ad])
def search_ads(
    title: Optional[str] = None,
    description: Optional[str] = None,
    price: Optional[float] = None,
    author: Optional[str] = None,
    created_at_from: Optional[datetime] = None,
    created_at_to: Optional[datetime] = None,
):
    """Доступно анонимно."""

    def _to_utc(dt: datetime) -> datetime:
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)

    result = list(ads.values())

    if title is not None:
        result = [a for a in result if title.lower() in a.title.lower()]
    if description is not None:
        result = [a for a in result if description.lower() in a.description.lower()]
    if price is not None:
        result = [a for a in result if a.price == price]
    if author is not None:
        result = [a for a in result if author.lower() in a.author.lower()]
    if created_at_from is not None:
        lower = _to_utc(created_at_from)
        result = [a for a in result if a.created_at >= lower]
    if created_at_to is not None:
        upper = _to_utc(created_at_to)
        result = [a for a in result if a.created_at <= upper]

    return result
