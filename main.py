# app.py
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
import uuid

app = FastAPI()
ads = {}


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


@app.post("/advertisement", response_model=Ad, status_code=201)
def create_ad(data: AdCreate):
    ad_id = str(uuid.uuid4())
    ad = Ad(id=ad_id, created_at=datetime.utcnow(), **data.model_dump())
    ads[ad_id] = ad
    return ad


@app.get("/advertisement/{advertisement_id}", response_model=Ad)
def get_ad(advertisement_id: str):
    ad = ads.get(advertisement_id)
    if not ad:
        raise HTTPException(404, "not found")
    return ad


@app.patch("/advertisement/{advertisement_id}", response_model=Ad)
def update_ad(advertisement_id: str, data: AdUpdate):
    ad = ads.get(advertisement_id)
    if not ad:
        raise HTTPException(404, "not found")
    updated = ad.model_copy(update={k: v for k, v in data.model_dump().items() if v is not None})
    ads[advertisement_id] = updated
    return updated


@app.delete("/advertisement/{advertisement_id}")
def delete_ad(advertisement_id: str):
    if ads.pop(advertisement_id, None) is None:
        raise HTTPException(404, "not found")
    return {"status": "deleted"}


@app.get("/advertisement", response_model=list[Ad])
def search_ads(
    title: Optional[str] = None,
    description: Optional[str] = None,
    price: Optional[float] = None,
    author: Optional[str] = None,
):
    result = ads.values()
    if title is not None:
        result = [a for a in result if title.lower() in a.title.lower()]
    if description is not None:
        result = [a for a in result if description.lower() in a.description.lower()]
    if price is not None:
        result = [a for a in result if a.price == price]
    if author is not None:
        result = [a for a in result if author.lower() in a.author.lower()]
    return list(result)