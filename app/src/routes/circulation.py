from typing import Annotated
from fastapi import APIRouter, Depends
from sqlmodel import select

from app.core.authentication import oauth2_scheme
from app.core.authorization import require_roles
from app.core.database import SessionDep
from app.src.models.circulation import CatalogEvent
from app.src.models.users import User
from app.src.routes.users import CommonsDependencies

router = APIRouter()


@router.get("/")
async def read_root(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
    params: CommonsDependencies,
    admin: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
):
    result = await session.exec(
        select(CatalogEvent).offset(params["skip"]).limit(params["limit"])
    )
    events = result.all()

    return events


@router.post("/checkout")
async def checkout_book(
    user_id: int,
    book_ids: list[int],
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
):
    return {
        "user_id": user_id,
        "book_ids": book_ids,
        "status": "checked out",
        "token": token,
    }


@router.post("/return/")
async def return_book(
    user_id: int,
    catalog_ids: list[int],
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
):
    return {
        "user_id": user_id,
        "catalog_ids": catalog_ids,
        "status": "returned",
        "token": token,
    }


@router.post("/renew")
async def renew_items(
    user_id: int,
    catalog_ids: list[int],
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
):
    return {
        "user_id": user_id,
        "catalog_ids": catalog_ids,
        "status": "renew",
        "token": token,
    }
