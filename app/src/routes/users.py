from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select

from app.core.database import SessionDep
from app.core.authentication import get_current_user, oauth2_scheme
from app.mocks.mock_data import mock_users
from app.src.models.users import User

router = APIRouter()

async def common_parameters(q: str | None = None, skip: int = 0, limit: int = 100):
    return { "q": q, "skip": skip, "limit": limit }

CommonsDependencies = Annotated[dict, Depends(common_parameters)]
@router.get("/")
async def get_users(token: Annotated[str, Depends(oauth2_scheme)], params: CommonsDependencies, session: SessionDep):
    result = await session.exec(select(User).offset(params['skip']).limit(params['limit']))
    users = result.all()
    return {"token": token, "users": users, **params}

@router.get("/me/")
async def get_my_info(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user

@router.get("/{user_id}")
async def get_user(user_id: int, token: Annotated[str, Depends(oauth2_scheme)], session: SessionDep):
    result = await session.exec(select(User).where(User.member_id == user_id))
    user = result.first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"token": token, "user": user}

@router.post("/")
async def create_user(user: User, token: Annotated[str, Depends(oauth2_scheme)], session: SessionDep):
    user_dict = user.model_dump()
    session.add(user)
    await session.commit()
    await session.refresh(user)
    message = f"User '{user.name}' with member ID {user.member_id} created successfully."
    return {"message": message, "user": user, "token": token}


@router.post("/{user_id}/checkout/")
async def checkout_book(user_id: int, book_ids: list[int], token: Annotated[str, Depends(oauth2_scheme)]):
    return {"user_id": user_id, "book_ids": book_ids, "status": "checked out", "token": token}

@router.post("/{user_id}/return/")
async def return_book(user_id: int, book_ids: list[int], token: Annotated[str, Depends(oauth2_scheme)]):
    return {"user_id": user_id, "book_ids": book_ids, "status": "returned", "token": token}

