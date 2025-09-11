from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

from app.core.database import SessionDep
from app.mocks.mock_data import mock_users
from app.src.models.users import User

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def common_parameters(q: str | None = None, skip: int = 0, limit: int = 100):
    return { "q": q, "skip": skip, "limit": limit }

CommonsDependencies = Annotated[dict, Depends(common_parameters)]
@router.get("/")
async def get_users(token: Annotated[str, Depends(oauth2_scheme)], params: CommonsDependencies):
    return {"token": token, "users": mock_users, **params}

@router.get("/me/")
async def get_my_info(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token, "user": mock_users[0]}  # Just an example, replace with actual user info

@router.get("/{user_id}")
async def get_user(user_id: int, token: Annotated[str, Depends(oauth2_scheme)]):
    if user_id not in [u["member_id"] for u in mock_users]:
        raise HTTPException(status_code=404, detail="User not found")
    user = next((u for u in mock_users if u["member_id"] == user_id), None)
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

