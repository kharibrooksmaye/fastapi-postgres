from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select

from app.core.authentication import get_current_user, oauth2_scheme
from app.core.authorization import require_roles
from app.core.database import SessionDep
from app.src.models.users import User

router = APIRouter()


async def common_parameters(q: str | None = None, skip: int = 0, limit: int = 100):
    return {"q": q, "skip": skip, "limit": limit}


CommonsDependencies = Annotated[dict, Depends(common_parameters)]


@router.get("/")
async def get_users(
    token: Annotated[str, Depends(oauth2_scheme)],
    admin: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    params: CommonsDependencies,
    session: SessionDep,
):
    result = await session.exec(
        select(User).offset(params["skip"]).limit(params["limit"])
    )
    users = result.all()
    return {"token": token, "users": users, **params}


@router.get("/me/")
async def get_my_info(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user


@router.get("/{user_id}")
async def get_user(
    user_id: int,
    token: Annotated[str, Depends(oauth2_scheme)],
    staff: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    session: SessionDep,
):
    result = await session.exec(select(User).where(User.member_id == user_id))
    user = result.first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"token": token, "user": user}


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    admin: Annotated[User, Depends(require_roles("admin"))],
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
):
    result = await session.exec(select(User).where(User.member_id == user_id))
    user = result.first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await session.delete(user)
    await session.commit()
    return {
        "message": f"User with member ID {user_id} deleted successfully.",
        "token": token,
    }


@router.post("/")
async def create_user(
    user: User,
    admin: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
):
    session.add(user)
    await session.commit()
    await session.refresh(user)
    message = (
        f"User '{user.name}' with member ID {user.member_id} created successfully."
    )
    return {"message": message, "user": user, "token": token}
