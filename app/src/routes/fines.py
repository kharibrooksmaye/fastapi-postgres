from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select

from app.core.authentication import get_current_user, oauth2_scheme
from app.core.authorization import require_roles
from app.core.database import SessionDep
from app.src.models.fines import Fines
from app.src.models.users import User
from app.src.routes.users import CommonsDependencies


router = APIRouter()

@router.get("/")
async def read_fines(
    token: Annotated[str, Depends(oauth2_scheme)],
    admin: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    params: CommonsDependencies,
    session: SessionDep,
):
    if not admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    result = await session.exec(
        select(Fines).offset(params["skip"]).limit(params["limit"])
    )
    fines = result.all()
    return {"fines": fines, **params}

@router.get("/me")
async def get_my_fines(
    current_user: Annotated[User, Depends(get_current_user)],
    session: SessionDep,
):
    result = await session.exec(select(Fines).where(Fines.user_id == current_user.id))
    fines = result.all()
    return {"fines": fines}

@router.get("/{user_id}")
async def get_user_fines(
    user_id: int,
    token: Annotated[str, Depends(oauth2_scheme)],
    staff: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    session: SessionDep,
):
    result = await session.exec(select(Fines).where(Fines.user_id == user_id))
    fines = result.all()
    return {"fines": fines}

@router.get("/{fine_id}")
async def get_fine(
    fine_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    token: Annotated[str, Depends(oauth2_scheme)],
    staff: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    session: SessionDep,
):
    result = await session.exec(select(Fines).where(Fines.id == fine_id))
    fine = result.one_or_none()
    if not staff and current_user.id != fine.user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    if not fine:
        raise HTTPException(status_code=404, detail="Fine not found")
    return {"fine": fine}