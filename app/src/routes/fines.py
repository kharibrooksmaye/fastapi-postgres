from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete
from sqlalchemy.orm import selectinload
from sqlmodel import select

from app.core.authentication import get_current_user, oauth2_scheme
from app.core.authorization import require_roles
from app.core.database import SessionDep
from app.src.models.fines import Fines
from app.src.models.items import Item
from app.src.models.users import User
from app.src.routes.users import CommonsDependencies
from app.src.schema.fines import FineWithItem


router = APIRouter()

@router.get("/", response_model=dict)
async def read_fines(
    token: Annotated[str, Depends(oauth2_scheme)],
    admin: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    params: CommonsDependencies,
    session: SessionDep,
):
    if not admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await session.exec(
        select(Fines)
        .options(selectinload(Fines.catalog_item))
        .options(selectinload(Fines.user))
        .offset(params["skip"])
        .limit(params["limit"])
    )
    fines = result.all()

    # Convert to response model to include relationships
    fines_with_items = [FineWithItem.model_validate(fine) for fine in fines]

    return {"fines": fines_with_items, **params}

@router.get("/me", response_model=dict)
async def get_my_fines(
    current_user: Annotated[User, Depends(get_current_user)],
    session: SessionDep,
):
    result = await session.exec(
        select(Fines)
        .options(selectinload(Fines.catalog_item))
        .where(Fines.user_id == current_user.id)
    )
    fines = result.all()

    # Convert to response model to include relationships
    fines_with_items = [FineWithItem.model_validate(fine) for fine in fines]

    return {"fines": fines_with_items}

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

@router.get("/fine/{fine_id}", response_model=dict)  # Changed path to avoid conflict with /{user_id}
async def get_fine(
    fine_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    staff: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    session: SessionDep,
):
    result = await session.exec(
        select(Fines)
        .options(selectinload(Fines.catalog_item))
        .where(Fines.id == fine_id)
    )
    fine = result.one_or_none()

    # Check if fine exists FIRST
    if not fine:
        raise HTTPException(status_code=404, detail="Fine not found")

    # Then check authorization
    if not staff and current_user.id != fine.user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Convert to response model to include relationships
    fine_with_item = FineWithItem.model_validate(fine)

    return {"fine": fine_with_item}

@router.delete("/{fine_id}")
async def delete_fine(
    fine_id: int,
    admin: Annotated[User, Depends(require_roles("admin"))],
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
):
    result = await session.exec(select(Fines).where(Fines.id == fine_id))
    fine = result.one_or_none()
    if not admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    if not fine:
        raise HTTPException(status_code=404, detail="Fine not found")
    await session.delete(fine)
    await session.commit()
    return {"detail": "Fine deleted successfully"}

@router.delete("/")
async def delete_all_fines(
    admin: Annotated[User, Depends(require_roles("admin"))],
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
):
    if not admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    await session.exec(delete(Fines))
    await session.commit()
    return {"detail": "All fines deleted successfully"}