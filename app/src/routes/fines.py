from datetime import datetime
from pydoc import cli
from re import A
from typing import Annotated, List
from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import delete
from sqlalchemy.orm import selectinload
from sqlmodel import select

from app.core.authentication import get_current_user, oauth2_scheme
from app.core.authorization import require_roles
from app.core.database import SessionDep
from app.core.payments import create_stripe_payment_intent
from app.src.models.fines import Fines
from app.src.models.items import Item
from app.src.models.users import User
from app.src.routes.users import CommonsDependencies
from app.src.schema.fines import FineWithItem
from app.src.schema.users import AdminRoleList


router = APIRouter()


@router.get("/", response_model=dict)
async def read_fines(
    token: Annotated[str, Depends(oauth2_scheme)],
    admin: Annotated[User, Depends(require_roles(AdminRoleList))],
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
        .options(selectinload(Fines.user))  # Eager load user to avoid lazy loading
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
    staff: Annotated[User, Depends(require_roles(AdminRoleList))],
    session: SessionDep,
):
    result = await session.exec(select(Fines).where(Fines.user_id == user_id))
    fines = result.all()
    return {"fines": fines}


@router.get(
    "/fine/{fine_id}", response_model=dict
)  # Changed path to avoid conflict with /{user_id}
async def get_fine(
    fine_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    session: SessionDep,
):
    result = await session.exec(
        select(Fines)
        .options(selectinload(Fines.catalog_item))
        .options(selectinload(Fines.user))  # Eager load user to avoid lazy loading
        .where(Fines.id == fine_id)
    )
    fine = result.one_or_none()

    # Check if fine exists FIRST
    if not fine:
        raise HTTPException(status_code=404, detail="Fine not found")

    # Then check authorization
    # Allow if user is staff (admin/librarian) OR if user owns the fine
    is_staff = current_user.type in AdminRoleList
    if not is_staff and current_user.id != fine.user_id:
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


@router.post("/pay/{fine_id}")
async def pay_fine(
    fine_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    admin: Annotated[User, Depends(require_roles(AdminRoleList))],
    session: SessionDep,
):
    result = await session.exec(
        select(Fines)
        .options(selectinload(Fines.catalog_item))  # Eager load to access title
        .where(Fines.id == fine_id)
    )
    fine = result.one_or_none()
    if not fine:
        raise HTTPException(status_code=404, detail="Fine not found")
    if fine.user_id != current_user.id and not admin:
        raise HTTPException(status_code=403, detail="Not authorized to pay this fine")
    if fine.paid:
        raise HTTPException(status_code=400, detail="Fine is already paid")

    metadata = {
        "fine_id": str(fine.id),
        "user_id": str(fine.user_id),
        "amount": str(fine.amount),
        "catalog_item": fine.catalog_item.title,
        "issued_date": fine.issued_date.strftime("%Y-%m-%d"),
        "due_date": fine.due_date.strftime("%Y-%m-%d"),
        "days_late": str(fine.days_late),
        "paid_on": datetime.now().strftime("%Y-%m-%d"),
    }
    intent = create_stripe_payment_intent(
        amount=int(fine.amount),  # Convert to cents
        currency="usd",
        user_id=fine.user_id,
        metadata=metadata,
    )
    intent.id
    await session.commit()
    await session.refresh(fine)
    return {
        "fine": fine,
        "payment_intent": intent.id,
        "client_secret": intent.client_secret,
        "total_amount": fine.amount,
    }

@router.post("/pay_multiple/")
async def pay_multiple_fines(
    fine_ids: Annotated[List[int], Body(embed=True)],
    current_user: Annotated[User, Depends(get_current_user)],
    admin: Annotated[User, Depends(require_roles(AdminRoleList))],
    session: SessionDep,
):
    print(fine_ids)
    result = await session.exec(
        select(Fines)
        .options(selectinload(Fines.catalog_item))  # Eager load to access title
        .where(Fines.id.in_(fine_ids))
    )
    fines = result.all()
    if not fines:
        raise HTTPException(status_code=404, detail="No fines found")
    
    total_amount = 0
    metadata = {}
    for fine in fines:
        if fine.user_id != current_user.id and not admin:
            raise HTTPException(status_code=403, detail="Not authorized to pay some of these fines")
        if fine.paid:
            raise HTTPException(status_code=400, detail=f"Fine with ID {fine.id} is already paid")
        total_amount += int(fine.amount)  # Convert to cents
        metadata[f"fine_{fine.id}"] = fine.catalog_item.title

    intent = create_stripe_payment_intent(
        amount=total_amount,
        currency="usd",
        user_id=current_user.id,
        metadata=metadata,
    )
    intent.id
    await session.commit()
    return {
        "fines": fines,
        "payment_intent": intent.id,
        "client_secret": intent.client_secret,
        "total_amount": total_amount,
    }
    
@router.put("/finalize_payment/")
async def update_fines(
    fines: Annotated[List[int], Body(embed=True)],
    payment_intent_id: Annotated[str, Body(embed=True)],
    admin: Annotated[User, Depends(require_roles(AdminRoleList))],
    session: SessionDep,
):
    if not admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    for fine_id in fines:
        result = await session.exec(select(Fines).where(Fines.id == fine_id))
        fine = result.one_or_none()
        if not fine:
            continue  # Skip if fine not found
        fine.paid = True
        fine.payment_intent_id = payment_intent_id

    await session.commit()
    return {"detail": "Fines updated successfully"}