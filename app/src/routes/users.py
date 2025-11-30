from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select

from app.core.authentication import get_current_user, get_password_hash, oauth2_scheme
from app.core.authorization import require_roles
from app.core.database import SessionDep
from app.src.models.users import User
from app.src.schema.users import AdminRoleList, UserUpdate, UserProfileUpdate

router = APIRouter()


async def common_parameters(q: str | None = None, skip: int = 0, limit: int = 100):
    return {"q": q, "skip": skip, "limit": limit}


CommonsDependencies = Annotated[dict, Depends(common_parameters)]


@router.get("/")
async def get_users(
    token: Annotated[str, Depends(oauth2_scheme)],
    admin: Annotated[User, Depends(require_roles(AdminRoleList))],
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


@router.get("/me/status")
async def get_my_status(
    current_user: Annotated[User, Depends(get_current_user)],
    session: SessionDep
):
    """
    Get current user status - requires valid authentication.
    This prevents user enumeration attacks.
    """
    
    response = {
        "status": "active" if current_user.is_active else "inactive",
        "user": {
            "id": current_user.id,
            "name": current_user.name,
            "email": current_user.email,
            "username": current_user.username,
            "type": current_user.type,
            "is_active": current_user.is_active
        }
    }
    
    # Only add action guidance if user is inactive
    if not current_user.is_active:
        response["message"] = "Account requires activation"
        response["action_required"] = "activation_required"
    else:
        response["message"] = "Account is active"
    
    return response


@router.get("/{user_id}")
async def get_user(
    user_id: int,
    token: Annotated[str, Depends(oauth2_scheme)],
    staff: Annotated[User, Depends(require_roles(AdminRoleList))],
    session: SessionDep,
):
    user = await session.get(User, user_id)
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
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await session.delete(user)
    await session.commit()
    return {
        "message": f"User '{user.name}' (ID {user_id}) deleted successfully.",
        "token": token,
    }


@router.put("/me/")
async def update_my_profile(
    user_data: UserProfileUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: SessionDep,
):
    """Update current user's own profile"""
    # Update user fields with provided data, excluding unset fields
    user_dict = user_data.model_dump(exclude_unset=True)
    
    # Hash password if provided
    if "password" in user_dict and user_dict["password"]:
        user_dict["password"] = get_password_hash(user_dict["password"])
    
    for field, value in user_dict.items():
        if hasattr(current_user, field):
            setattr(current_user, field, value)
    
    # Update the updated_at timestamp
    from datetime import datetime, timezone
    current_user.updated_at = datetime.now(timezone.utc)
    
    await session.commit()
    await session.refresh(current_user)
    
    return {"message": "Profile updated successfully", "user": current_user}


@router.put("/{user_id}")
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    admin: Annotated[User, Depends(require_roles(AdminRoleList))],
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
):
    """Admin-only endpoint to update any user"""
    # Find user by database id
    existing_user = await session.get(User, user_id)
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update user fields with provided data, excluding unset fields
    user_dict = user_data.model_dump(exclude_unset=True)
    
    # Hash password if provided
    if "password" in user_dict and user_dict["password"]:
        user_dict["password"] = get_password_hash(user_dict["password"])
    
    for field, value in user_dict.items():
        if hasattr(existing_user, field):
            setattr(existing_user, field, value)
    
    # Update the updated_at timestamp
    from datetime import datetime, timezone
    existing_user.updated_at = datetime.now(timezone.utc)
    
    await session.commit()
    await session.refresh(existing_user)
    
    message = f"User '{existing_user.name}' (ID {user_id}) updated successfully."
    return {"message": message, "user": existing_user, "token": token}


@router.post("/")
async def create_user(
    user: User,
    admin: Annotated[User, Depends(require_roles(AdminRoleList))],
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
