# prevent patrons from accessing admin routes
from typing import List, Union
from fastapi import Depends, HTTPException
from starlette.status import HTTP_403_FORBIDDEN

from app.core.authentication import get_current_user
from app.src.schema.users import User


def require_roles(allowed_roles: Union[str, List[str]]):
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    async def check_roles(current_user: User = Depends(get_current_user)):
        if current_user.type not in allowed_roles:
            roles_str = ", ".join(allowed_roles)
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: Requires role(s) {roles_str}",
            )
        return current_user

    return check_roles


def require_minimum_role(minimum_role: str):
    role_hierarchy = {"patron": 1, "librarian": 2, "admin": 3}
    if minimum_role not in role_hierarchy:
        raise ValueError(f"Invalid role: {minimum_role}")
    min_level = role_hierarchy.get(minimum_role, 0)

    async def check_minimum_role(current_user: User = Depends(get_current_user)):
        user_level = role_hierarchy.get(current_user.type, 0)
        if user_level < min_level:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: Requires minimum role of {minimum_role}",
            )
        return current_user

    return check_minimum_role
