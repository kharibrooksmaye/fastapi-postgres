from typing import Annotated
from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import or_, select
from app.core.authentication import (
    create_access_token,
    get_password_hash,
    get_user,
    verify_password,
)
from app.core.database import SessionDep
from app.src.models.users import User
from app.src.schema.users import ActivateUserRequest

router = APIRouter()


@router.post("/login")
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep
):
    user = await get_user(session, form_data.username)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer", "user": user}


@router.post("/token")
async def get_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep
):
    user = await get_user(session, form_data.username)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/register", response_model=User)
async def register_user(user: User, session: SessionDep):
    if not user or not user.username or not user.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password are required",
        )
    existing_user = await get_user(session, user.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    try:
        user.password = get_password_hash(user.password)
        session.add(user)
        await session.commit()
        return user
    except Exception as e:
        print(f"Error registering user: {e}")
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register user",
        )


@router.post("/activate/lookup")
async def activate_user_lookup(
    data: Annotated[ActivateUserRequest, Form()], session: SessionDep
):
    email = data.email
    username = data.username
    phone_number = data.phone_number
    result = await session.exec(
        select(User).where(
            or_(
                User.email == email,
                User.username == username,
                User.phone_number == phone_number,
            )
        )
    )
    user = result.first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found with provided email and phone number",
        )
    if user.username or user.password:
        return {
            "status_code": status.HTTP_206_PARTIAL_CONTENT,
            "detail": "User has already been activated, please log in",
        }
    user.is_active = True
    session.add(user)
    await session.commit()
    return {"message": f"User '{user.username}' activated successfully."}
