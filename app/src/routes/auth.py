from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from app.core.authentication import create_access_token, get_user, verify_password
from app.core.database import SessionDep

router = APIRouter()

@router.post("/token")
async def get_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep):
    user = await get_user(session, form_data.username)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}