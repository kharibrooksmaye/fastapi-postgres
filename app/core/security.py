from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer

from app.src.schema.users import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def fake_decode_token(token: str):
    return User(
        member_id=token + "fakedecoded", name="John Doe", email="john.doe@example.com", type="patron", id=1
    )

async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    return user