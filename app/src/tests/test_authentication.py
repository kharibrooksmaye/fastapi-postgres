from app.main import app
from app.core.database import SessionDep
from app.core.authentication import create_access_token, get_password_hash
from app.src.schema.users import User, UserTypeEnum
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock


def override_create_access_token(data: dict):
    token = create_access_token(data)
    return token