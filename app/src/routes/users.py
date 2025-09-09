from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

from app.mocks.mock_data import mock_patrons
from app.src.schema.users import Patron

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def common_parameters(q: str | None = None, skip: int = 0, limit: int = 100):
    return { "q": q, "skip": skip, "limit": limit }

CommonsDependencies = Annotated[dict, Depends(common_parameters)]
@router.get("/")
async def get_patrons(token: Annotated[str, Depends(oauth2_scheme)], params: CommonsDependencies):
    return {"token": token, "patrons": mock_patrons, **params}

@router.get("/me/")
async def get_my_info(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token, "patron": mock_patrons[0]}  # Just an example, replace with actual user info

@router.get("/{patron_id}")
async def get_patron(patron_id: int, token: Annotated[str, Depends(oauth2_scheme)]):
    if patron_id not in [p["member_id"] for p in mock_patrons]:
        raise HTTPException(status_code=404, detail="Patron not found")
    patron = next((p for p in mock_patrons if p["member_id"] == patron_id), None)
    return {"token": token, "patron": patron}

@router.post("/")
async def create_patron(patron: Patron, token: Annotated[str, Depends(oauth2_scheme)]):
    patron_dict = patron.model_dump()
    message = f"Patron '{patron.name}' with member ID {patron.member_id} created successfully."
    return {"message": message, "patron": patron_dict, "token": token}


@router.post("/{patron_id}/checkout/")
async def checkout_book(patron_id: int, book_ids: list[int], token: Annotated[str, Depends(oauth2_scheme)]):
    return {"patron_id": patron_id, "book_ids": book_ids, "status": "checked out", "token": token}

@router.post("/{patron_id}/return/")
async def return_book(patron_id: int, book_ids: list[int], token: Annotated[str, Depends(oauth2_scheme)]):
    return {"patron_id": patron_id, "book_ids": book_ids, "status": "returned", "token": token}

