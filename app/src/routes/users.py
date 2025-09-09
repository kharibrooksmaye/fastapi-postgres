from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException

from app.mocks.mock_data import mock_patrons
from app.src.schema.users import Patron

router = APIRouter()

async def common_parameters(q: str | None = None, skip: int = 0, limit: int = 100):
    return { "q": q, "skip": skip, "limit": limit }

CommonsDependencies = Annotated[dict, Depends(common_parameters)]
@router.get("/patrons/")
async def get_patrons(params: CommonsDependencies):
    return {"patrons": mock_patrons, **params}

@router.get("/patrons/me/")
async def get_my_info():
    return {"patron": mock_patrons[0]}  # Just an example, replace with actual user info

@router.get("/patrons/{patron_id}")
async def get_patron(patron_id: int):
    if patron_id not in [p["member_id"] for p in mock_patrons]:
        raise HTTPException(status_code=404, detail="Patron not found")
    patron = next((p for p in mock_patrons if p["member_id"] == patron_id), None)
    return {"patron": patron}

@router.post("/patrons/")
async def create_patron(patron: Patron):
    patron_dict = patron.model_dump()
    message = f"Patron '{patron.name}' with member ID {patron.member_id} created successfully."
    return {"message": message, "patron": patron_dict}


@router.post("/patrons/{patron_id}/checkout/")
async def checkout_book(patron_id: int, book_ids: list[int]):
    return {"patron_id": patron_id, "book_ids": book_ids, "status": "checked out"}

@router.post("/patrons/{patron_id}/return/")
async def return_book(patron_id: int, book_ids: list[int]):
    return {"patron_id": patron_id, "book_ids": book_ids, "status": "returned"}

