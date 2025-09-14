from typing import Annotated, Union
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select

from app.core.authorization import require_roles
from app.src.models.items import Item
from app.core.database import SessionDep
from app.src.models.users import User

router = APIRouter()


@router.get("/")
async def read_root(session: SessionDep):
    result = await session.exec(select(Item))
    items = result.all()
    return items


@router.get("/{item}s")
async def get_items(item: str, session: SessionDep):
    print(item)
    if item:
        result = await session.exec(select(Item).where(Item.type == item))
        items = result.all()
    return items


@router.get("/{item}s/{item_id}")
async def get_item(
    item: str, item_id: int, session: SessionDep, q: Union[str, None] = None
):
    print(item, item_id)
    db_item = await session.get(Item, item_id)
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    return db_item


@router.post("/{item}s/")
async def create_item(
    item: str,
    body_item: Item,
    admin: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    session: SessionDep,
) -> Item:
    item_dict = body_item.model_dump()
    body_item.type = item
    last_name = body_item.author.split(" ")[1]
    complete_call_number = f"{body_item.call_number} {last_name}"
    item_dict.update({"complete_call_number": complete_call_number})

    session.add(body_item)
    await session.commit()
    await session.refresh(body_item)
    return body_item


@router.put("/{item}s/{item_id}")
async def update_item(
    item: str,
    item_id: int,
    body_item: Item,
    admin: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    session: SessionDep,
):
    db_item = await session.get(Item, item_id)
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    item_dict = body_item.model_dump()
    last_name = body_item.author.split(" ")[1]
    complete_call_number = f"{body_item.call_number} {last_name}"
    item_dict.update({"complete_call_number": complete_call_number})
    for key, value in item_dict.items():
        setattr(db_item, key, value)
    await session.commit()
    await session.refresh(db_item)
    return db_item


@router.delete("/{item}s/{item_id}")
async def delete_item(
    item: str,
    item_id: int,
    admin: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    session: SessionDep,
):
    db_item = await session.get(Item, item_id)
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    await session.delete(db_item)
    await session.commit()
    return {"item_id": item_id, "status": "deleted"}
