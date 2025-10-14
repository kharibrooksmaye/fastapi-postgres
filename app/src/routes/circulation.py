from datetime import datetime, timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select

from app.core.authentication import get_current_user, oauth2_scheme
from app.core.authorization import require_roles
from app.core.database import SessionDep
from app.src.models.circulation import CatalogEvent
from app.src.models.items import Item
from app.src.models.users import User
from app.src.routes.users import CommonsDependencies

router = APIRouter()


@router.get("/")
async def read_root(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
    params: CommonsDependencies,
    admin: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
):
    events_result = await session.exec(
        select(User, CatalogEvent)
        .join(CatalogEvent, User.id == CatalogEvent.user)
        .offset(params["skip"])
        .limit(params["limit"])
    )
    events_with_users = events_result.all()

    enriched_events = []
    all_item_ids = set()
    for user, event in events_with_users:
        all_item_ids.update(event.catalog_ids)
    items_result = await session.exec(
            select(Item).where(Item.id.in_(all_item_ids))
        )
    all_items = {item.id: item for item in items_result.all()}
    
    for user, event in events_with_users:
        items = [all_items[id] for id in event.catalog_ids if id in all_items]
        enriched_events.append({
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "type": user.type
            },
            "event": {
                "id": event.id,
                "action": event.action,
                "event_timestamp": event.event_timestamp,
                "catalog_ids": event.catalog_ids,
                "admin_id": event.admin_id,
                "due_date": event.due_date
            },
            "items": [
                {
                    "id": item.id,
                    "title": item.title,
                    "author": item.author,
                    "type": item.type
                }
                for item in items
            ]
        })

    return enriched_events

@router.post("/{action}/{user_id}")
async def book_action(
    user_id: int,
    book_ids: list[int],
    action: str,
    admin: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    user: Annotated[User, Depends(get_current_user)],
    session: SessionDep,
):
    if user.type not in ["librarian", "admin"] and user.id != user_id:
        print("this is not the right id")
        raise HTTPException(status_code=403, detail="You cannot access other users' library")

    target_user_result = await session.exec(select(User).where(User.id == user_id))
    target_user = target_user_result.first()
    if not target_user:
        raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found")

    due_date = datetime.now() + timedelta(days=15)
    try:
        catalog_event_data = {
            "action": action,
            "event_timestamp": datetime.now(),
            "catalog_ids": book_ids,
            "admin_id": admin.id,
            "user": user_id
        }


        if action in ["checkout", "renew"]:
            catalog_event_data["due_date"] = due_date

        body = CatalogEvent(**catalog_event_data)

        session.add(body)
        await session.commit()
        await session.refresh(body)


        items_result = await session.exec(select(Item).where(Item.id.in_(book_ids)))
        
        items = {item.id: item for item in items_result.all()}
        
        print(items)

        for catalog_id in book_ids:
            item = items.get(catalog_id)
            if item:
                if item.catalog_events is None:
                    item.catalog_events = [body.id]
                else:
                    item.catalog_events.append(body.id)
                if action == "checkout":
                    item.is_checked_out = True
                if action == "return":
                    item.is_checked_out = False
                session.add(item)

        await session.commit()

        action_message = ""
        if action == "checkout":
            action_message = "checked out"
            
        message = {
            "message": f"Books {action_message} successfully",
            "event_id": body.id,
            "user_id": user_id,
            "book_ids": book_ids,
        }
        
        if action in ["checkout", "renew"]:
            message["due_date"] = due_date.strftime("%Y-%m-%d %H:%M:%S")
        return {
            "message": f"Books {action_message} successfully",
            "event_id": body.id,
            "user_id": user_id,
            "book_ids": book_ids,
            "due_date": body.due_date
        }
    except Exception as e:
        await session.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to checkout books: {str(e)}")
