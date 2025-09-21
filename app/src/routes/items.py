from typing import Annotated, Union
from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlmodel import select

from app.core.settings import settings
from app.core.authorization import require_roles
from app.src.models.items import Item
from app.core.database import SessionDep, SupabaseAsyncClientDep
from app.src.models.users import User
from app.src.routes.users import CommonsDependencies

router = APIRouter()

@router.get("/")
async def read_root(session: SessionDep, params: CommonsDependencies):
    query = params["q"]
    print(query)

    if query == "catalog_events":
        item_field = getattr(Item, query)
        result = await session.exec(select(Item).where(item_field.is_not(None)))
    else:
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

@router.post("/upload_image/")
async def upload_image(file: UploadFile, supabase: SupabaseAsyncClientDep):
    supabase_storage = supabase.storage
    file_name = file.filename

    # Check if file already exists
    try:
        existing_file = await supabase_storage.from_("maktaba_catalog_images").download(file_name)
        if existing_file:
            # File exists, return the public URL
            public_url = await supabase_storage.from_("maktaba_catalog_images").get_public_url(file_name)
            return {"status": 200, "message": "File already exists", "url": public_url}
    except Exception:
        # File doesn't exist, proceed with upload
        pass

    # Upload new file
    file_content = await file.read()

    try:
        result = await supabase_storage.from_("maktaba_catalog_images").upload(path=file_name, file=file_content)

        # Verify upload was successful
        if hasattr(result, 'error') and result.error:
            raise HTTPException(status_code=500, detail=f"Upload failed: {result.error}")

        # Verify file exists after upload
        try:
            await supabase_storage.from_("maktaba_catalog_images").download(file_name)
        except Exception:
            raise HTTPException(status_code=500, detail="Upload appeared successful but file not found")

        # Return the public URL for the uploaded file
        public_url = await supabase_storage.from_("maktaba_catalog_images").get_public_url(file_name)
        return {"status": 200, "message": "Image uploaded successfully", "url": public_url, "data": result}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image upload failed: {str(e)}")

@router.post("/{item}s/")
async def create_item(
    item: str,
    body_item: Item,
    admin: Annotated[User, Depends(require_roles(["librarian", "admin"]))],
    session: SessionDep,
) -> Item:
    body_item.type = item
    key_name = body_item.author or body_item.director or body_item.artist
    if key_name and " " in key_name:
        last_name = key_name.split(" ")[1]
        complete_call_number = f"{body_item.call_number} {last_name}"
        body_item.call_number = complete_call_number

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

    # Update fields directly on the db_item
    for key, value in body_item.model_dump(exclude_unset=True).items():
        if hasattr(db_item, key):
            setattr(db_item, key, value)

    # Handle call number update
    key_name = body_item.author or body_item.director or body_item.artist
    if key_name and " " in key_name:
        last_name = key_name.split(" ")[1]
        complete_call_number = f"{body_item.call_number} {last_name}"
        db_item.call_number = complete_call_number

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
