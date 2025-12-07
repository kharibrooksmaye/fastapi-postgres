from typing import Annotated, Union
from fastapi import APIRouter, Depends, HTTPException, UploadFile, Request
from sqlmodel import select

from app.core.authorization import require_roles
from app.core.rate_limit import limiter
from app.src.models.items import Item
from app.core.database import SessionDep, SupabaseAsyncClientDep
from app.src.models.users import User
from app.src.routes.users import CommonsDependencies
from app.src.schema.users import AdminRoleList

router = APIRouter()


def _build_item_query(filter_type: str) -> any:
    """
    Build secure SQLModel queries for item filtering.
    
    This function prevents SQL injection by using predefined, 
    static column references instead of dynamic attribute access.
    
    Args:
        filter_type: The type of filter to apply
        
    Returns:
        SQLModel query object
        
    Raises:
        ValueError: If filter_type is not supported
    """
    query_map = {
        "catalog_events": select(Item).where(Item.catalog_events.is_not(None)),
        "title": select(Item).where(Item.title.is_not(None)),
        "author": select(Item).where(Item.author.is_not(None)),
        "type": select(Item).where(Item.type.is_not(None))
    }
    
    if filter_type not in query_map:
        raise ValueError(f"Unsupported filter type: {filter_type}")
    
    return query_map[filter_type]


@router.get("/")
async def read_root(session: SessionDep, params: CommonsDependencies):
    """
    Retrieve catalog items with optional filtering.
    
    Supports secure filtering by predefined fields to prevent SQL injection.
    All queries use static column references for maximum security.
    
    Args:
        session: Database session dependency
        params: Common query parameters including optional 'q' filter
        
    Returns:
        List of catalog items matching the filter criteria
        
    Raises:
        HTTPException: 400 if invalid filter parameter provided
    """
    query_filter = params["q"]
    
    try:
        if query_filter:
            # Use secure query builder
            query = _build_item_query(query_filter)
            result = await session.exec(query)
        else:
            # Return all items when no filter specified
            result = await session.exec(select(Item))
            
        items = result.all()
        return items
        
    except ValueError as e:
        # Convert internal error to user-friendly HTTP error
        allowed_filters = ["catalog_events", "title", "author", "type"]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid query parameter '{query_filter}'. Allowed values: {', '.join(allowed_filters)}"
        )


@router.get("/{item}s")
async def get_items(item: str, session: SessionDep):
    types = ["book", "cd", "dvd", "magazine", "newspaper", "journal"]
    if item in types:
        result = await session.exec(select(Item).where(Item.type == item))
    else:
        raise HTTPException(status_code=400, detail="Invalid item type")
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
@limiter.limit("10 per hour")
async def upload_image(request: Request, file: UploadFile, supabase: SupabaseAsyncClientDep):
    supabase_storage = supabase.storage
    file_name = file.filename

    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
    ALLOWED_TYPES = {"image/jpeg", "image/png", "image/gif"}
    
    if file.size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large")
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=415, detail="Invalid file type")
    try:
        existing_file = await supabase_storage.from_("maktaba_catalog_images").download(
            file_name
        )
        if existing_file:
            public_url = await supabase_storage.from_(
                "maktaba_catalog_images"
            ).get_public_url(file_name)
            return {"status": 200, "message": "File already exists", "url": public_url}
    except Exception:
        pass

    file_content = await file.read()

    try:
        result = await supabase_storage.from_("maktaba_catalog_images").upload(
            path=file_name, file=file_content
        )
        if hasattr(result, "error") and result.error:
            raise HTTPException(
                status_code=500, detail=f"Upload failed: {result.error}"
            )
        try:
            await supabase_storage.from_("maktaba_catalog_images").download(file_name)
        except Exception:
            raise HTTPException(
                status_code=500, detail="Upload appeared successful but file not found"
            )
        public_url = await supabase_storage.from_(
            "maktaba_catalog_images"
        ).get_public_url(file_name)
        return {
            "status": 200,
            "message": "Image uploaded successfully",
            "url": public_url,
            "data": result,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image upload failed: {str(e)}")


@router.post("/{item}s/")
@limiter.limit("30 per minute")
async def create_item(
    request: Request,
    item: str,
    body_item: Item,
    admin: Annotated[User, Depends(require_roles(AdminRoleList))],
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
@limiter.limit("60 per minute")
async def update_item(
    request: Request,
    item: str,
    item_id: int,
    body_item: Item,
    admin: Annotated[User, Depends(require_roles(AdminRoleList))],
    session: SessionDep,
):
    db_item = await session.get(Item, item_id)
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")

    for key, value in body_item.model_dump(exclude_unset=True).items():
        if hasattr(db_item, key):
            setattr(db_item, key, value)

    key_name = body_item.author or body_item.director or body_item.artist
    if key_name and " " in key_name:
        last_name = key_name.split(" ")[1]
        complete_call_number = f"{body_item.call_number} {last_name}"
        db_item.call_number = complete_call_number

    await session.commit()
    await session.refresh(db_item)
    return db_item


@router.delete("/{item}s/{item_id}")
@limiter.limit("20 per minute")
async def delete_item(
    request: Request,
    item: str,
    item_id: int,
    admin: Annotated[User, Depends(require_roles(AdminRoleList))],
    session: SessionDep,
):
    db_item = await session.get(Item, item_id)
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    await session.delete(db_item)
    await session.commit()
    return {"item_id": item_id, "status": "deleted"}
