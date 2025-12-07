import hashlib
from pathlib import Path
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


# Security constants for file upload
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit (reduced for security)
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
ALLOWED_MAGIC_NUMBERS = {
    b'\xff\xd8\xff': 'image/jpeg',  # JPEG
    b'\x89PNG\r\n\x1a\n': 'image/png',  # PNG
    b'GIF87a': 'image/gif',  # GIF87a
    b'GIF89a': 'image/gif',  # GIF89a
    b'RIFF': 'image/webp'  # WebP (partial check)
}


def _validate_file_security(file: UploadFile, content: bytes) -> None:
    """Comprehensive file security validation.
    
    Validates file size, MIME type, extension, and content magic numbers
    to prevent malicious file uploads and security vulnerabilities.
    
    Args:
        file: The uploaded file object
        content: File content bytes for magic number validation
        
    Raises:
        HTTPException: If any security validation fails
    """
    # 1. File size validation
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413, 
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB"
        )
    
    # 2. MIME type validation
    if file.content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=415, 
            detail=f"Invalid file type. Allowed: {', '.join(ALLOWED_MIME_TYPES)}"
        )
    
    # 3. File extension validation
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
        
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid file extension. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    
    # 4. Magic number validation (content-based detection)
    magic_validated = False
    for magic_bytes, expected_type in ALLOWED_MAGIC_NUMBERS.items():
        if content.startswith(magic_bytes):
            magic_validated = True
            # Verify MIME type matches magic number
            if expected_type != file.content_type and not (
                expected_type == 'image/gif' and file.content_type == 'image/gif'
            ):
                raise HTTPException(
                    status_code=400, 
                    detail="File content doesn't match declared MIME type"
                )
            break
    
    if not magic_validated:
        raise HTTPException(
            status_code=400, 
            detail="File content validation failed - not a valid image"
        )
    
    # 5. Additional security checks
    if len(content) < 100:  # Suspiciously small image
        raise HTTPException(
            status_code=400, 
            detail="File too small to be a valid image"
        )


def _generate_secure_filename(original_filename: str, content: bytes) -> str:
    """Generate secure filename with hash to prevent conflicts and attacks.
    
    Args:
        original_filename: Original uploaded filename
        content: File content for hash generation
        
    Returns:
        Secure filename with hash prefix
    """
    # Create content hash for uniqueness and integrity
    content_hash = hashlib.sha256(content).hexdigest()[:16]
    
    # Sanitize original filename
    safe_name = Path(original_filename).name
    # Remove any dangerous characters
    safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._-")
    
    # Combine hash with sanitized name
    return f"{content_hash}_{safe_name}"


@router.post("/upload_image/")
@limiter.limit("10 per hour")
async def upload_image(request: Request, file: UploadFile, supabase: SupabaseAsyncClientDep):
    """Secure image upload with comprehensive validation.
    
    Security features:
    - File size limits (5MB)
    - MIME type validation
    - File extension validation  
    - Magic number content validation
    - Secure filename generation
    - Content integrity checking
    """
    supabase_storage = supabase.storage
    
    # Read file content once for all validations
    file_content = await file.read()
    
    # Comprehensive security validation
    _validate_file_security(file, file_content)
    
    # Generate secure filename
    secure_filename = _generate_secure_filename(file.filename, file_content)
    
    # Check if file already exists (using secure filename)
    try:
        existing_file = await supabase_storage.from_("maktaba_catalog_images").download(
            secure_filename
        )
        if existing_file:
            public_url = await supabase_storage.from_(
                "maktaba_catalog_images"
            ).get_public_url(secure_filename)
            return {
                "status": 200, 
                "message": "File already exists", 
                "url": public_url,
                "filename": secure_filename
            }
    except Exception:
        # File doesn't exist, continue with upload
        pass

    try:
        # Upload with secure filename
        result = await supabase_storage.from_("maktaba_catalog_images").upload(
            path=secure_filename, file=file_content
        )
        
        if hasattr(result, "error") and result.error:
            raise HTTPException(
                status_code=500, 
                detail=f"Storage upload failed: {result.error}"
            )
        
        # Verify upload integrity
        try:
            downloaded = await supabase_storage.from_("maktaba_catalog_images").download(secure_filename)
            if not downloaded or len(downloaded) != len(file_content):
                raise HTTPException(
                    status_code=500, 
                    detail="Upload integrity check failed"
                )
        except Exception as verify_error:
            raise HTTPException(
                status_code=500, 
                detail=f"Upload verification failed: {str(verify_error)}"
            )
        
        # Generate public URL
        public_url = await supabase_storage.from_(
            "maktaba_catalog_images"
        ).get_public_url(secure_filename)
        
        return {
            "status": 200,
            "message": "Image uploaded successfully",
            "url": public_url,
            "filename": secure_filename,
            "original_filename": file.filename,
            "size": len(file_content),
            "content_type": file.content_type
        }

    except HTTPException:
        # Re-raise HTTP exceptions (validation errors)
        raise
    except Exception as e:
        # Log unexpected errors for monitoring
        raise HTTPException(
            status_code=500, 
            detail=f"Unexpected upload error: {str(e)}"
        )


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
