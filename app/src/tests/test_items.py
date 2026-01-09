import pytest
from io import BytesIO

# Minimal valid 1x1 pixel PNG image for testing file uploads
# This is a real PNG that passes magic number validation
VALID_PNG_BYTES = bytes([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR chunk
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,  # 1x1 pixel
    0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,  
    0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,  # IDAT chunk
    0x54, 0x08, 0xD7, 0x63, 0xF8, 0xFF, 0xFF, 0x3F,
    0x00, 0x05, 0xFE, 0x02, 0xFE, 0xDC, 0xCC, 0x59,
    0xE7, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,  # IEND chunk
    0x44, 0xAE, 0x42, 0x60, 0x82
] + [0x00] * 50)  # Pad to meet minimum size requirement

def test_authenticated_catalog_requests(authenticated_client):
    """Test GET /catalog/ - get all items"""
    response = authenticated_client.get("/catalog/")
    assert response.status_code == 200
    assert len(response.json()) > 0
    assert isinstance(response.json(), list)

    response = authenticated_client.get("/catalog/?q=catalog_events")
    assert response.status_code == 200


@pytest.mark.parametrize("item_type", ["book", "cd", "dvd", "magazine", "journal"])
def test_catalog_items_endpoint(authenticated_client, item_type):
    """Test GET /catalog/{item}s - get items by type"""
    response = authenticated_client.get(f"/catalog/{item_type}s")
    assert response.status_code == 200
    items = response.json()
    assert isinstance(items, list)

    for item in items:
        assert item["type"] == item_type
        assert "title" in item


def test_catalog_invalid_item_type(authenticated_client):
    """Test GET /catalog/{item}s with invalid type - should return 400"""
    response = authenticated_client.get("/catalog/invalid_types")
    assert response.status_code == 400
    assert "Invalid item type" in response.json()["detail"]


def test_get_single_item(authenticated_client):
    """Test GET /catalog/{item}s/{item_id} - get single item"""
    response = authenticated_client.get("/catalog/books")
    assert response.status_code == 200
    books = response.json()

    if books:
        book_id = books[0]["id"]


        response = authenticated_client.get(f"/catalog/books/{book_id}")
        assert response.status_code == 200
        item = response.json()
        assert item["id"] == book_id
        assert item["type"] == "book"


def test_get_single_item_not_found(authenticated_client):
    """Test GET /catalog/{item}s/{item_id} with invalid ID - should return 404"""
    response = authenticated_client.get("/catalog/books/99999")
    assert response.status_code == 404
    assert "Item not found" in response.json()["detail"]


def test_create_item(authenticated_client):
    """Test POST /catalog/{item}s/ - create new item"""
    new_book = {
        "title": "Test Book",
        "type": "book",
        "author": "Test Author",
        "published_year": 2024,
        "call_number": "TEST123",
        "genre": "Fiction",
        "summary": "A test book"
    }

    response = authenticated_client.post("/catalog/books/", json=new_book)
    assert response.status_code == 200
    created_item = response.json()
    assert created_item["title"] == "Test Book"
    assert created_item["type"] == "book"
    assert created_item["author"] == "Test Author"
    assert "Author" in created_item["call_number"]


def test_create_item_with_single_name_author(authenticated_client):
    """Test POST /catalog/{item}s/ - create item with single-name author (no space)"""
    new_book = {
        "title": "Test Book 2",
        "type": "book",
        "author": "Madonna",
        "published_year": 2024,
        "call_number": "TEST456"
    }

    response = authenticated_client.post("/catalog/books/", json=new_book)
    assert response.status_code == 200
    created_item = response.json()
    assert created_item["call_number"] == "TEST456"


def test_update_item(authenticated_client):
    """Test PUT /catalog/{item}s/{item_id} - update existing item"""
    response = authenticated_client.get("/catalog/books")
    books = response.json()

    if books:
        book_id = books[0]["id"]


        updated_data = {
            "title": "Updated Title",
            "summary": "Updated summary"
        }

        response = authenticated_client.put(f"/catalog/books/{book_id}", json=updated_data)
        assert response.status_code == 200
        updated_item = response.json()
        assert updated_item["title"] == "Updated Title"
        assert updated_item["summary"] == "Updated summary"


def test_update_item_not_found(authenticated_client):
    """Test PUT /catalog/{item}s/{item_id} with invalid ID - should return 404"""
    updated_data = {"title": "Updated Title"}

    response = authenticated_client.put("/catalog/books/99999", json=updated_data)
    assert response.status_code == 404
    assert "Item not found" in response.json()["detail"]


def test_delete_item(authenticated_client):
    """Test DELETE /catalog/{item}s/{item_id} - delete item"""
    new_book = {
        "title": "Book to Delete",
        "type": "book",
        "author": "Delete Author",
        "call_number": "DEL123"
    }

    create_response = authenticated_client.post("/catalog/books/", json=new_book)
    created_item = create_response.json()
    item_id = created_item["id"]

    response = authenticated_client.delete(f"/catalog/books/{item_id}")
    assert response.status_code == 200
    assert response.json()["item_id"] == item_id
    assert response.json()["status"] == "deleted"

    get_response = authenticated_client.get(f"/catalog/books/{item_id}")
    assert get_response.status_code == 404


def test_delete_item_not_found(authenticated_client):
    """Test DELETE /catalog/{item}s/{item_id} with invalid ID - should return 404"""
    response = authenticated_client.delete("/catalog/books/99999")
    assert response.status_code == 404
    assert "Item not found" in response.json()["detail"]


def test_unauthenticated_catalog_requests(unauthenticated_client):
    """Test GET /catalog/ without authentication"""
    response = unauthenticated_client.get("/catalog/")
    assert response.status_code == 200
    assert len(response.json()) > 0
    items = response.json()
    assert "title" in items[0]


def test_unauthenticated_create_item(unauthenticated_client):
    """Test POST /catalog/{item}s/ without authentication - should return 401"""
    new_book = {
        "title": "Test Book",
        "type": "book",
        "author": "Test Author"
    }

    response = unauthenticated_client.post("/catalog/books/", json=new_book)
    assert response.status_code == 401


def test_unauthenticated_update_item(unauthenticated_client):
    """Test PUT /catalog/{item}s/{item_id} without authentication - should return 401"""
    response = unauthenticated_client.put("/catalog/books/1", json={"title": "Updated"})
    assert response.status_code == 401


def test_unauthenticated_delete_item(unauthenticated_client):
    """Test DELETE /catalog/{item}s/{item_id} without authentication - should return 401"""
    response = unauthenticated_client.delete("/catalog/books/1")
    assert response.status_code == 401


def test_upload_image_new_file(authenticated_client, mocker):
    """Test POST /catalog/upload_image/ - upload new image"""
    from app.core.database import get_supabase_client

    mock_storage = mocker.MagicMock()
    mock_bucket = mocker.MagicMock()

    # First download raises exception (file doesn't exist)
    # Second download returns the same content for verification
    mock_bucket.download = mocker.AsyncMock(side_effect=[
        Exception("File not found"),
        VALID_PNG_BYTES  # Return same content for integrity check
    ])

    mock_upload_result = mocker.MagicMock()
    mock_upload_result.error = None
    mock_bucket.upload = mocker.AsyncMock(return_value=mock_upload_result)

    mock_bucket.get_public_url = mocker.AsyncMock(return_value="https://example.com/test_image.png")

    mock_storage.from_ = mocker.MagicMock(return_value=mock_bucket)

    mock_supabase = mocker.AsyncMock()
    mock_supabase.storage = mock_storage

    async def mock_get_supabase():
        return mock_supabase

    from app.main import app
    app.dependency_overrides[get_supabase_client] = mock_get_supabase

    try:

        files = {
            "file": ("test_image.png", BytesIO(VALID_PNG_BYTES), "image/png")
        }

        response = authenticated_client.post("/catalog/upload_image/", files=files)
        assert response.status_code == 200
        assert response.json()["status"] == 200
        assert response.json()["message"] == "Image uploaded successfully"
        assert "url" in response.json()
        assert response.json()["url"] == "https://example.com/test_image.png"
    finally:

        del app.dependency_overrides[get_supabase_client]


def test_upload_image_existing_file(authenticated_client, mocker):
    """Test POST /catalog/upload_image/ - file already exists"""
    from app.core.database import get_supabase_client

    mock_storage = mocker.MagicMock()
    mock_bucket = mocker.MagicMock()

    mock_bucket.download = mocker.AsyncMock(return_value=b"existing file content")

    mock_bucket.get_public_url = mocker.AsyncMock(return_value="https://example.com/existing_image.png")

    mock_storage.from_ = mocker.MagicMock(return_value=mock_bucket)

    mock_supabase = mocker.AsyncMock()
    mock_supabase.storage = mock_storage

    async def mock_get_supabase():
        return mock_supabase

    from app.main import app
    app.dependency_overrides[get_supabase_client] = mock_get_supabase

    try:
        files = {
            "file": ("existing_image.png", BytesIO(VALID_PNG_BYTES), "image/png")
        }

        response = authenticated_client.post("/catalog/upload_image/", files=files)
        assert response.status_code == 200
        assert response.json()["message"] == "File already exists"
        assert response.json()["url"] == "https://example.com/existing_image.png"
    finally:
        del app.dependency_overrides[get_supabase_client]


def test_upload_image_upload_error(authenticated_client, mocker):
    """Test POST /catalog/upload_image/ - upload fails with error"""
    from app.core.database import get_supabase_client

    mock_storage = mocker.MagicMock()
    mock_bucket = mocker.MagicMock()

    mock_bucket.download = mocker.AsyncMock(side_effect=Exception("File not found"))

    mock_upload_result = mocker.MagicMock()
    mock_upload_result.error = "Storage quota exceeded"
    mock_bucket.upload = mocker.AsyncMock(return_value=mock_upload_result)

    mock_storage.from_ = mocker.MagicMock(return_value=mock_bucket)

    mock_supabase = mocker.AsyncMock()
    mock_supabase.storage = mock_storage

    async def mock_get_supabase():
        return mock_supabase

    from app.main import app
    app.dependency_overrides[get_supabase_client] = mock_get_supabase

    try:
        files = {
            "file": ("test_image.png", BytesIO(VALID_PNG_BYTES), "image/png")
        }

        response = authenticated_client.post("/catalog/upload_image/", files=files)
        assert response.status_code == 500
        assert "Storage upload failed" in response.json()["detail"]
    finally:
        del app.dependency_overrides[get_supabase_client]


def test_upload_image_verification_failure(authenticated_client, mocker):
    """Test POST /catalog/upload_image/ - upload succeeds but verification fails"""
    from app.core.database import get_supabase_client

    mock_storage = mocker.MagicMock()
    mock_bucket = mocker.MagicMock()

    download_call_count = [0]

    def mock_download_side_effect(*args, **kwargs):
        download_call_count[0] += 1
        if download_call_count[0] == 1:
            # First call - file doesn't exist (before upload)
            raise Exception("File not found")
        else:
            # Second call - verification fails
            raise Exception("File not found after upload")

    mock_bucket.download = mocker.AsyncMock(side_effect=mock_download_side_effect)

    mock_upload_result = mocker.MagicMock()
    mock_upload_result.error = None
    mock_bucket.upload = mocker.AsyncMock(return_value=mock_upload_result)

    mock_storage.from_ = mocker.MagicMock(return_value=mock_bucket)

    mock_supabase = mocker.AsyncMock()
    mock_supabase.storage = mock_storage

    async def mock_get_supabase():
        return mock_supabase

    from app.main import app
    app.dependency_overrides[get_supabase_client] = mock_get_supabase

    try:
        files = {
            "file": ("test_image.png", BytesIO(VALID_PNG_BYTES), "image/png")
        }

        response = authenticated_client.post("/catalog/upload_image/", files=files)
        assert response.status_code == 500
        assert "Upload verification failed" in response.json()["detail"]
    finally:
        del app.dependency_overrides[get_supabase_client]


def test_upload_image_exception_during_upload(authenticated_client, mocker):
    """Test POST /catalog/upload_image/ - exception thrown during upload"""
    from app.core.database import get_supabase_client

    mock_storage = mocker.MagicMock()
    mock_bucket = mocker.MagicMock()

    mock_bucket.download = mocker.AsyncMock(side_effect=Exception("File not found"))

    mock_bucket.upload = mocker.AsyncMock(side_effect=Exception("Network error"))

    mock_storage.from_ = mocker.MagicMock(return_value=mock_bucket)

    mock_supabase = mocker.AsyncMock()
    mock_supabase.storage = mock_storage

    async def mock_get_supabase():
        return mock_supabase

    from app.main import app
    app.dependency_overrides[get_supabase_client] = mock_get_supabase

    try:
        files = {
            "file": ("test_image.png", BytesIO(VALID_PNG_BYTES), "image/png")
        }

        response = authenticated_client.post("/catalog/upload_image/", files=files)
        assert response.status_code == 500
        assert "Unexpected upload error" in response.json()["detail"]
    finally:
        del app.dependency_overrides[get_supabase_client]
