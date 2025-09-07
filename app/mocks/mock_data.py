import json
from pathlib import Path

# Adjust the path as needed; this assumes mock_books.json is in the same directory as this file
book_path = Path(__file__).parent / "mock_books.json"
patron_path = Path(__file__).parent / "mock_patrons.json"

with open(book_path, "r") as f:
    mock_books = json.load(f)

with open(patron_path, "r") as f:
    mock_patrons = json.load(f)