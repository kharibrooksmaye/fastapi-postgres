import json
from pathlib import Path
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select

# Import models
import sys
sys.path.append(str(Path(__file__).parent.parent))
from src.models.items import Item
from src.models.users import User

# Adjust the path as needed; this assumes mock_books.json is in the same directory as this file
item_path = Path(__file__).parent / "mock_items.json"
patron_path = Path(__file__).parent / "mock_patrons.json"

with open(item_path, "r") as f:
    mock_items = json.load(f)

with open(patron_path, "r") as f:
    mock_patrons = json.load(f)

async def seed_database(session: AsyncSession):
    """
    Seed the database with mock books and patrons/users data.
    """
    # Check if data already exists to avoid duplicates
    existing_items = await session.exec(select(Item))
    existing_users = await session.exec(select(User))

    if existing_items.first() is not None:
        print("Items already exist in database, skipping item seeding...")
    else:
        # Seed items
        for item_data in mock_items:
            # Remove id to let the database auto-generate it
            item_dict = item_data.copy()
            if 'id' in item_dict:
                del item_dict['id']

            # Add the type field if it's missing
            if 'type' not in item_dict:
                item_dict['type'] = 'book'

            item = Item(**item_dict)
            session.add(item)

        await session.commit()
        print(f"Successfully seeded {len(mock_items)} items")

    if existing_users.first() is not None:
        print("Users already exist in database, skipping user seeding...")
    else:
        # Seed users (patrons)
        for patron_data in mock_patrons:
            # Create user from patron data
            user = User(
                type=patron_data.get("type", "patron"),
                name=patron_data["name"],
                email=patron_data["email"], 
                member_id=patron_data["member_id"],
                phone_number=patron_data.get("phone_number"),
                address=patron_data.get("address"),
                is_active=patron_data["is_active"]
            )
            session.add(user)
        
        await session.commit()
        print(f"Successfully seeded {len(mock_patrons)} users")