import json
from pathlib import Path
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select

import sys

sys.path.append(str(Path(__file__).parent.parent))
from app.core.authentication import get_password_hash
from app.src.models.items import Item
from app.src.models.users import User

item_path = Path(__file__).parent / "mock_items.json"
user_path = Path(__file__).parent / "mock_users.json"

with open(item_path, "r") as f:
    mock_items = json.load(f)

with open(user_path, "r") as f:
    mock_users = json.load(f)


async def seed_database(session: AsyncSession):
    """
    Seed the database with mock books and patrons/users data.
    """

    existing_items = await session.exec(select(Item))
    existing_users = await session.exec(select(User))

    if existing_items.first() is not None:
        print("Items already exist in database, skipping item seeding...")
    else:
    
        for item_data in mock_items:
        
            item_dict = item_data.copy()
            if "id" in item_dict:
                del item_dict["id"]

        
            if "type" not in item_dict:
                item_dict["type"] = "book"

            item = Item(**item_dict)
            session.add(item)

        await session.commit()
        print(f"Successfully seeded {len(mock_items)} items")

    if existing_users.first() is not None:
        print("Users already exist in database, skipping user seeding...")
    else:
    
        for patron_data in mock_users:
        
            user = User(
                type=patron_data.get("type", "patron"),
                name=patron_data["name"],
                email=patron_data["email"],
                member_id=patron_data["member_id"],
                phone_number=patron_data.get("phone_number"),
                address=patron_data.get("address"),
                is_active=patron_data["is_active"],
                username=patron_data["username"],
                password=get_password_hash(patron_data["password"]),
            )
            session.add(user)

        await session.commit()
        print(f"Successfully seeded {len(mock_users)} users")


    
        
    