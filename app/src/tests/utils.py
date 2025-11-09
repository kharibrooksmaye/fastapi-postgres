from unittest.mock import AsyncMock, Mock
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from datetime import datetime, timedelta
from decimal import Decimal

from app.core.authentication import create_access_token
from app.src.models.items import Item
from app.src.models.users import User
from app.src.models.fines import Fines
from app.core.settings import settings
from app.src.schema.users import UserTypeEnum


class TestDatabase:
    def __init__(self, session: Session):
        self.session = session
    
    def populate_test_data(self):
        test_user = User(
            username="testuser",
            name="Test User",
            email="testuser@example.com",
            member_id="1",
            type="admin",
            password="$2b$12$NxBnVDJB/IbsFlbGIYMVOOTGk5WpQNmc.RnV31HTcXKOBr72fkrmO",
            is_active=True
        )
        patron_user = User(
            username="patron",
            name="Patron User",
            email="patron@example.com",
            member_id="2",
            type="patron",
            password="patronpass",
            is_active=True
        )
        librarian_user = User(
            username="librarian",
            name="Librarian User",
            email="librarian@example.com",
            member_id="3",
            type="librarian",
            password="librarianpass",
            is_active=True
        )

        self.session.add_all([test_user, patron_user, librarian_user])
        self.session.commit()

        test_items = [
            Item(title="Test Book", type="book", author="Author A"),
            Item(title="Test Magazine", type="magazine", publisher="Test Publisher"),
            Item(title="Test DVD", type="dvd", director="Director B"),
            Item(title="Test CD", type="cd", artist="Artist C"),
            Item(title="Test Journal", type="journal", publisher="Journal Publisher")
        ]

        self.session.add_all(test_items)
        self.session.commit()

        # Add test fines for different users
        # Fines for testuser (id=1, admin)
        test_fines = [
            Fines(
                user_id=1,
                catalog_item_id=1,
                amount=Decimal("10.50"),
                due_date=datetime.now() + timedelta(days=7),
                issued_date=datetime.now(),
                paid=False,
                days_late=0
            ),
            Fines(
                user_id=1,
                catalog_item_id=2,
                amount=Decimal("5.00"),
                due_date=datetime.now() - timedelta(days=3),
                issued_date=datetime.now() - timedelta(days=10),
                paid=False,
                days_late=3
            ),
            # Fines for patron user (id=2)
            Fines(
                user_id=2,
                catalog_item_id=3,
                amount=Decimal("15.00"),
                due_date=datetime.now() + timedelta(days=5),
                issued_date=datetime.now(),
                paid=False,
                days_late=0
            ),
            Fines(
                user_id=2,
                catalog_item_id=4,
                amount=Decimal("20.00"),
                due_date=datetime.now() - timedelta(days=5),
                issued_date=datetime.now() - timedelta(days=15),
                paid=True,
                days_late=5,
                payment_intent_id="pi_test_123"
            ),
            # Fine for librarian user (id=3)
            Fines(
                user_id=3,
                catalog_item_id=5,
                amount=Decimal("8.00"),
                due_date=datetime.now() + timedelta(days=10),
                issued_date=datetime.now(),
                paid=False,
                days_late=0
            )
        ]

        self.session.add_all(test_fines)
        self.session.commit()

async def override_get_session():
    mock_session = AsyncMock()
    mock_result = Mock()
    test_user = User(
        id=1,
        name="Test User",
        member_id="1",
        username="testuser",
        email="testuser@example.com",
        password="$2b$12$NxBnVDJB/IbsFlbGIYMVOOTGk5WpQNmc.RnV31HTcXKOBr72fkrmO",
        is_active=True,
        type=UserTypeEnum.admin
    )
    mock_result.first.return_value = test_user
    mock_result.all.return_value = [test_user]

    mock_session.exec = AsyncMock(return_value=mock_result)
    mock_session.add = Mock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.delete = AsyncMock()

    yield mock_session

async def override_get_session_for_items():
    mock_session = AsyncMock()
    mock_result = Mock()
    test_user = User(
        id=1,
        name="Test User",
        member_id="1",
        username="testuser",
        email="testuser@example.com",
        password="$2b$12$NxBnVDJB/IbsFlbGIYMVOOTGk5WpQNmc.RnV31HTcXKOBr72fkrmO",
        is_active=True,
        type=UserTypeEnum.admin
    )
    mock_result.first.return_value = test_user
    mock_result.all.return_value = [test_user]

    mock_session.exec = AsyncMock(return_value=mock_result)
    mock_session.add = Mock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.delete = AsyncMock()

    yield mock_session
async def override_get_my_info():
    """Mock function to override get_current_user dependency"""
    hashed_password = "$2b$12$NxBnVDJB/IbsFlbGIYMVOOTGk5WpQNmc.RnV31HTcXKOBr72fkrmO"
    return User(
        id=1,
        name="Test User",
        member_id="1",
        username="testuser",
        email="testuser@example.com",
        password=hashed_password,
        is_active=True,
        type=UserTypeEnum.admin
    )

def override_oauth2_scheme():
    return "testtoken"

def override_create_access_token(data: dict):
    token = create_access_token(data)
    return token

async def override_get_db():
    test_engine = await create_engine(settings.test_db_url)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()