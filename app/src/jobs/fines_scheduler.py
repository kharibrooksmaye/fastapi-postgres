import os
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlmodel import select
from app.core.database import async_session_maker

from app.src.models.circulation import CatalogEvent
from app.src.models.fines import Fines
from app.src.models.users import User  # Import User model for foreign key metadata
from app.src.models.items import Item  # Import Item model for foreign key metadata

scheduler = AsyncIOScheduler()


async def check_overdue_items():
    print("Checking for overdue items...")
    try:
        async with async_session_maker() as session:
            statement = select(CatalogEvent).where(
                CatalogEvent.action == "checkout",
                CatalogEvent.due_date < datetime.now(),
            )
            overdue_checkouts = await session.exec(statement)
            checkout_results = overdue_checkouts.all()
            
            fines_updated = 0
            fines_created = 0
            for checkout in checkout_results:
                for item_id in checkout.catalog_ids:
                    print(
                        f"Item {item_id} checked out by User {checkout.user} is overdue!"
                    )
                    result = await session.exec(
                        select(Fines).where(
                            Fines.user_id == checkout.user,
                            Fines.catalog_item_id == item_id,
                            Fines.paid == False,
                        )
                    )
                    existing_fine = result.first()

                    if existing_fine:
                        existing_fine.amount += 3.00
                        fines_updated += 1
                    else:
                        difference = (
                            datetime.now().date() - checkout.due_date.date()
                        ).days
                        new_fine = Fines(
                            user_id=checkout.user,
                            amount=3.00 * difference,
                            catalog_item_id=item_id,
                            due_date=checkout.due_date,
                            issued_date=datetime.now(),
                            days_late=difference,
                            paid=False,
                        )
                        fines_created += 1
                        session.add(new_fine)
            await session.commit()
            print(f"Fines updated: {fines_updated}, Fines created: {fines_created}")
    except Exception as e:
        print(f"Error checking overdue items: {e}")



def start_scheduler():
    if os.getenv("ENV") == "development":
        # Testing: every 5 minutes
        scheduler.add_job(
            func=check_overdue_items, trigger="interval", minutes=5, id="overdue_check"
        )
    else:
        # Production: daily at noon
        scheduler.add_job(
            func=check_overdue_items,
            trigger="cron",
            hour=12,
            minute=0,
            id="overdue_check",
        )
    scheduler.start()


def stop_scheduler():
    scheduler.shutdown()
