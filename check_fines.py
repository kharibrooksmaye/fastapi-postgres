"""Check fines in the database"""
import asyncio
from app.core.database import async_session_maker
from sqlmodel import select
from app.src.models.fines import Fines

async def count_fines():
    async with async_session_maker() as session:
        result = await session.exec(select(Fines))
        fines = result.all()
        print(f'Total fines in database: {len(fines)}')
        if fines:
            print('\nFirst 10 fines:')
            for fine in fines[:10]:
                print(f'  Fine ID {fine.id}: User {fine.user_id}, Item {fine.catalog_item_id}, '
                      f'Amount ${fine.amount}, Days Late: {fine.days_late}, Paid: {fine.paid}')

asyncio.run(count_fines())
