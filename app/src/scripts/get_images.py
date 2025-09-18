import asyncio
import json
import requests
from typing import Annotated
from fastapi import Depends
from sqlalchemy import MetaData, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from supabase import Client, create_async_client
from app.core.settings import settings
from app.src.models.items import Item

meta = MetaData()

def googleImageSearch(q: str):
    url = f"https://www.googleapis.com/customsearch/v1?key={settings.image_api_key}&cx={settings.google_cxe}&searchType=image&q={q}"
    result = requests.get(url)
    data = result.json()
    print(json.dumps(data))
async def supabase():
    url: str = settings.supabase_url
    key: str = settings.supabase_key
    supabase: Client = await create_async_client(url, key)
    return supabase

# retrieve all existing catalog items and use their name to search the endpoint for images
async def get_images():
    print(settings.db_url)
    engine = create_async_engine(settings.db_url)
    async with engine.begin() as conn:
        await conn.run_sync(meta.create_all)
        
    async with AsyncSession(engine) as session:
        async with session.begin():
            result = await session.execute(select(Item))
            all_items = result.scalars().all()
            for item in all_items:
                item_name = item.title
                item_author = item.author or item.director or item.artist
                item_type = item.type
                search_term = f"{item_name} {item_author} {item_type}"
                googleImageSearch(search_term)
                
                supabase_client = await supabase()
                
                
        

loop = asyncio.get_event_loop()
loop.run_until_complete(get_images())