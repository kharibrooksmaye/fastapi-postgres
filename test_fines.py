"""
Manual test script to check overdue items and generate fines immediately.
Run this from the project root: python test_fines.py
"""
import asyncio
from app.src.jobs.fines_scheduler import check_overdue_items

if __name__ == "__main__":
    print("Running overdue items check manually...")
    asyncio.run(check_overdue_items())
    print("Done!")
