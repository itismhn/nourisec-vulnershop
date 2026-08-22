"""Wipe and reseed the VulnerShop database to its clean, original state.

Run with `python scripts/reset_db.py`. This is the standalone equivalent of
the "Reset Database" button in the admin panel (app/admin.py: /admin/reset).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.db import init_db
from scripts.seed import seed

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        init_db()
        seed()
    print("Database reset complete.")
