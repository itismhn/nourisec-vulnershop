#!/bin/sh
set -e

if [ ! -f "/app/instance/vulnershop.db" ]; then
    echo "No database found - seeding VulnerShop with fake data..."
    python scripts/reset_db.py
fi

exec python run.py
