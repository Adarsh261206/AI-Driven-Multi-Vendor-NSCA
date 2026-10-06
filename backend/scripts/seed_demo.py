"""Seed a demo admin user for local judging / evaluation.

Idempotent: safe to run multiple times — existing users are left alone.

Usage (from backend/):
    python scripts/seed_demo.py

Env overrides (all optional):
    SEED_ADMIN_EMAIL     default admin@configshield.local
    SEED_ADMIN_PASSWORD  default Admin12345 (min 8 chars)
    SEED_ADMIN_NAME      default Demo Admin

After seeding, open http://localhost:3000 and sign in, then upload a
file from demo-configs/ (e.g. cisco-good.cfg) to run your first audit.
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # noqa: E402

from sqlalchemy import select  # noqa: E402

from app.database import AsyncSessionLocal  # noqa: E402
from app.models import User, UserRole  # noqa: E402
from app.security.auth import hash_password  # noqa: E402


async def main() -> int:
    email = os.environ.get("SEED_ADMIN_EMAIL", "admin@configshield.local")
    password = os.environ.get("SEED_ADMIN_PASSWORD", "Admin12345")
    name = os.environ.get("SEED_ADMIN_NAME", "Demo Admin")

    if len(password) < 8:
        print("SEED_ADMIN_PASSWORD must be at least 8 characters.")
        return 1

    async with AsyncSessionLocal() as session:
        existing = (
            await session.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        if existing is not None:
            print(f"Admin already exists: {email} (nothing to do)")
            return 0

        user = User(
            email=email,
            password_hash=hash_password(password),
            full_name=name,
            role=UserRole.ADMIN.value,
            is_active=True,
        )
        session.add(user)
        await session.commit()

    print(f"Seeded admin: {email}")
    print("Next: open http://localhost:3000, sign in, upload demo-configs/cisco-good.cfg")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
