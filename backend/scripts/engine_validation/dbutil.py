"""Ephemeral PostgreSQL schema helpers for engine validation.

Creates/drops only the throwaway database named in TEST_DATABASE_URL.
Never touches the production database.
"""

from __future__ import annotations

import os

TEST_DB_URL = (
    "postgresql+asyncpg://postgres:postgres@localhost:5432/engine_validation_test"
)


async def create_schema() -> None:
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.models import Base  # noqa: F401  (registers all model metadata)

    engine = create_async_engine(TEST_DB_URL, echo=False)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
    finally:
        await engine.dispose()


async def drop_schema() -> None:
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.models import Base  # noqa: F401

    engine = create_async_engine(TEST_DB_URL, echo=False)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    finally:
        await engine.dispose()


def make_session_factory():
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    engine = create_async_engine(TEST_DB_URL, echo=False, pool_pre_ping=True)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return engine, factory


async def schema_available() -> bool:
    """True when the throwaway DB exists and has the configurations table.

    Coroutine so it can be awaited from async fixtures without nested
    event loops.
    """

    async def _probe() -> bool:
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine

        engine = create_async_engine(TEST_DB_URL, echo=False)
        try:
            async with engine.connect() as conn:
                await conn.execute(
                    text(
                        "SELECT 1 FROM information_schema.tables "
                        "WHERE table_name='configurations'"
                    )
                )
                row = await conn.execute(
                    text(
                        "SELECT COUNT(*) FROM information_schema.tables "
                        "WHERE table_name='configurations'"
                    )
                )
                return int(row.scalar() or 0) == 1
        except Exception:
            return False
        finally:
            await engine.dispose()

    return await _probe()


if __name__ == "__main__":
    import asyncio

    raise SystemExit(0 if asyncio.run(schema_available()) else 1)
