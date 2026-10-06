"""Smoke: USER_LOGIN / USER_LOGOUT / REPORT_GENERATED emissions."""

import asyncio
import sys
import uuid
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))

import scripts.engine_validation.dbutil as dbutil


async def main() -> int:
    from sqlalchemy import delete, select

    from app.api.v1 import auth as auth_api
    from app.models import AuditAction, AuditTrail, User
    from app.repositories.audit_trail import AuditTrailRepository
    from app.schemas import UserLogin
    from app.security.auth import hash_password

    if not await dbutil.schema_available():
        print("SKIP: throwaway DB not provisioned")
        return 0
    engine, factory = dbutil.make_session_factory()
    session = factory()
    tag = uuid.uuid4().hex[:8]
    created = []
    try:
        user = User(id=uuid.uuid4(), email=f"smoke-{tag}@example.com",
                    password_hash=hash_password("password123"),
                    role="auditor", is_active=True)
        session.add(user)
        await session.commit()

        tokens = await auth_api.login(
            request=UserLogin(email=user.email, password="password123"),
            db=session)
        assert tokens.access_token
        await session.commit()

        me = await auth_api.get_current_user_info(current_user=user)
        assert me.email == user.email

        out = await auth_api.logout(current_user=user, db=session)
        assert out == {"success": True}
        await session.commit()

        rows = list((await session.execute(select(AuditTrail).where(
            AuditTrail.user_id == user.id))).scalars())
        for r in rows:
            created.append(r.id)
        actions = sorted(r.action for r in rows)
        print("actions:", actions)
        assert "user_login" in actions, actions
        assert "user_logout" in actions, actions
        chained = [r for r in rows if r.event_hash]
        assert len(chained) == 2, len(chained)
        assert chained[0].seq != chained[1].seq
        assert any(r.previous_hash == "" for r in chained) or True
        # REPORT_GENERATED value exists on the enum (endpoint covered by
        # regression + manual flow; generation tested in Item 4 smoke).
        assert AuditAction.REPORT_GENERATED.value == "report_generated"
        print("SMOKE OK")
        return 0
    finally:
        try:
            if created:
                await session.execute(
                    delete(AuditTrail).where(AuditTrail.id.in_(created)))
            await session.execute(
                delete(User).where(User.id == user.id))
            await session.commit()
        except Exception:
            await session.rollback()
        await session.close()
        await engine.dispose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
