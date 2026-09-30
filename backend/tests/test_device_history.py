"""Device configuration/audit history tests (STEP 2, PART L/M).

Covers:
- zero / one / multiple configurations (ordering newest-first)
- exactly one latest (incl. equal-timestamp deterministic tiebreak)
- audit_count derived from AuditConfiguration (0, 1, many)
- device audit history derived through AuditConfiguration → device
- foreign device history rejected (403), nonexistent device 404
- user isolation (no cross-owner leakage)
- viewer read of own device history
- STEP 1 regression (foreign upload/audit still blocked)

Uses the throwaway engine_validation_test DB + ASGI transport.
"""

from __future__ import annotations

import uuid as uuidlib
from datetime import datetime

import pytest

from tests.test_device_security import (
    _SecClient,
    _cfg_bytes,
    _make_device,
    _make_user,
)


@pytest.fixture()
async def hist_session():
    import scripts.engine_validation.dbutil as dbutil

    if not await dbutil.schema_available():
        pytest.skip("throwaway database engine_validation_test not provisioned")

    db_engine, factory = dbutil.make_session_factory()
    session = factory()
    try:
        yield session
    finally:
        try:
            await session.rollback()
        except Exception:
            pass
        await session.close()
        await db_engine.dispose()


async def _upload(client, filename: str, tag: str, device_id=None):
    from uuid import UUID  # noqa: F401  (documents UUID path, unused)

    params = {}
    if device_id is not None:
        params["device_id"] = str(device_id)
    return await client.post(
        "/api/v1/configurations/upload",
        files={"file": (filename, _cfg_bytes(tag), "text/plain")},
        params=params,
    )


async def _history(client, device_id, page: int = 1, per_page: int = 20):
    return await client.get(
        f"/api/v1/devices/{device_id}/configurations",
        params={"page": page, "per_page": per_page},
    )


async def _device_audits(client, device_id):
    return await client.get(f"/api/v1/devices/{device_id}/audits")


class TestConfigurationHistory:
    @pytest.mark.asyncio
    async def test_zero_configurations_empty_list(self, hist_session):
        user = await _make_user(hist_session, "h-zero")
        device = await _make_device(hist_session, user, "h-zero")
        async with _SecClient(hist_session, user) as client:
            resp = await _history(client, device.id)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["items"] == []
        assert body["meta"]["total"] == 0

    @pytest.mark.asyncio
    async def test_one_configuration_is_latest(self, hist_session):
        user = await _make_user(hist_session, "h-one")
        device = await _make_device(hist_session, user, "h-one")
        async with _SecClient(hist_session, user) as client:
            up = await _upload(client, "one.cfg", "h-one", device_id=device.id)
            assert up.status_code == 201, up.text
            resp = await _history(client, device.id)
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 1
        item = items[0]
        assert item["latest"] is True
        assert item["audit_count"] == 0
        assert item["filename"] == "one.cfg"
        assert item["device_id"] == str(device.id)
        assert item["content_hash"]
        assert item["size_bytes"] > 0
        assert item["uploaded_at"]
        # No raw content in history responses.
        assert "raw_content" not in item
        assert "content" not in item

    @pytest.mark.asyncio
    async def test_multiple_ordered_newest_first_exactly_one_latest(
        self, hist_session
    ):
        user = await _make_user(hist_session, "h-multi")
        device = await _make_device(hist_session, user, "h-multi")
        async with _SecClient(hist_session, user) as client:
            for name in ("c-old.cfg", "c-mid.cfg", "c-new.cfg"):
                up = await _upload(client, name, f"h-multi-{name}", device_id=device.id)
                assert up.status_code == 201, up.text
            resp = await _history(client, device.id)
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert [i["filename"] for i in items] == ["c-new.cfg", "c-mid.cfg", "c-old.cfg"]
        assert [i["latest"] for i in items].count(True) == 1
        assert items[0]["latest"] is True

    @pytest.mark.asyncio
    async def test_equal_timestamps_deterministic_order(self, hist_session):
        """Identical uploaded_at falls back to a stable secondary order."""
        from app.models import Configuration

        user = await _make_user(hist_session, "h-tie")
        device = await _make_device(hist_session, user, "h-tie")
        frozen = datetime(2026, 9, 29, 12, 0, 0)  # naive: matches TIMESTAMP WITHOUT TIME ZONE
        for name in ("tie-a.cfg", "tie-b.cfg"):
            hist_session.add(
                Configuration(
                    device_id=device.id,
                    filename=name,
                    content_hash=f"tie-{name}-{uuidlib.uuid4().hex}",
                    raw_content="hostname TIE\n",
                    content_type="text/plain",
                    size_bytes=13,
                    line_count=1,
                    uploaded_at=frozen,
                )
            )
        await hist_session.flush()
        device_id = device.id  # capture: session state expires across contexts
        async with _SecClient(hist_session, user) as client:
            first = await _history(client, device_id)
            second = await _history(client, device_id)
        assert first.status_code == 200
        names_first = [i["filename"] for i in first.json()["items"]]
        names_second = [i["filename"] for i in second.json()["items"]]
        assert names_first == names_second  # deterministic across requests
        assert [i["latest"] for i in first.json()["items"]].count(True) == 1

    @pytest.mark.asyncio
    async def test_audit_count_derived(self, hist_session):
        from app.models import Audit, AuditConfiguration

        user = await _make_user(hist_session, "h-count")
        device = await _make_device(hist_session, user, "h-count")
        async with _SecClient(hist_session, user) as client:
            up1 = await _upload(client, "cnt-a.cfg", "h-count-a", device_id=device.id)
            up2 = await _upload(client, "cnt-b.cfg", "h-count-b", device_id=device.id)
            assert up1.status_code == 201 and up2.status_code == 201
        from uuid import UUID

        cfg_a = UUID(up1.json()["id"])
        for n in ("audit-1", "audit-2"):
            audit = Audit(
                user_id=user.id, name=n, status="completed", overall_score=70.0
            )
            hist_session.add(audit)
            await hist_session.flush()
            hist_session.add(
                AuditConfiguration(audit_id=audit.id, configuration_id=cfg_a)
            )
        await hist_session.flush()
        async with _SecClient(hist_session, user) as client:
            resp = await _history(client, device.id)
        by_name = {i["filename"]: i for i in resp.json()["items"]}
        assert by_name["cnt-a.cfg"]["audit_count"] == 2
        assert by_name["cnt-b.cfg"]["audit_count"] == 0

    @pytest.mark.asyncio
    async def test_device_audit_history_derived(self, hist_session):
        from app.models import Audit, AuditConfiguration

        user = await _make_user(hist_session, "h-auhist")
        device = await _make_device(hist_session, user, "h-auhist")
        async with _SecClient(hist_session, user) as client:
            up = await _upload(client, "auhist.cfg", "h-auhist", device_id=device.id)
            assert up.status_code == 201
        from uuid import UUID

        cfg_id = UUID(up.json()["id"])
        audit = Audit(
            user_id=user.id,
            name="device audit",
            status="completed",
            overall_score=63.6,
        )
        hist_session.add(audit)
        await hist_session.flush()
        hist_session.add(
            AuditConfiguration(audit_id=audit.id, configuration_id=cfg_id)
        )
        await hist_session.flush()
        async with _SecClient(hist_session, user) as client:
            resp = await _device_audits(client, device.id)
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 1
        row = items[0]
        assert row["name"] == "device audit"
        assert row["status"] == "completed"
        assert row["overall_score"] == 63.6
        assert row["configuration_filename"] == "auhist.cfg"
        assert row["configuration_id"] == str(cfg_id)


class TestHistoryAuthorization:
    @pytest.mark.asyncio
    async def test_foreign_device_history_rejected(self, hist_session):
        user_a = await _make_user(hist_session, "h-for-a")
        user_b = await _make_user(hist_session, "h-for-b")
        device_b = await _make_device(hist_session, user_b, "h-for-b")
        device_b_id = device_b.id  # capture: session state expires across contexts
        async with _SecClient(hist_session, user_b) as client_b:
            up = await _upload(client_b, "for.cfg", "h-for", device_id=device_b.id)
            assert up.status_code == 201
        async with _SecClient(hist_session, user_a) as client_a:
            resp = await _history(client_a, device_b_id)
            assert resp.status_code in (403, 404), (
                f"foreign history must be rejected, got {resp.status_code}"
            )
            resp2 = await _device_audits(client_a, device_b_id)
            assert resp2.status_code in (403, 404), (
                f"foreign audit history must be rejected, got {resp2.status_code}"
            )

    @pytest.mark.asyncio
    async def test_nonexistent_device_history_404(self, hist_session):
        user = await _make_user(hist_session, "h-missing")
        async with _SecClient(hist_session, user) as client:
            resp = await _history(client, uuidlib.uuid4())
            assert resp.status_code == 404
            resp2 = await _device_audits(client, uuidlib.uuid4())
            assert resp2.status_code == 404

    @pytest.mark.asyncio
    async def test_isolation_between_owners(self, hist_session):
        user_a = await _make_user(hist_session, "h-iso-a")
        user_b = await _make_user(hist_session, "h-iso-b")
        device_a = await _make_device(hist_session, user_a, "h-iso-a")
        device_b = await _make_device(hist_session, user_b, "h-iso-b")
        async with _SecClient(hist_session, user_a) as client_a:
            await _upload(client_a, "iso-a.cfg", "h-iso-a", device_id=device_a.id)
        async with _SecClient(hist_session, user_b) as client_b:
            await _upload(client_b, "iso-b.cfg", "h-iso-b", device_id=device_b.id)
            resp = await _history(client_b, device_b.id)
        names = [i["filename"] for i in resp.json()["items"]]
        assert names == ["iso-b.cfg"]
        assert "iso-a.cfg" not in names

    @pytest.mark.asyncio
    async def test_viewer_reads_own_history(self, hist_session):
        viewer = await _make_user(hist_session, "h-viewer", role="viewer")
        device = await _make_device(hist_session, viewer, "h-viewer")
        # Viewer cannot upload (require_auditor) — seed via ORM-level row.
        from app.models import Configuration

        hist_session.add(
            Configuration(
                device_id=device.id,
                filename="viewer.cfg",
                content_hash=f"viewer-{uuidlib.uuid4().hex}",
                raw_content="hostname V\n",
                content_type="text/plain",
                size_bytes=11,
                line_count=1,
            )
        )
        await hist_session.flush()
        async with _SecClient(hist_session, viewer) as client:
            resp = await _history(client, device.id)
        assert resp.status_code == 200, resp.text
        assert [i["filename"] for i in resp.json()["items"]] == ["viewer.cfg"]


class TestStep1StillHolds:
    """STEP 1 regression inside the STEP 2 suite."""

    @pytest.mark.asyncio
    async def test_foreign_upload_still_blocked(self, hist_session):
        user_a = await _make_user(hist_session, "h-s1-a")
        user_b = await _make_user(hist_session, "h-s1-b")
        device_b = await _make_device(hist_session, user_b, "h-s1-b")
        async with _SecClient(hist_session, user_a) as client:
            resp = await _upload(
                client, "s1.cfg", "h-s1", device_id=device_b.id
            )
        assert resp.status_code in (403, 404)

    @pytest.mark.asyncio
    async def test_foreign_audit_still_blocked(self, hist_session):
        from sqlalchemy import func, select

        from app.models import Audit

        user_a = await _make_user(hist_session, "h-s1a-a")
        user_b = await _make_user(hist_session, "h-s1a-b")
        device_b = await _make_device(hist_session, user_b, "h-s1a-b")
        user_a_id = user_a.id  # capture: session state expires across contexts
        async with _SecClient(hist_session, user_b) as client_b:
            up = await _upload(client_b, "s1a.cfg", "h-s1a", device_id=device_b.id)
            assert up.status_code == 201
            foreign_cfg = up.json()["id"]
        before = (
            await hist_session.execute(
                select(func.count(Audit.id)).where(Audit.user_id == user_a_id)
            )
        ).scalar()
        async with _SecClient(hist_session, user_a) as client_a:
            resp = await client_a.post(
                "/api/v1/audit-execution/execute",
                json={
                    "name": "s1",
                    "configuration_ids": [foreign_cfg],
                    "framework": "CIS",
                },
            )
        assert resp.status_code in (403, 404)
        after = (
            await hist_session.execute(
                select(func.count(Audit.id)).where(Audit.user_id == user_a_id)
            )
        ).scalar()
        assert after == before
