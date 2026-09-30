"""Device inventory derived-field tests (STEP 4).

GET /devices returns operational inventory computed from existing
relationships — no new columns, no fabricated values:

- latest_configuration_filename/at: MAX(uploaded_at), tie-break id DESC
- last_audit_id/at: latest COMPLETED audit via device configs
- last_audit_status: latest audit of ANY status (Running/Failed display)
- last_compliance_score: overall_score of latest COMPLETED (else None)
- configuration_count, last_audit_date (populated at last)

Plus: server-side search (name/IP/vendor/platform, case-insensitive),
filter composition, pagination totals, ownership isolation.
"""

from __future__ import annotations

import uuid as uuidlib
from datetime import datetime, timedelta

import pytest

from tests.test_device_security import (
    _SecClient,
    _cfg_bytes,
    _make_device,
    _make_user,
)


@pytest.fixture()
async def inv_session():
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


async def _upload(client, filename: str, tag: str, device_id):
    return await client.post(
        "/api/v1/configurations/upload",
        files={"file": (filename, _cfg_bytes(tag), "text/plain")},
        params={"device_id": str(device_id)},
    )


async def _list(client, **params):
    return await client.get("/api/v1/devices/", params=params)


async def _mk_audit(session, user_id, name, status, score=None, created_at=None):
    from app.models import Audit

    audit = Audit(
        user_id=user_id,
        name=name,
        status=status,
        overall_score=score,
    )
    if created_at is not None:
        audit.created_at = created_at
    session.add(audit)
    await session.flush()
    return audit


async def _link(session, audit_id, config_id):
    from app.models import AuditConfiguration

    session.add(
        AuditConfiguration(audit_id=audit_id, configuration_id=config_id)
    )
    await session.flush()


def _by_name(items, name):
    for item in items:
        if item["name"] == name:
            return item
    raise AssertionError(f"device {name!r} missing from inventory")


class TestDerivedInventory:
    @pytest.mark.asyncio
    async def test_no_config_all_null(self, inv_session):
        user = await _make_user(inv_session, "inv-none")
        await _make_device(inv_session, user, "inv-none")
        async with _SecClient(inv_session, user) as client:
            resp = await _list(client)
        assert resp.status_code == 200, resp.text
        item = _by_name(resp.json()["items"], "sec-device-inv-none")
        assert item["configuration_count"] == 0
        assert item["latest_configuration_filename"] is None
        assert item["latest_configuration_at"] is None
        assert item["last_audit_id"] is None
        assert item["last_audit_status"] is None
        assert item["last_compliance_score"] is None
        assert item["last_audit_date"] is None

    @pytest.mark.asyncio
    async def test_one_config_latest(self, inv_session):
        user = await _make_user(inv_session, "inv-one")
        device = await _make_device(inv_session, user, "inv-one")
        device_id = device.id
        async with _SecClient(inv_session, user) as client:
            up = await _upload(client, "one.cfg", "inv-one", device_id)
            assert up.status_code == 201, up.text
            resp = await _list(client)
        item = _by_name(resp.json()["items"], "sec-device-inv-one")
        assert item["configuration_count"] == 1
        assert item["latest_configuration_filename"] == "one.cfg"
        assert item["latest_configuration_at"] is not None
        assert item["last_audit_id"] is None
        assert item["last_compliance_score"] is None

    @pytest.mark.asyncio
    async def test_multiple_latest_is_newest(self, inv_session):
        user = await _make_user(inv_session, "inv-multi")
        device = await _make_device(inv_session, user, "inv-multi")
        device_id = device.id
        async with _SecClient(inv_session, user) as client:
            for name in ("m-old.cfg", "m-mid.cfg", "m-new.cfg"):
                up = await _upload(client, name, f"inv-multi-{name}", device_id)
                assert up.status_code == 201, up.text
            resp = await _list(client)
        item = _by_name(resp.json()["items"], "sec-device-inv-multi")
        assert item["configuration_count"] == 3
        assert item["latest_configuration_filename"] == "m-new.cfg"

    @pytest.mark.asyncio
    async def test_tie_deterministic(self, inv_session):
        from app.models import Configuration

        user = await _make_user(inv_session, "inv-tie")
        device = await _make_device(inv_session, user, "inv-tie")
        frozen = datetime(2026, 9, 29, 12, 0, 0)
        for name in ("tie-a.cfg", "tie-b.cfg"):
            inv_session.add(
                Configuration(
                    device_id=device.id,
                    filename=name,
                    content_hash=f"inv-tie-{name}-{uuidlib.uuid4().hex}",
                    raw_content="hostname T\n",
                    content_type="text/plain",
                    size_bytes=11,
                    line_count=1,
                    uploaded_at=frozen,
                )
            )
        await inv_session.flush()
        async with _SecClient(inv_session, user) as client:
            first = await _list(client)
            second = await _list(client)
        a = _by_name(first.json()["items"], "sec-device-inv-tie")
        b = _by_name(second.json()["items"], "sec-device-inv-tie")
        assert a["latest_configuration_filename"] == b["latest_configuration_filename"]
        assert a["configuration_count"] == 2

    @pytest.mark.asyncio
    async def test_completed_audit_derived(self, inv_session):
        user = await _make_user(inv_session, "inv-done")
        device = await _make_device(inv_session, user, "inv-done")
        user_id, device_id = user.id, device.id
        async with _SecClient(inv_session, user) as client:
            up = await _upload(client, "done.cfg", "inv-done", device_id)
            assert up.status_code == 201
        from uuid import UUID

        audit = await _mk_audit(
            inv_session, user_id, "done audit", "completed", score=63.6
        )
        await _link(inv_session, audit.id, UUID(up.json()["id"]))
        async with _SecClient(inv_session, user) as client:
            resp = await _list(client)
        item = _by_name(resp.json()["items"], "sec-device-inv-done")
        assert item["last_audit_id"] == str(audit.id)
        assert item["last_audit_status"] == "completed"
        assert item["last_compliance_score"] == 63.6
        assert item["last_audit_date"] is not None

    @pytest.mark.asyncio
    async def test_failed_latest_status_with_completed_result(self, inv_session):
        user = await _make_user(inv_session, "inv-fail")
        device = await _make_device(inv_session, user, "inv-fail")
        user_id, device_id = user.id, device.id
        async with _SecClient(inv_session, user) as client:
            up = await _upload(client, "fail.cfg", "inv-fail", device_id)
            assert up.status_code == 201
        from uuid import UUID

        cfg_id = UUID(up.json()["id"])
        base = datetime(2026, 9, 29, 10, 0, 0)
        old = await _mk_audit(
            inv_session, user_id, "old ok", "completed", score=80.0,
            created_at=base,
        )
        await _link(inv_session, old.id, cfg_id)
        new = await _mk_audit(
            inv_session, user_id, "new failed", "failed",
            created_at=base + timedelta(hours=1),
        )
        await _link(inv_session, new.id, cfg_id)
        async with _SecClient(inv_session, user) as client:
            resp = await _list(client)
        item = _by_name(resp.json()["items"], "sec-device-inv-fail")
        # Latest execution state is failed...
        assert item["last_audit_status"] == "failed"
        # ...but the completed result still comes from the completed audit.
        assert item["last_audit_id"] == str(old.id)
        assert item["last_compliance_score"] == 80.0

    @pytest.mark.asyncio
    async def test_processing_status(self, inv_session):
        user = await _make_user(inv_session, "inv-proc")
        device = await _make_device(inv_session, user, "inv-proc")
        user_id, device_id = user.id, device.id
        async with _SecClient(inv_session, user) as client:
            up = await _upload(client, "proc.cfg", "inv-proc", device_id)
            assert up.status_code == 201
        from uuid import UUID

        running = await _mk_audit(inv_session, user_id, "running", "processing")
        await _link(inv_session, running.id, UUID(up.json()["id"]))
        async with _SecClient(inv_session, user) as client:
            resp = await _list(client)
        item = _by_name(resp.json()["items"], "sec-device-inv-proc")
        assert item["last_audit_status"] == "processing"
        assert item["last_audit_id"] is None
        assert item["last_compliance_score"] is None


class TestInventorySearchFilters:
    async def _seed(self, inv_session, tag: str, vendor: str, platform: str, ip: str, user=None):
        from app.models import Device

        # One owner per test-case: pass user explicitly when several
        # devices must belong to the same inventory.
        if user is None:
            user = await _make_user(inv_session, f"inv-s-{tag}")
        device = Device(
            user_id=user.id,
            name=f"inv-search-{tag}",
            vendor=vendor,
            platform=platform,
            ip_address=ip,
        )
        inv_session.add(device)
        await inv_session.flush()
        return user

    @pytest.mark.asyncio
    async def test_search_by_name(self, inv_session):
        user = await self._seed(inv_session, "alpha", "cisco", "ios_xe", "10.1.0.1")
        await self._seed(inv_session, "beta", "juniper", "junos", "10.2.0.1", user=user)
        async with _SecClient(inv_session, user) as client:
            resp = await _list(client, search="ALPHA")
        names = [i["name"] for i in resp.json()["items"]]
        assert names == ["inv-search-alpha"]

    @pytest.mark.asyncio
    async def test_search_by_ip_and_vendor(self, inv_session):
        user = await self._seed(inv_session, "gamma", "cisco", "ios_xe", "192.168.9.9")
        await self._seed(inv_session, "delta", "juniper", "junos", "10.3.0.1", user=user)
        async with _SecClient(inv_session, user) as client:
            by_ip = await _list(client, search="192.168.9")
            assert [i["name"] for i in by_ip.json()["items"]] == ["inv-search-gamma"]
            by_vendor = await _list(client, search="juniper")
            assert [i["name"] for i in by_vendor.json()["items"]] == ["inv-search-delta"]

    @pytest.mark.asyncio
    async def test_search_composes_with_filters(self, inv_session):
        user = await self._seed(inv_session, "r1", "cisco", "ios_xe", "10.4.0.1")
        await self._seed(inv_session, "r2", "cisco", "junos", "10.4.0.2", user=user)
        async with _SecClient(inv_session, user) as client:
            resp = await _list(
                client, search="inv-search", vendor="cisco", platform="ios_xe"
            )
        assert [i["name"] for i in resp.json()["items"]] == ["inv-search-r1"]

    @pytest.mark.asyncio
    async def test_search_pagination_total(self, inv_session):
        user = await self._seed(inv_session, "p1", "cisco", "ios_xe", "10.5.0.1")
        await self._seed(inv_session, "p2", "cisco", "ios_xe", "10.5.0.2", user=user)
        await self._seed(inv_session, "other", "juniper", "junos", "10.5.0.3", user=user)
        async with _SecClient(inv_session, user) as client:
            resp = await _list(client, search="inv-search-p", page=2, per_page=1)
        body = resp.json()
        assert body["meta"]["total"] == 2
        assert body["meta"]["total_pages"] == 2
        assert len(body["items"]) == 1

    @pytest.mark.asyncio
    async def test_search_no_match(self, inv_session):
        user = await self._seed(inv_session, "nomatch", "cisco", "ios_xe", "10.6.0.1")
        async with _SecClient(inv_session, user) as client:
            resp = await _list(client, search="zzz-no-such-device")
        assert resp.json()["items"] == []
        assert resp.json()["meta"]["total"] == 0


class TestInventoryIsolation:
    @pytest.mark.asyncio
    async def test_cross_owner_invisible(self, inv_session):
        user_a = await _make_user(inv_session, "inv-iso-a")
        user_b = await _make_user(inv_session, "inv-iso-b")
        device_b = await _make_device(inv_session, user_b, "inv-iso-b")
        device_b_id = device_b.id
        async with _SecClient(inv_session, user_b) as client_b:
            up = await client_b.post(
                "/api/v1/configurations/upload",
                files={"file": ("iso.cfg", b"hostname ISO\n", "text/plain")},
                params={"device_id": str(device_b_id)},
            )
            assert up.status_code == 201
        from uuid import UUID

        audit = await _mk_audit(
            inv_session, user_b.id, "b audit", "completed", score=99.9
        )
        await _link(inv_session, audit.id, UUID(up.json()["id"]))
        async with _SecClient(inv_session, user_a) as client_a:
            resp = await _list(client_a)
        names = [i["name"] for i in resp.json()["items"]]
        assert "sec-device-inv-iso-b" not in names
        # No field may leak B's config/audit/score.
        blob = resp.text
        assert "iso.cfg" not in blob
        assert "99.9" not in blob
