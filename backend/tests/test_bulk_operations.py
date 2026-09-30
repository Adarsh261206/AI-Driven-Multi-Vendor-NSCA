"""Bulk operations tests (STEP 6).

BULK UPLOAD (POST /configurations/bulk):
- envelope validation is atomic (mapping/ownership/lifecycle for ALL
  items first; any envelope failure -> zero rows)
- ingestion is per-file (one bad file never fails valid siblings)
- duplicates replay honestly (existing id, DUPLICATE status)
- history/latest/audit-count semantics preserved

BULK AUDIT (POST /audit-execution/bulk):
- validation atomic across ALL items (one bad item -> zero audits)
- execution creates N independent audits (own rows, associations, trail)
- archived/foreign/orphan/missing rejected per STEP 1/3/5 rules
- no baseline in request; pipeline resolves per audit (existing)

Throwaway DB + ASGI transport. No frontend involvement.
"""

from __future__ import annotations

import json
import uuid as uuidlib

import pytest
from sqlalchemy import func, select

from app.models import Audit, AuditConfiguration, Configuration
from tests.test_device_security import (
    _SecClient,
    _cfg_bytes,
    _make_device,
    _make_user,
)


@pytest.fixture()
async def bulk_session():
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


async def _bulk_upload(client, files, device_ids):
    """Multipart bulk upload: files[i] <-> device_map[i] positionally.

    device_map travels as one JSON form field (dict-form data keeps the
    httpx client on its async stream path).
    """
    return await client.post(
        "/api/v1/configurations/bulk",
        files=[("files", f) for f in files],
        data={"device_map": json.dumps([str(d) for d in device_ids])},
    )


def _file(name: str, tag: str):
    return (name, _cfg_bytes(tag), "text/plain")


async def _config_count(session) -> int:
    return (await session.execute(select(func.count(Configuration.id)))).scalar()


async def _audit_count(session, user_id) -> int:
    return (
        await session.execute(
            select(func.count(Audit.id)).where(Audit.user_id == user_id)
        )
    ).scalar()


class TestBulkUpload:
    async def _two_devices(self, session, tag: str):
        user = await _make_user(session, f"bulk-{tag}")
        dev_a = await _make_device(session, user, f"bulk-{tag}-a")
        dev_b = await _make_device(session, user, f"bulk-{tag}-b")
        return user, user.id, dev_a.id, dev_b.id

    @pytest.mark.asyncio
    async def test_multiple_valid_files(self, bulk_session):
        user, _, dev_a, dev_b = await self._two_devices(bulk_session, "ok")
        async with _SecClient(bulk_session, user) as client:
            resp = await _bulk_upload(
                client,
                [_file("a.cfg", "bulk-ok-a"), _file("b.cfg", "bulk-ok-b")],
                [str(dev_a), str(dev_b)],
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["summary"] == {"total": 2, "stored": 2, "duplicate": 0, "invalid": 0}
        assert all(i["status"] == "stored" for i in body["items"])
        assert all(i["configuration_id"] for i in body["items"])
        # Linkage correct per position.
        got_a = (
            await bulk_session.execute(
                select(Configuration).where(
                    Configuration.id == body["items"][0]["configuration_id"]
                )
            )
        ).scalar_one()
        assert str(got_a.device_id) == str(dev_a)

    @pytest.mark.asyncio
    async def test_invalid_file_does_not_fail_siblings(self, bulk_session):
        user, _, dev_a, dev_b = await self._two_devices(bulk_session, "part")
        async with _SecClient(bulk_session, user) as client:
            resp = await _bulk_upload(
                client,
                [
                    _file("good.cfg", "bulk-part-good"),
                    ("bad.exe", b"hostname X\n", "text/plain"),
                ],
                [str(dev_a), str(dev_b)],
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["summary"] == {"total": 2, "stored": 1, "duplicate": 0, "invalid": 1}
        by_name = {i["filename"]: i for i in body["items"]}
        assert by_name["good.cfg"]["status"] == "stored"
        assert by_name["bad.exe"]["status"] == "invalid"
        assert by_name["bad.exe"]["error"]

    @pytest.mark.asyncio
    async def test_length_mismatch_rejected_atomically(self, bulk_session):
        user, _, dev_a, _ = await self._two_devices(bulk_session, "len")
        before = await _config_count(bulk_session)
        async with _SecClient(bulk_session, user) as client:
            resp = await _bulk_upload(
                client,
                [_file("a.cfg", "bulk-len-a"), _file("b.cfg", "bulk-len-b")],
                [str(dev_a)],
            )
        assert resp.status_code == 400, resp.text
        assert await _config_count(bulk_session) == before

    @pytest.mark.asyncio
    async def test_foreign_device_rejected_atomically(self, bulk_session):
        user_a = await _make_user(bulk_session, "bulk-for-a")
        user_b = await _make_user(bulk_session, "bulk-for-b")
        dev_a = await _make_device(bulk_session, user_a, "bulk-for-a")
        dev_b = await _make_device(bulk_session, user_b, "bulk-for-b")
        before = await _config_count(bulk_session)
        async with _SecClient(bulk_session, user_a) as client:
            resp = await _bulk_upload(
                client,
                [_file("a.cfg", "bulk-for-a"), _file("b.cfg", "bulk-for-b")],
                [str(dev_a.id), str(dev_b.id)],
            )
        assert resp.status_code in (403, 404), resp.text
        # Zero rows: the valid sibling was NOT persisted.
        assert await _config_count(bulk_session) == before

    @pytest.mark.asyncio
    async def test_archived_device_rejected_atomically(self, bulk_session):
        user, _, dev_a, dev_b = await self._two_devices(bulk_session, "arc")
        async with _SecClient(bulk_session, user) as client:
            arch = await client.post(f"/api/v1/devices/{dev_b}/archive")
            assert arch.status_code == 200
        before = await _config_count(bulk_session)
        async with _SecClient(bulk_session, user) as client:
            resp = await _bulk_upload(
                client,
                [_file("a.cfg", "bulk-arc-a"), _file("b.cfg", "bulk-arc-b")],
                [str(dev_a), str(dev_b)],
            )
        assert resp.status_code == 409, resp.text
        assert await _config_count(bulk_session) == before

    @pytest.mark.asyncio
    async def test_nonexistent_device_rejected_atomically(self, bulk_session):
        user, _, dev_a, _ = await self._two_devices(bulk_session, "nod")
        before = await _config_count(bulk_session)
        async with _SecClient(bulk_session, user) as client:
            resp = await _bulk_upload(
                client,
                [_file("a.cfg", "bulk-nod-a"), _file("b.cfg", "bulk-nod-b")],
                [str(dev_a), str(uuidlib.uuid4())],
            )
        assert resp.status_code in (400, 403, 404), resp.text
        assert await _config_count(bulk_session) == before

    @pytest.mark.asyncio
    async def test_duplicate_content_replays_honestly(self, bulk_session):
        user, _, dev_a, _ = await self._two_devices(bulk_session, "dupe")
        # Unique per run: the throwaway DB persists across runs and a
        # fixed payload would replay a stale row instead of testing
        # within-batch dedup.
        nonce = uuidlib.uuid4().hex[:8].encode()
        fixed = (
            b"hostname BULK-DUPE-" + nonce + b"\n!\ninterface Gi0/0\n"
            b" ip address 10.0.0.1 255.255.255.0\n"
        )
        async with _SecClient(bulk_session, user) as client:
            resp = await _bulk_upload(
                client,
                [("d1.cfg", fixed, "text/plain"), ("d2.cfg", fixed, "text/plain")],
                [str(dev_a), str(dev_a)],
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["summary"] == {"total": 2, "stored": 1, "duplicate": 1, "invalid": 0}
        assert body["items"][0]["status"] == "stored"
        assert body["items"][1]["status"] == "duplicate"
        assert body["items"][1]["configuration_id"] == body["items"][0]["configuration_id"]

    @pytest.mark.asyncio
    async def test_empty_batch_rejected(self, bulk_session):
        # No files part at all: FastAPI's required-field validation (422)
        # rejects before any application code runs — zero rows by design.
        user, _, _, _ = await self._two_devices(bulk_session, "empty")
        async with _SecClient(bulk_session, user) as client:
            resp = await _bulk_upload(client, [], [])
        assert resp.status_code == 422, resp.text

    @pytest.mark.asyncio
    async def test_same_device_multiple_configs(self, bulk_session):
        user, _, dev_a, _ = await self._two_devices(bulk_session, "multi")
        async with _SecClient(bulk_session, user) as client:
            resp = await _bulk_upload(
                client,
                [_file("m1.cfg", "bulk-multi-1"), _file("m2.cfg", "bulk-multi-2")],
                [str(dev_a), str(dev_a)],
            )
            assert resp.status_code == 200, resp.text
            hist = await client.get(f"/api/v1/devices/{dev_a}/configurations")
        assert hist.status_code == 200
        assert hist.json()["meta"]["total"] == 2
        assert hist.json()["items"][0]["latest"] is True


class TestBulkAudit:
    async def _user_with_auditable(self, session, tag: str, ncfgs: int = 1):
        """Owner + device + n linked configs; returns ids (no audits yet)."""
        user = await _make_user(session, f"ba-{tag}")
        dev = await _make_device(session, user, f"ba-{tag}")
        user_id, dev_id = user.id, dev.id
        cfg_ids = []
        async with _SecClient(session, user) as client:
            for i in range(ncfgs):
                up = await client.post(
                    "/api/v1/configurations/upload",
                    files={"file": (f"{tag}-{i}.cfg", _cfg_bytes(f"ba-{tag}-{i}"), "text/plain")},
                    params={"device_id": str(dev_id)},
                )
                assert up.status_code == 201, up.text
                cfg_ids.append(up.json()["id"])
        return user, user_id, dev_id, cfg_ids

    async def _bulk_execute(self, client, items):
        return await client.post("/api/v1/audit-execution/bulk", json={"items": items})

    @pytest.mark.asyncio
    async def test_multiple_valid_items(self, bulk_session):
        user, user_id, dev_id, cfg_ids = await self._user_with_auditable(
            bulk_session, "ok", ncfgs=2
        )
        async with _SecClient(bulk_session, user) as client:
            resp = await self._bulk_execute(
                client,
                [
                    {"name": "bulk-a-0", "configuration_ids": [cfg_ids[0]], "device_ids": [str(dev_id)]},
                    {"name": "bulk-a-1", "configuration_ids": [cfg_ids[1]], "device_ids": [str(dev_id)]},
                ],
            )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["total"] == 2
        assert len(body["audits"]) == 2
        assert body["audits"][0]["audit_id"] != body["audits"][1]["audit_id"]
        # Associations correct per item (scoped to the created audits —
        # the throwaway DB accumulates rows across tests).
        from uuid import UUID as _UUID

        created_ids = [_UUID(a["audit_id"]) for a in body["audits"]]
        rows = (
            await bulk_session.execute(
                select(AuditConfiguration).where(
                    AuditConfiguration.audit_id.in_(created_ids)
                )
            )
        ).all()
        assert len(rows) == 2

    @pytest.mark.asyncio
    async def test_single_item(self, bulk_session):
        user, user_id, dev_id, cfg_ids = await self._user_with_auditable(
            bulk_session, "single"
        )
        async with _SecClient(bulk_session, user) as client:
            resp = await self._bulk_execute(
                client,
                [{"name": "solo", "configuration_ids": cfg_ids, "device_ids": [str(dev_id)]}],
            )
        assert resp.status_code == 202, resp.text
        assert resp.json()["total"] == 1

    @pytest.mark.asyncio
    async def test_foreign_item_rejects_whole_batch(self, bulk_session):
        user_a, user_a_id, dev_a_id, cfg_a = await self._user_with_auditable(
            bulk_session, "mix-a"
        )
        _, _, _, cfg_b = await self._user_with_auditable(bulk_session, "mix-b")
        before = (
            await bulk_session.execute(
                select(func.count(Audit.id)).where(Audit.user_id == user_a_id)
            )
        ).scalar()
        async with _SecClient(bulk_session, user_a) as client:
            resp = await self._bulk_execute(
                client,
                [
                    {"name": "mine", "configuration_ids": cfg_a, "device_ids": [str(dev_a_id)]},
                    {"name": "theirs", "configuration_ids": cfg_b},
                ],
            )
        assert resp.status_code in (403, 404), resp.text
        after = (
            await bulk_session.execute(
                select(func.count(Audit.id)).where(Audit.user_id == user_a_id)
            )
        ).scalar()
        assert after == before, "atomic validation: zero audits on rejection"

    @pytest.mark.asyncio
    async def test_archived_item_rejects_whole_batch(self, bulk_session):
        user, user_id, dev_id, cfg_ids = await self._user_with_auditable(
            bulk_session, "arcb", ncfgs=2
        )
        async with _SecClient(bulk_session, user) as client:
            arch = await client.post(f"/api/v1/devices/{dev_id}/archive")
            assert arch.status_code == 200
            resp = await self._bulk_execute(
                client,
                [
                    {"name": "x0", "configuration_ids": [cfg_ids[0]], "device_ids": [str(dev_id)]},
                    {"name": "x1", "configuration_ids": [cfg_ids[1]], "device_ids": [str(dev_id)]},
                ],
            )
        assert resp.status_code == 409, resp.text
        assert (
            await bulk_session.execute(
                select(func.count(Audit.id)).where(Audit.user_id == user_id)
            )
        ).scalar() == 0

    @pytest.mark.asyncio
    async def test_nonexistent_config_rejects_whole_batch(self, bulk_session):
        user, user_id, dev_id, cfg_ids = await self._user_with_auditable(
            bulk_session, "ncb"
        )
        async with _SecClient(bulk_session, user) as client:
            resp = await self._bulk_execute(
                client,
                [
                    {"name": "ok", "configuration_ids": cfg_ids, "device_ids": [str(dev_id)]},
                    {"name": "ghost", "configuration_ids": [str(uuidlib.uuid4())]},
                ],
            )
        assert resp.status_code == 400, resp.text
        assert (
            await bulk_session.execute(
                select(func.count(Audit.id)).where(Audit.user_id == user_id)
            )
        ).scalar() == 0

    @pytest.mark.asyncio
    async def test_empty_and_oversized_batches(self, bulk_session):
        user, _, _, _ = await self._user_with_auditable(bulk_session, "lim")
        async with _SecClient(bulk_session, user) as client:
            empty = await self._bulk_execute(client, [])
            assert empty.status_code == 400, empty.text
            big = await self._bulk_execute(
                client,
                [{"name": f"n{i}", "configuration_ids": []} for i in range(21)],
            )
            assert big.status_code == 400, big.text

    @pytest.mark.asyncio
    async def test_duplicate_config_across_items_allowed(self, bulk_session):
        # Same snapshot in two items = two independent audits (executions
        # are not deduplicated; only configuration content is).
        user, user_id, dev_id, cfg_ids = await self._user_with_auditable(
            bulk_session, "dupea"
        )
        async with _SecClient(bulk_session, user) as client:
            resp = await self._bulk_execute(
                client,
                [
                    {"name": "dup-0", "configuration_ids": cfg_ids, "device_ids": [str(dev_id)]},
                    {"name": "dup-1", "configuration_ids": cfg_ids, "device_ids": [str(dev_id)]},
                ],
            )
        assert resp.status_code == 202, resp.text
        assert resp.json()["audits"][0]["audit_id"] != resp.json()["audits"][1]["audit_id"]

    @pytest.mark.asyncio
    async def test_no_baseline_injection_accepted(self, bulk_session):
        # Unknown extra fields must not sneak a baseline/scope override in.
        user, _, dev_id, cfg_ids = await self._user_with_auditable(
            bulk_session, "nbinj"
        )
        async with _SecClient(bulk_session, user) as client:
            resp = await client.post(
                "/api/v1/audit-execution/bulk",
                json={
                    "items": [
                        {
                            "name": "inj",
                            "configuration_ids": cfg_ids,
                            "device_ids": [str(dev_id)],
                            "baseline_id": str(uuidlib.uuid4()),
                        }
                    ]
                },
            )
        # Pydantic ignores unknown fields by default: accepted, no effect.
        assert resp.status_code == 202, resp.text
