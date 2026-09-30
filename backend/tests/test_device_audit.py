"""Device-aware single audit scope tests (STEP 3).

Contract under test: optional `device_ids` on audit creation/execution
acts as an execution-time scope constraint (NOT a persisted Audit.device_id).
Every device must be owned; every configuration must belong to one of the
scoped devices; any violation rejects the ENTIRE request atomically.

Matrix:
- device A + config A(devA) + scope [A] → 202, audit created
- device A + config B(devB) + scope [A] → 403, zero audits (execute + create)
- scope [B-foreign] as A → 403/404, zero audits
- scope [random] → 404
- config [random] → 400 (existing contract)
- unlinked config + scope [A] → reject (403)
- no scope + own config → 202 (legacy ownership-only behavior preserved)
- same snapshot twice → two independent audits (no audit dedup)
- no-baseline org → audit still created (202)
- upload binds server-side device_id regardless of content identity
- dedup replay returns the existing snapshot honestly

Direct API calls only. Throwaway DB + ASGI transport.
"""

from __future__ import annotations

import uuid as uuidlib

import pytest
from sqlalchemy import func, select

from app.models import Audit
from tests.test_device_security import (
    _SecClient,
    _cfg_bytes,
    _make_device,
    _make_user,
)


@pytest.fixture()
async def scope_session():
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
    params = {}
    if device_id is not None:
        params["device_id"] = str(device_id)
    return await client.post(
        "/api/v1/configurations/upload",
        files={"file": (filename, _cfg_bytes(tag), "text/plain")},
        params=params,
    )


async def _execute(client, name, config_ids, device_ids=None):
    body: dict = {
        "name": name,
        "configuration_ids": [str(c) for c in config_ids],
        "framework": "CIS",
    }
    if device_ids is not None:
        body["device_ids"] = [str(d) for d in device_ids]
    return await client.post("/api/v1/audit-execution/execute", json=body)


async def _create(client, name, config_ids, device_ids=None):
    body: dict = {
        "name": name,
        "configuration_ids": [str(c) for c in config_ids],
        "framework": "CIS",
    }
    if device_ids is not None:
        body["device_ids"] = [str(d) for d in device_ids]
    return await client.post("/api/v1/audits/", json=body)


async def _audit_count(session, user_id) -> int:
    return (
        await session.execute(
            select(func.count(Audit.id)).where(Audit.user_id == user_id)
        )
    ).scalar()


async def _seed_ab(scope_session, tag: str):
    """Two owners; returns (user_a, user_b, dev_a, dev_b, cfg_a, cfg_b)."""
    user_a = await _make_user(scope_session, f"{tag}-a")
    user_b = await _make_user(scope_session, f"{tag}-b")
    dev_a = await _make_device(scope_session, user_a, f"{tag}-a")
    dev_b = await _make_device(scope_session, user_b, f"{tag}-b")
    user_a_id, dev_a_id, dev_b_id = user_a.id, dev_a.id, dev_b.id
    async with _SecClient(scope_session, user_a) as client_a:
        up_a = await _upload(client_a, f"{tag}-a.cfg", f"{tag}-a", device_id=dev_a_id)
        assert up_a.status_code == 201, up_a.text
        cfg_a = up_a.json()["id"]
    async with _SecClient(scope_session, user_b) as client_b:
        up_b = await _upload(client_b, f"{tag}-b.cfg", f"{tag}-b", device_id=dev_b_id)
        assert up_b.status_code == 201, up_b.text
        cfg_b = up_b.json()["id"]
    return user_a, user_b, dev_a, dev_b, cfg_a, cfg_b, user_a_id, dev_a_id, dev_b_id


class TestDeviceScopedAudit:
    @pytest.mark.asyncio
    async def test_device_scoped_audit_succeeds(self, scope_session):
        user_a, _, _, _, cfg_a, _, user_a_id, dev_a_id, _ = await _seed_ab(
            scope_session, "dsc-ok"
        )
        async with _SecClient(scope_session, user_a) as client:
            resp = await _execute(
                client, "scoped audit", [cfg_a], device_ids=[dev_a_id]
            )
        assert resp.status_code == 202, resp.text
        assert resp.json()["id"]
        assert await _audit_count(scope_session, user_a_id) == 1

    @pytest.mark.asyncio
    async def test_device_config_mismatch_rejected_execute(self, scope_session):
        # Device A + Config B(devB): backend MUST reject, not substitute.
        user_a, _, _, _, _, cfg_b, user_a_id, dev_a_id, _ = await _seed_ab(
            scope_session, "dsc-mismatch"
        )
        before = await _audit_count(scope_session, user_a_id)
        async with _SecClient(scope_session, user_a) as client:
            resp = await _execute(
                client, "mismatch audit", [cfg_b], device_ids=[dev_a_id]
            )
        assert resp.status_code in (403, 404), (
            f"cross-scope combination must be rejected, got {resp.status_code}: {resp.text}"
        )
        assert await _audit_count(scope_session, user_a_id) == before

    @pytest.mark.asyncio
    async def test_device_config_mismatch_rejected_create(self, scope_session):
        user_a, _, _, _, _, cfg_b, user_a_id, dev_a_id, _ = await _seed_ab(
            scope_session, "dsc-mismatchc"
        )
        before = await _audit_count(scope_session, user_a_id)
        async with _SecClient(scope_session, user_a) as client:
            resp = await _create(
                client, "mismatch audit", [cfg_b], device_ids=[dev_a_id]
            )
        assert resp.status_code in (403, 404), (
            f"cross-scope combination must be rejected, got {resp.status_code}: {resp.text}"
        )
        assert await _audit_count(scope_session, user_a_id) == before

    @pytest.mark.asyncio
    async def test_foreign_device_scope_rejected(self, scope_session):
        user_a, _, _, _, cfg_a, _, user_a_id, _, dev_b_id = await _seed_ab(
            scope_session, "dsc-fordev"
        )
        before = await _audit_count(scope_session, user_a_id)
        async with _SecClient(scope_session, user_a) as client:
            resp = await _execute(
                client, "foreign scope", [cfg_a], device_ids=[dev_b_id]
            )
        assert resp.status_code in (403, 404), (
            f"foreign device scope must be rejected, got {resp.status_code}: {resp.text}"
        )
        assert await _audit_count(scope_session, user_a_id) == before

    @pytest.mark.asyncio
    async def test_nonexistent_device_scope_404(self, scope_session):
        user_a, _, _, _, cfg_a, _, user_a_id, _, _ = await _seed_ab(
            scope_session, "dsc-nodev"
        )
        before = await _audit_count(scope_session, user_a_id)
        async with _SecClient(scope_session, user_a) as client:
            resp = await _execute(
                client, "ghost scope", [cfg_a], device_ids=[uuidlib.uuid4()]
            )
        assert resp.status_code == 404, (
            f"nonexistent device scope must stay 404, got {resp.status_code}: {resp.text}"
        )
        assert await _audit_count(scope_session, user_a_id) == before

    @pytest.mark.asyncio
    async def test_nonexistent_config_still_400(self, scope_session):
        # Existing contract preserved: unknown config IDs -> 400.
        user_a, _, _, _, _, _, user_a_id, dev_a_id, _ = await _seed_ab(
            scope_session, "dsc-nocfg"
        )
        async with _SecClient(scope_session, user_a) as client:
            resp = await _execute(
                client, "ghost config", [uuidlib.uuid4()], device_ids=[dev_a_id]
            )
        assert resp.status_code == 400, (
            f"nonexistent config must stay 400, got {resp.status_code}: {resp.text}"
        )
        assert await _audit_count(scope_session, user_a_id) == 0

    @pytest.mark.asyncio
    async def test_unlinked_config_with_device_scope_rejected(self, scope_session):
        user_a, _, _, _, _, _, user_a_id, dev_a_id, _ = await _seed_ab(
            scope_session, "dsc-nolink"
        )
        async with _SecClient(scope_session, user_a) as client:
            up = await _upload(client, "nolink.cfg", "dsc-nolink")
            assert up.status_code == 201, up.text
            orphan = up.json()["id"]
            resp = await _execute(
                client, "orphan scope", [orphan], device_ids=[dev_a_id]
            )
        assert resp.status_code in (403, 404), (
            f"unlinked config cannot satisfy device scope, got {resp.status_code}: {resp.text}"
        )
        assert await _audit_count(scope_session, user_a_id) == 0

    @pytest.mark.asyncio
    async def test_no_scope_legacy_behavior_preserved(self, scope_session):
        # No device_ids: STEP 1 ownership-only behavior, unchanged.
        user_a, _, _, _, cfg_a, _, user_a_id, _, _ = await _seed_ab(
            scope_session, "dsc-legacy"
        )
        async with _SecClient(scope_session, user_a) as client:
            resp = await _execute(client, "legacy audit", [cfg_a])
        assert resp.status_code == 202, resp.text
        assert await _audit_count(scope_session, user_a_id) == 1

    @pytest.mark.asyncio
    async def test_same_snapshot_twice_creates_two_audits(self, scope_session):
        # Audits are executions, not deduplicated artifacts.
        user_a, _, _, _, cfg_a, _, user_a_id, dev_a_id, _ = await _seed_ab(
            scope_session, "dsc-twice"
        )
        async with _SecClient(scope_session, user_a) as client:
            r1 = await _execute(client, "first", [cfg_a], device_ids=[dev_a_id])
            r2 = await _execute(client, "second", [cfg_a], device_ids=[dev_a_id])
        assert r1.status_code == 202 and r2.status_code == 202
        assert r1.json()["id"] != r2.json()["id"]
        assert await _audit_count(scope_session, user_a_id) == 2

    @pytest.mark.asyncio
    async def test_audit_without_baseline_still_created(self, scope_session):
        # Fresh users have no organization/baseline: audit must still run.
        user_a, _, _, _, cfg_a, _, user_a_id, dev_a_id, _ = await _seed_ab(
            scope_session, "dsc-nobase"
        )
        assert user_a.organization_id is None
        async with _SecClient(scope_session, user_a) as client:
            resp = await _execute(
                client, "no-baseline audit", [cfg_a], device_ids=[dev_a_id]
            )
        assert resp.status_code == 202, resp.text

    @pytest.mark.asyncio
    async def test_upload_binds_selected_device(self, scope_session):
        # Adversarial D: content claims another identity, but the upload
        # binds the server-side selected device — never the file's claim.
        from app.models import Configuration
        from sqlalchemy import select

        user_a, _, _, _, _, _, _, dev_a_id, _ = await _seed_ab(
            scope_session, "dsc-bind"
        )
        async with _SecClient(scope_session, user_a) as client:
            up = await _upload(
                client, "claimed.cfg", "dsc-bind-other-hostname", device_id=dev_a_id
            )
            assert up.status_code == 201, up.text
            row = (
                await scope_session.execute(
                    select(Configuration).where(
                        Configuration.id == up.json()["id"]
                    )
                )
            ).scalar_one()
            assert str(row.device_id) == str(dev_a_id)

    @pytest.mark.asyncio
    async def test_dedup_replay_returns_existing_snapshot(self, scope_session):
        # Adversarial L: byte-identical content replays the existing
        # snapshot honestly instead of forking history.
        fixed_content = (
            b"hostname DEDUP-FIXED\n!\ninterface Gi0/0\n"
            b" ip address 10.0.0.1 255.255.255.0\n"
        )
        user_a, _, _, _, _, _, _, dev_a_id, _ = await _seed_ab(
            scope_session, "dsc-dupe"
        )
        async with _SecClient(scope_session, user_a) as client:
            up1 = await client.post(
                "/api/v1/configurations/upload",
                files={"file": ("dupe.cfg", fixed_content, "text/plain")},
                params={"device_id": str(dev_a_id)},
            )
            assert up1.status_code == 201, up1.text
            up2 = await client.post(
                "/api/v1/configurations/upload",
                files={"file": ("dupe-copy.cfg", fixed_content, "text/plain")},
                params={"device_id": str(dev_a_id)},
            )
            assert up2.status_code == 201, up2.text
            assert up2.json()["id"] == up1.json()["id"]
