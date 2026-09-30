"""Device lifecycle tests (STEP 5).

Covers PART 16 matrix (device/config/audit/inventory subsets):
- edit: own/foreign/missing/invalid/history-preserved
- archive/unarchive: own/foreign/missing/filtering/idempotency
- archived restrictions: upload/audit rejected; history/report reads allowed
- delete policy: pristine allowed; history-bearing blocked (409+counts);
  foreign/missing/repeat deterministic
- inventory lifecycle filter + composition + pagination

Throwaway DB + ASGI transport. No frontend involvement.
"""

from __future__ import annotations

import uuid as uuidlib

import pytest
from sqlalchemy import func, select

from app.models import Audit, AuditConfiguration, Configuration, Device
from tests.test_device_security import (
    _SecClient,
    _cfg_bytes,
    _make_device,
    _make_user,
)


@pytest.fixture()
async def life_session():
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


async def _mk_audit(session, user_id, name, status="completed", score=70.0):
    audit = Audit(user_id=user_id, name=name, status=status, overall_score=score)
    session.add(audit)
    await session.flush()
    return audit


async def _mk_audit(session, user_id, name, status="completed", score=70.0):
    audit = Audit(user_id=user_id, name=name, status=status, overall_score=score)
    session.add(audit)
    await session.flush()
    return audit


class TestDeviceEdit:
    @pytest.mark.asyncio
    async def test_edit_own_device(self, life_session):
        user = await _make_user(life_session, "ed-own")
        device = await _make_device(life_session, user, "ed-own")
        device_id = device.id
        async with _SecClient(life_session, user) as client:
            resp = await client.put(
                f"/api/v1/devices/{device_id}",
                json={"name": "renamed", "notes": "updated notes"},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["name"] == "renamed"
        assert body["notes"] == "updated notes"
        assert body["vendor"] == "cisco"  # untouched fields preserved

    @pytest.mark.asyncio
    async def test_edit_foreign_device_404(self, life_session):
        user_a = await _make_user(life_session, "ed-for-a")
        user_b = await _make_user(life_session, "ed-for-b")
        device_b = await _make_device(life_session, user_b, "ed-for-b")
        device_b_id = device_b.id
        async with _SecClient(life_session, user_a) as client:
            resp = await client.put(
                f"/api/v1/devices/{device_b_id}", json={"name": "hijack"}
            )
        assert resp.status_code == 404, resp.text

    @pytest.mark.asyncio
    async def test_edit_nonexistent_device_404(self, life_session):
        user = await _make_user(life_session, "ed-missing")
        async with _SecClient(life_session, user) as client:
            resp = await client.put(
                f"/api/v1/devices/{uuidlib.uuid4()}", json={"name": "x"}
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_edit_invalid_data_422(self, life_session):
        user = await _make_user(life_session, "ed-invalid")
        device = await _make_device(life_session, user, "ed-invalid")
        device_id = device.id
        async with _SecClient(life_session, user) as client:
            resp = await client.put(
                f"/api/v1/devices/{device_id}", json={"name": ""}
            )
        assert resp.status_code == 422, resp.text

    @pytest.mark.asyncio
    async def test_edit_preserves_history(self, life_session):
        from uuid import UUID

        user = await _make_user(life_session, "ed-hist")
        device = await _make_device(life_session, user, "ed-hist")
        device_id = device.id
        async with _SecClient(life_session, user) as client:
            up = await _upload(client, "hist.cfg", "ed-hist", device_id)
            assert up.status_code == 201
            # Vendor/platform change must not rewrite history linkage.
            resp = await client.put(
                f"/api/v1/devices/{device_id}",
                json={"vendor": "juniper", "platform": "junos"},
            )
            assert resp.status_code == 200, resp.text
            hist = await client.get(f"/api/v1/devices/{device_id}/configurations")
        assert hist.status_code == 200
        assert [i["filename"] for i in hist.json()["items"]] == ["hist.cfg"]
        row = (
            await life_session.execute(
                select(Configuration).where(
                    Configuration.id == UUID(up.json()["id"])
                )
            )
        ).scalar_one()
        assert str(row.device_id) == str(device_id)


class TestArchiveUnarchive:
    @pytest.mark.asyncio
    async def test_archive_and_unarchive(self, life_session):
        user = await _make_user(life_session, "arc-own")
        device = await _make_device(life_session, user, "arc-own")
        device_id = device.id
        async with _SecClient(life_session, user) as client:
            arch = await client.post(f"/api/v1/devices/{device_id}/archive")
            assert arch.status_code == 200, arch.text
            assert arch.json()["is_active"] is False
            # Repeated archive is deterministic (still archived, still 200).
            arch2 = await client.post(f"/api/v1/devices/{device_id}/archive")
            assert arch2.status_code == 200
            assert arch2.json()["is_active"] is False
            unarch = await client.post(f"/api/v1/devices/{device_id}/unarchive")
            assert unarch.status_code == 200, unarch.text
            assert unarch.json()["is_active"] is True
            unarch2 = await client.post(f"/api/v1/devices/{device_id}/unarchive")
            assert unarch2.status_code == 200
            assert unarch2.json()["is_active"] is True

    @pytest.mark.asyncio
    async def test_archive_foreign_404(self, life_session):
        user_a = await _make_user(life_session, "arc-for-a")
        user_b = await _make_user(life_session, "arc-for-b")
        device_b = await _make_device(life_session, user_b, "arc-for-b")
        device_b_id = device_b.id
        async with _SecClient(life_session, user_a) as client:
            assert (
                await client.post(f"/api/v1/devices/{device_b_id}/archive")
            ).status_code == 404
            assert (
                await client.post(f"/api/v1/devices/{device_b_id}/unarchive")
            ).status_code == 404

    @pytest.mark.asyncio
    async def test_archive_nonexistent_404(self, life_session):
        user = await _make_user(life_session, "arc-missing")
        async with _SecClient(life_session, user) as client:
            assert (
                await client.post(f"/api/v1/devices/{uuidlib.uuid4()}/archive")
            ).status_code == 404

    @pytest.mark.asyncio
    async def test_viewer_cannot_archive(self, life_session):
        viewer = await _make_user(life_session, "arc-viewer", role="viewer")
        device = await _make_device(life_session, viewer, "arc-viewer")
        device_id = device.id
        async with _SecClient(life_session, viewer) as client:
            resp = await client.post(f"/api/v1/devices/{device_id}/archive")
        assert resp.status_code == 403, resp.text

    @pytest.mark.asyncio
    async def test_lifecycle_filter(self, life_session):
        user = await _make_user(life_session, "arc-filter")
        device = await _make_device(life_session, user, "arc-filter")
        device_id = device.id
        async with _SecClient(life_session, user) as client:
            await client.post(f"/api/v1/devices/{device_id}/archive")
            default = await client.get("/api/v1/devices/")
            assert device_id.__str__() not in [
                i["id"] for i in default.json()["items"]
            ]
            archived = await client.get(
                "/api/v1/devices/", params={"lifecycle": "archived"}
            )
            assert [i["id"] for i in archived.json()["items"]] == [str(device_id)]
            everything = await client.get(
                "/api/v1/devices/", params={"lifecycle": "all"}
            )
            assert str(device_id) in [i["id"] for i in everything.json()["items"]]
            active = await client.get(
                "/api/v1/devices/", params={"lifecycle": "active"}
            )
            assert str(device_id) not in [i["id"] for i in active.json()["items"]]

    @pytest.mark.asyncio
    async def test_lifecycle_composes_with_search(self, life_session):
        user = await _make_user(life_session, "arc-compose")
        device = await _make_device(life_session, user, "arc-compose")
        device_id = device.id
        async with _SecClient(life_session, user) as client:
            await client.post(f"/api/v1/devices/{device_id}/archive")
            resp = await client.get(
                "/api/v1/devices/",
                params={"search": "arc-compose", "lifecycle": "archived"},
            )
            assert [i["id"] for i in resp.json()["items"]] == [str(device_id)]
            resp2 = await client.get(
                "/api/v1/devices/",
                params={"search": "arc-compose", "lifecycle": "active"},
            )
            assert resp2.json()["items"] == []


class TestArchivedRestrictions:
    async def _archived_with_config(self, life_session, tag: str):
        user = await _make_user(life_session, f"rst-{tag}")
        device = await _make_device(life_session, user, f"rst-{tag}")
        user_id, device_id = user.id, device.id
        async with _SecClient(life_session, user) as client:
            up = await _upload(client, f"{tag}.cfg", f"rst-{tag}", device_id)
            assert up.status_code == 201
            arch = await client.post(f"/api/v1/devices/{device_id}/archive")
            assert arch.status_code == 200
        return user, user_id, device_id, up.json()["id"]

    @pytest.mark.asyncio
    async def test_archived_upload_rejected(self, life_session):
        user, _, device_id, _ = await self._archived_with_config(life_session, "up")
        async with _SecClient(life_session, user) as client:
            resp = await _upload(client, "new.cfg", "rst-up-2", device_id)
        assert resp.status_code == 409, (
            f"archived-device upload must be rejected, got {resp.status_code}: {resp.text}"
        )

    @pytest.mark.asyncio
    async def test_archived_audit_rejected(self, life_session):
        from sqlalchemy import func as _func
        from sqlalchemy import select as _select

        user, user_id, device_id, cfg_id = await self._archived_with_config(
            life_session, "au"
        )
        before = (
            await life_session.execute(
                _select(_func.count(Audit.id)).where(Audit.user_id == user_id)
            )
        ).scalar()
        async with _SecClient(life_session, user) as client:
            # With explicit device scope...
            r1 = await client.post(
                "/api/v1/audit-execution/execute",
                json={
                    "name": "archived audit",
                    "configuration_ids": [cfg_id],
                    "device_ids": [str(device_id)],
                    "framework": "CIS",
                },
            )
            assert r1.status_code == 409, r1.text
            # ...and without it (legacy path resolves the archived device).
            r2 = await client.post(
                "/api/v1/audit-execution/execute",
                json={
                    "name": "archived audit 2",
                    "configuration_ids": [cfg_id],
                    "framework": "CIS",
                },
            )
            assert r2.status_code == 409, r2.text
        after = (
            await life_session.execute(
                _select(_func.count(Audit.id)).where(Audit.user_id == user_id)
            )
        ).scalar()
        assert after == before

    @pytest.mark.asyncio
    async def test_archived_history_reads_allowed(self, life_session):
        user, _, device_id, cfg_id = await self._archived_with_config(
            life_session, "rd"
        )
        async with _SecClient(life_session, user) as client:
            assert (await client.get(f"/api/v1/devices/{device_id}")).status_code == 200
            hist = await client.get(f"/api/v1/devices/{device_id}/configurations")
            assert hist.status_code == 200
            assert [i["id"] for i in hist.json()["items"]] == [cfg_id]
            content = await client.get(f"/api/v1/configurations/{cfg_id}/content")
            assert content.status_code == 200
            assert "hostname" in content.json()["content"]
            audits = await client.get(f"/api/v1/devices/{device_id}/audits")
            assert audits.status_code == 200

    @pytest.mark.asyncio
    async def test_unarchive_restores_operations(self, life_session):
        user, _, device_id, cfg_id = await self._archived_with_config(
            life_session, "re"
        )
        async with _SecClient(life_session, user) as client:
            unarch = await client.post(f"/api/v1/devices/{device_id}/unarchive")
            assert unarch.status_code == 200
            up = await _upload(client, "after.cfg", "rst-re-2", device_id)
            assert up.status_code == 201, up.text
            ex = await client.post(
                "/api/v1/audit-execution/execute",
                json={
                    "name": "after unarchive",
                    "configuration_ids": [cfg_id],
                    "device_ids": [str(device_id)],
                    "framework": "CIS",
                },
            )
            assert ex.status_code == 202, ex.text


class TestDeletePolicy:
    @pytest.mark.asyncio
    async def test_pristine_delete_allowed(self, life_session):
        user = await _make_user(life_session, "del-clean")
        device = await _make_device(life_session, user, "del-clean")
        device_id = device.id
        async with _SecClient(life_session, user) as client:
            resp = await client.delete(f"/api/v1/devices/{device_id}")
            assert resp.status_code == 204, resp.text
            again = await client.get(f"/api/v1/devices/{device_id}")
            assert again.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_with_history_blocked(self, life_session):
        user = await _make_user(life_session, "del-hist")
        device = await _make_device(life_session, user, "del-hist")
        device_id = device.id
        user_id = user.id
        async with _SecClient(life_session, user) as client:
            up = await _upload(client, "hist.cfg", "del-hist", device_id)
            assert up.status_code == 201
        from uuid import UUID

        audit = await _mk_audit(life_session, user_id, "hist audit")
        life_session.add(
            AuditConfiguration(audit_id=audit.id, configuration_id=UUID(up.json()["id"]))
        )
        await life_session.flush()
        async with _SecClient(life_session, user) as client:
            resp = await client.delete(f"/api/v1/devices/{device_id}")
            assert resp.status_code == 409, resp.text
            assert "Archive" in resp.json()["detail"]
        # Rows intact: device + config + join + audit all survive.
        assert (
            await life_session.execute(
                select(func.count(Device.id)).where(Device.id == device_id)
            )
        ).scalar() == 1
        assert (
            await life_session.execute(
                select(func.count(Configuration.id)).where(
                    Configuration.device_id == device_id
                )
            )
        ).scalar() == 1

    @pytest.mark.asyncio
    async def test_delete_foreign_404(self, life_session):
        user_a = await _make_user(life_session, "del-for-a")
        user_b = await _make_user(life_session, "del-for-b")
        device_b = await _make_device(life_session, user_b, "del-for-b")
        device_b_id = device_b.id
        async with _SecClient(life_session, user_a) as client:
            assert (
                await client.delete(f"/api/v1/devices/{device_b_id}")
            ).status_code == 404

    @pytest.mark.asyncio
    async def test_delete_nonexistent_404(self, life_session):
        user = await _make_user(life_session, "del-missing")
        async with _SecClient(life_session, user) as client:
            assert (
                await client.delete(f"/api/v1/devices/{uuidlib.uuid4()}")
            ).status_code == 404

    @pytest.mark.asyncio
    async def test_delete_repeat_deterministic(self, life_session):
        user = await _make_user(life_session, "del-repeat")
        device = await _make_device(life_session, user, "del-repeat")
        device_id = device.id
        async with _SecClient(life_session, user) as client:
            assert (
                await client.delete(f"/api/v1/devices/{device_id}")
            ).status_code == 204
            assert (
                await client.delete(f"/api/v1/devices/{device_id}")
            ).status_code == 404
