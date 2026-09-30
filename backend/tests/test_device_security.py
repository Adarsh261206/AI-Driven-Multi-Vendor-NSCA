"""Device/configuration ownership security regression tests (STEP 1).

Matrix (USER A: Device A + Configuration A, USER B: Device B + Config B):

- A uploads using Device A → PASS (201)
- A uploads using Device B → REJECT (403/404, never 201)
- B uploads using Device A → REJECT
- A audits Configuration A → PASS (202, audit created)
- A audits Configuration B → REJECT (no audit created)
- A audits [A + B] → ENTIRE REQUEST REJECTED (audit count unchanged)
- A lists Device A configurations → only A's data
- A requests Device B configurations → REJECT (403)

Direct API calls only — no frontend restrictions involved.
Uses the throwaway engine_validation_test DB + ASGI transport with
dependency overrides (same pattern as tests/validation/test_v01_ingestion).
"""

from __future__ import annotations

import uuid as uuidlib

import pytest


@pytest.fixture()
async def sec_session():
    """Throwaway-DB session; skips when schema is not provisioned."""
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


class _SecClient:
    """ASGI client bound to one user + one throwaway-DB session."""

    def __init__(self, session, user):
        self.session = session
        self.user = user
        self.client = None

    async def __aenter__(self):
        import httpx
        from httpx import ASGITransport

        from app.database import get_db
        from app.main import app
        from app.security.auth import get_current_user

        session = self.session
        user = self.user

        async def _test_db():
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

        async def _test_user():
            # A rejected request rolls the shared session back, which
            # expires this ORM object. Refresh per request so attribute
            # access inside endpoints never hits expired state.
            # (Production is unaffected: real requests load a fresh user
            # in a fresh session.)
            try:
                await session.refresh(user)
            except Exception:
                pass
            return user

        app.dependency_overrides[get_db] = _test_db
        app.dependency_overrides[get_current_user] = _test_user
        try:
            self.client = httpx.AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            )
            await self.client.__aenter__()
        except Exception:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(get_current_user, None)
            raise
        return self.client

    async def __aexit__(self, exc_type, exc, tb):
        from app.database import get_db
        from app.main import app
        from app.security.auth import get_current_user

        try:
            if self.client is not None:
                await self.client.__aexit__(exc_type, exc, tb)
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(get_current_user, None)


async def _make_user(session, tag: str, role: str = "auditor"):
    from app.models import User

    user = User(
        id=uuidlib.uuid4(),
        email=f"sec-{tag}-{uuidlib.uuid4().hex[:8]}@test.local",
        password_hash="x",
        role=role,
        is_active=True,
    )
    session.add(user)
    await session.flush()
    return user


async def _make_device(session, user, tag: str):
    from app.models import Device

    device = Device(
        user_id=user.id,
        name=f"sec-device-{tag}",
        vendor="cisco",
        platform="ios_xe",
    )
    session.add(device)
    await session.flush()
    return device


async def _upload_as(client, filename: str, content: bytes, device_id=None):
    files = {"file": (filename, content, "text/plain")}
    params = {}
    if device_id is not None:
        params["device_id"] = str(device_id)
    return await client.post(
        "/api/v1/configurations/upload", files=files, params=params
    )


def _cfg_bytes(tag: str) -> bytes:
    # Unique nonce per call: content-hash dedup would otherwise replay a
    # stale row (linked to a previous run's device) on repeat runs.
    nonce = uuidlib.uuid4().hex[:8]
    return (
        f"hostname SEC-{tag}-{nonce}\n"
        "!\n"
        "interface GigabitEthernet0/0\n"
        " ip address 10.0.0.1 255.255.255.0\n"
        " no shutdown\n"
        "!\n"
        "line vty 0 4\n"
        " transport input ssh\n"
    ).encode()


async def _audit_count(session, user_id) -> int:
    from sqlalchemy import func, select

    from app.models import Audit

    return (
        await session.execute(
            select(func.count(Audit.id)).where(Audit.user_id == user_id)
        )
    ).scalar()


class TestUploadDeviceOwnership:
    """POST /configurations/upload?device_id= — ownership enforced."""

    @pytest.mark.asyncio
    async def test_upload_with_own_device_succeeds(self, sec_session):
        user_a = await _make_user(sec_session, "up-own-a")
        device_a = await _make_device(sec_session, user_a, "up-own-a")
        async with _SecClient(sec_session, user_a) as client:
            resp = await _upload_as(
                client, "own.cfg", _cfg_bytes("up-own-a"), device_id=device_a.id
            )
        assert resp.status_code == 201, resp.text
        assert resp.json()["id"]

    @pytest.mark.asyncio
    async def test_device_id_binds_only_via_query_param(self, sec_session):
        """STEP 7.5 D-B1: the backend contract binds device_id from the
        query string. A device_id smuggled as a multipart form field is
        ignored — the row persists UNLINKED rather than binding wrongly.
        Frontend clients must send ?device_id= (query)."""
        from sqlalchemy import select

        from app.models import Configuration

        user_a = await _make_user(sec_session, "up-transport")
        device_a = await _make_device(sec_session, user_a, "up-transport")
        async with _SecClient(sec_session, user_a) as client:
            resp = await client.post(
                "/api/v1/configurations/upload",
                files={"file": ("transport.cfg", _cfg_bytes("up-transport"), "text/plain")},
                data={"device_id": str(device_a.id)},
            )
            assert resp.status_code == 201, resp.text
            row = (
                await sec_session.execute(
                    select(Configuration).where(
                        Configuration.id == resp.json()["id"]
                    )
                )
            ).scalar_one()
            assert row.device_id is None
            # ...and therefore invisible to the device history endpoint.
            hist = await client.get(f"/api/v1/devices/{device_a.id}/configurations")
            assert hist.status_code == 200
            assert hist.json()["items"] == []

    @pytest.mark.asyncio
    async def test_identical_content_across_devices_stored_per_device(self, sec_session):
        """Fleet rule: same bytes on Device A, uploaded for Device B
        (same owner) -> 201 with a NEW row for Device B. Identical
        golden configs across many switches are legitimate; dedup is
        scoped to (device, content), never global.
        """
        user = await _make_user(sec_session, "up-fleet-same")
        device_a = await _make_device(sec_session, user, "up-fleet-a")
        device_b = await _make_device(sec_session, user, "up-fleet-b")
        dev_a_id, dev_b_id = device_a.id, device_b.id  # capture before contexts expire state
        shared = _cfg_bytes("up-fleet-shared")
        async with _SecClient(sec_session, user) as client:
            first = await _upload_as(client, "shared.cfg", shared, device_id=dev_a_id)
            assert first.status_code == 201, first.text
            second = await _upload_as(client, "shared-copy.cfg", shared, device_id=dev_b_id)
            assert second.status_code == 201, second.text
            assert first.json()["id"] != second.json()["id"]
            # Each device history shows its own row.
            for dev_id in (dev_a_id, dev_b_id):
                hist = await client.get(f"/api/v1/devices/{dev_id}/configurations")
                assert hist.status_code == 200
                assert len(hist.json()["items"]) == 1

    @pytest.mark.asyncio
    async def test_identical_content_cross_user_no_leak(self, sec_session):
        """Same bytes owned by another user, uploaded to my device ->
        201 with my own row. No cross-device linkage, no identity leak."""
        user_a = await _make_user(sec_session, "up-fleet-xa")
        user_b = await _make_user(sec_session, "up-fleet-xb")
        device_a = await _make_device(sec_session, user_a, "up-fleet-xa")
        device_b = await _make_device(sec_session, user_b, "up-fleet-xb")
        dev_a_id, dev_b_id = device_a.id, device_b.id  # capture before contexts expire state
        shared = _cfg_bytes("up-fleet-shared-x")
        async with _SecClient(sec_session, user_a) as client_a:
            assert (
                await _upload_as(client_a, "x.cfg", shared, device_id=dev_a_id)
            ).status_code == 201
        async with _SecClient(sec_session, user_b) as client_b:
            resp = await _upload_as(client_b, "x-copy.cfg", shared, device_id=dev_b_id)
            assert resp.status_code == 201, resp.text
            hist = await client_b.get(f"/api/v1/devices/{dev_b_id}/configurations")
            assert hist.status_code == 200
            assert len(hist.json()["items"]) == 1
            assert hist.json()["items"][0]["id"] == resp.json()["id"]

    @pytest.mark.asyncio
    async def test_duplicate_content_same_device_replays(self, sec_session):
        """Same bytes, same device -> unchanged 201 idempotent replay."""
        user = await _make_user(sec_session, "up-dupe-replay")
        device = await _make_device(sec_session, user, "up-dupe-replay")
        shared = _cfg_bytes("up-dupe-replay-shared")
        async with _SecClient(sec_session, user) as client:
            first = await _upload_as(client, "r.cfg", shared, device_id=device.id)
            second = await _upload_as(client, "r-again.cfg", shared, device_id=device.id)
            assert first.status_code == 201 and second.status_code == 201
            assert first.json()["id"] == second.json()["id"]

    @pytest.mark.asyncio
    async def test_upload_with_foreign_device_rejected(self, sec_session):
        user_a = await _make_user(sec_session, "up-for-a")
        user_b = await _make_user(sec_session, "up-for-b")
        device_b = await _make_device(sec_session, user_b, "up-for-b")
        async with _SecClient(sec_session, user_a) as client:
            resp = await _upload_as(
                client, "foreign.cfg", _cfg_bytes("up-for"), device_id=device_b.id
            )
        assert resp.status_code in (403, 404), (
            f"foreign device upload must be rejected, got {resp.status_code}: {resp.text}"
        )

    @pytest.mark.asyncio
    async def test_upload_with_foreign_device_rejected_reverse(self, sec_session):
        user_a = await _make_user(sec_session, "up-rev-a")
        user_b = await _make_user(sec_session, "up-rev-b")
        device_a = await _make_device(sec_session, user_a, "up-rev-a")
        async with _SecClient(sec_session, user_b) as client:
            resp = await _upload_as(
                client, "foreign2.cfg", _cfg_bytes("up-rev"), device_id=device_a.id
            )
        assert resp.status_code in (403, 404), (
            f"foreign device upload must be rejected, got {resp.status_code}: {resp.text}"
        )

    @pytest.mark.asyncio
    async def test_upload_with_nonexistent_device_rejected(self, sec_session):
        # Established contract (V01-62): the engine owns the
        # nonexistent-device case with its typed 400 — preserved as-is.
        user_a = await _make_user(sec_session, "up-missing")
        async with _SecClient(sec_session, user_a) as client:
            resp = await _upload_as(
                client, "missing.cfg", _cfg_bytes("up-missing"),
                device_id=uuidlib.uuid4(),
            )
        assert resp.status_code == 400, (
            f"nonexistent device must stay engine-400, got {resp.status_code}: {resp.text}"
        )
        assert "does not identify an existing device" in resp.json().get("detail", "")


class TestAuditConfigurationOwnership:
    """Audit endpoints reject foreign configs atomically — no partial audit."""

    async def _seed_pair(self, sec_session, tag: str):
        """Two users, each with own device + own config (uploaded as owner)."""
        user_a = await _make_user(sec_session, f"{tag}-a")
        user_b = await _make_user(sec_session, f"{tag}-b")
        device_a = await _make_device(sec_session, user_a, f"{tag}-a")
        device_b = await _make_device(sec_session, user_b, f"{tag}-b")
        async with _SecClient(sec_session, user_a) as client_a:
            resp_a = await _upload_as(
                client_a, f"{tag}-a.cfg", _cfg_bytes(f"{tag}-a"),
                device_id=device_a.id,
            )
            assert resp_a.status_code == 201, resp_a.text
            config_a = resp_a.json()["id"]
        async with _SecClient(sec_session, user_b) as client_b:
            resp_b = await _upload_as(
                client_b, f"{tag}-b.cfg", _cfg_bytes(f"{tag}-b"),
                device_id=device_b.id,
            )
            assert resp_b.status_code == 201, resp_b.text
            config_b = resp_b.json()["id"]
        return user_a, user_b, config_a, config_b

    @pytest.mark.asyncio
    async def test_audit_own_config_accepted_execute(self, sec_session):
        user_a, _, config_a, _ = await self._seed_pair(sec_session, "au-own")
        async with _SecClient(sec_session, user_a) as client:
            resp = await client.post(
                "/api/v1/audit-execution/execute",
                json={
                    "name": "own-config audit",
                    "configuration_ids": [config_a],
                    "framework": "CIS",
                },
            )
        assert resp.status_code == 202, resp.text
        assert resp.json()["id"]

    @pytest.mark.asyncio
    async def test_audit_own_config_accepted_create(self, sec_session):
        user_a, _, config_a, _ = await self._seed_pair(sec_session, "au-create")
        async with _SecClient(sec_session, user_a) as client:
            resp = await client.post(
                "/api/v1/audits/",
                json={
                    "name": "own-config audit",
                    "configuration_ids": [config_a],
                    "framework": "CIS",
                },
            )
        assert resp.status_code == 202, resp.text

    @pytest.mark.asyncio
    async def test_audit_foreign_config_rejected_execute(self, sec_session):
        user_a, _, _, config_b = await self._seed_pair(sec_session, "au-for")
        user_a_id = user_a.id  # capture: session state expires across contexts
        before = await _audit_count(sec_session, user_a_id)
        async with _SecClient(sec_session, user_a) as client:
            resp = await client.post(
                "/api/v1/audit-execution/execute",
                json={
                    "name": "foreign-config audit",
                    "configuration_ids": [config_b],
                    "framework": "CIS",
                },
            )
        assert resp.status_code in (403, 404), (
            f"foreign config audit must be rejected, got {resp.status_code}: {resp.text}"
        )
        assert await _audit_count(sec_session, user_a_id) == before

    @pytest.mark.asyncio
    async def test_audit_mixed_configs_atomically_rejected(self, sec_session):
        user_a, _, config_a, config_b = await self._seed_pair(sec_session, "au-mix")
        user_a_id = user_a.id  # capture: session state expires across contexts
        before = await _audit_count(sec_session, user_a_id)
        async with _SecClient(sec_session, user_a) as client:
            resp = await client.post(
                "/api/v1/audit-execution/execute",
                json={
                    "name": "mixed-config audit",
                    "configuration_ids": [config_a, config_b],
                    "framework": "CIS",
                },
            )
        assert resp.status_code in (403, 404), (
            f"mixed authorized+unauthorized must reject ENTIRE request, "
            f"got {resp.status_code}: {resp.text}"
        )
        assert await _audit_count(sec_session, user_a_id) == before, (
            "no partial audit may be created on rejection"
        )

    @pytest.mark.asyncio
    async def test_audit_mixed_configs_atomically_rejected_create(self, sec_session):
        user_a, _, config_a, config_b = await self._seed_pair(sec_session, "au-mixc")
        user_a_id = user_a.id  # capture: session state expires across contexts
        before = await _audit_count(sec_session, user_a_id)
        async with _SecClient(sec_session, user_a) as client:
            resp = await client.post(
                "/api/v1/audits/",
                json={
                    "name": "mixed-config audit",
                    "configuration_ids": [config_a, config_b],
                    "framework": "CIS",
                },
            )
        assert resp.status_code in (403, 404), (
            f"mixed authorized+unauthorized must reject ENTIRE request, "
            f"got {resp.status_code}: {resp.text}"
        )
        assert await _audit_count(sec_session, user_a_id) == before


class TestConfigListOwnership:
    """GET /configurations?device_id= — foreign filter rejected."""

    @pytest.mark.asyncio
    async def test_list_own_device_configs(self, sec_session):

        user_a = await _make_user(sec_session, "ls-own-a")
        user_b = await _make_user(sec_session, "ls-own-b")
        device_a = await _make_device(sec_session, user_a, "ls-own-a")
        await _make_device(sec_session, user_b, "ls-own-b")
        async with _SecClient(sec_session, user_a) as client:
            up = await _upload_as(
                client, "ls-own.cfg", _cfg_bytes("ls-own"), device_id=device_a.id
            )
            assert up.status_code == 201, up.text
            config_id = up.json()["id"]
            resp = await client.get(
                "/api/v1/configurations/", params={"device_id": str(device_a.id)}
            )
        assert resp.status_code == 200, resp.text
        ids = [c["id"] for c in resp.json()["items"]]
        assert ids == [config_id]

    @pytest.mark.asyncio
    async def test_list_foreign_device_configs_rejected(self, sec_session):
        user_a = await _make_user(sec_session, "ls-for-a")
        user_b = await _make_user(sec_session, "ls-for-b")
        device_b = await _make_device(sec_session, user_b, "ls-for-b")
        async with _SecClient(sec_session, user_b) as client_b:
            up = await _upload_as(
                client_b, "ls-for.cfg", _cfg_bytes("ls-for"), device_id=device_b.id
            )
            assert up.status_code == 201, up.text
        async with _SecClient(sec_session, user_a) as client_a:
            resp = await client_a.get(
                "/api/v1/configurations/", params={"device_id": str(device_b.id)}
            )
        assert resp.status_code in (403, 404), (
            f"foreign device filter must be rejected, got {resp.status_code}: {resp.text}"
        )

    @pytest.mark.asyncio
    async def test_unlinked_configs_hidden_from_non_admin(self, sec_session):
        """Documents established read semantics: get/content 403 NULL-device
        configs for non-admins — list must not widen that."""
        user_a = await _make_user(sec_session, "ls-null")
        async with _SecClient(sec_session, user_a) as client:
            up = await _upload_as(client, "ls-null.cfg", _cfg_bytes("ls-null"))
            assert up.status_code == 201, up.text
            config_id = up.json()["id"]
            resp = await client.get(f"/api/v1/configurations/{config_id}")
        assert resp.status_code == 403, (
            f"unlinked config must be 403 for non-admin, got {resp.status_code}"
        )
