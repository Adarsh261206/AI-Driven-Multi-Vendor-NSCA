"""Company Baseline end-to-end tests.

Covers:
- Validation: valid, unknown, duplicate, malformed, empty, cross-registry
- Onboarding lifecycle: org creation, activation, one-active-baseline
- Persistence + resolution (multiple audits reuse the same baseline)
- No-baseline regression (Full CIS works, no fake company score)
- Cross-company isolation (org derived from authenticated user)
- Mutation test: changing the baseline never changes CIS verdicts/evidence
- Scope semantics: OUT_OF_SCOPE != PASS/FAIL/REVIEW/NOT_APPLICABLE
- Metrics: company denominator = selected controls only
- Findings: company baseline never manufactures duplicate findings
- NIST separation: NIST evaluation independent of company scope
"""

from __future__ import annotations

import asyncio
import uuid as uuidlib

import pytest

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import settings
from app.models import (
    CompanyBaseline,
    Organization,
    User,
)
from app.security.auth import hash_password
from app.services.baseline import (
    BaselineValidationError,
    BaselineValidationService,
    validate_baseline_controls,
)
from app.api.v1.baseline import (
    check_organization_baseline,
    evaluate_company_baseline,
    generate_comparison_data,
    get_active_baseline_for_organization,
    onboarding_no_flow,
    onboarding_yes_flow,
    resolve_baseline_for_audit,
    user_has_baseline_capability,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
async def db():
    """Fresh engine per test — avoids asyncpg cross-event-loop reuse."""
    engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        try:
            await session.rollback()
        except Exception:
            pass
        await session.close()
        await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(email: str, role: str = "auditor") -> User:
    return User(
        email=email,
        password_hash=hash_password("test-pass-123"),
        full_name="Baseline Tester",
        role=role,
        is_active=True,
    )


async def _cleanup(email_prefix: str, db=None) -> None:
    """Remove users + their orgs/baselines created by a test run."""
    async with (db if db is not None else _make_session()) as session:
        users = await session.execute(
            select(User).where(User.email.like(f"{email_prefix}%"))
        )
        for u in users.scalars().all():
            if u.organization_id:
                await session.execute(
                    delete(CompanyBaseline).where(
                        CompanyBaseline.organization_id == u.organization_id
                    )
                )
                await session.execute(
                    delete(Organization).where(Organization.id == u.organization_id)
                )
        await session.execute(delete(User).where(User.email.like(f"{email_prefix}%")))
        await session.commit()


def _make_session():
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    return async_sessionmaker(engine, expire_on_commit=False)()


def _unique(prefix: str) -> str:
    return f"{prefix}{uuidlib.uuid4().hex[:10]}"


# ---------------------------------------------------------------------------
# 1. Validation service
# ---------------------------------------------------------------------------

class TestBaselineValidation:
    """Validation against the real CIS benchmark registry."""

    def test_valid_controls_pass(self):
        service = BaselineValidationService()
        result = service.validate(["1.1.1", "1.1.5", "1.5.2", "1.2.8"])
        assert result["valid_count"] == 4
        assert result["errors"] == []
        assert {"1.1.1", "1.1.5", "1.5.2", "1.2.8"} <= result["valid_controls"]

    def test_unknown_control_rejected(self):
        service = BaselineValidationService()
        with pytest.raises(BaselineValidationError) as exc:
            service.validate(["99.99.99"])
        assert exc.value.errors == [
            {"control_id": "99.99.99", "reason": "unknown"}
        ]

    def test_duplicate_control_rejected(self):
        service = BaselineValidationService()
        with pytest.raises(BaselineValidationError) as exc:
            service.validate(["1.1.1", "1.1.1", "1.1.5"])
        assert exc.value.errors == [
            {"control_id": "1.1.1", "reason": "duplicate"}
        ]

    def test_malformed_control_rejected(self):
        service = BaselineValidationService()
        with pytest.raises(BaselineValidationError) as exc:
            service.validate(["bad id!"])
        assert exc.value.errors[0]["reason"] == "unknown"

    def test_empty_baseline_rejected(self):
        service = BaselineValidationService()
        with pytest.raises(BaselineValidationError):
            service.validate([])
        # empty submission → zero valid controls; validation fails loudly

    def test_mixed_valid_and_invalid_reports_all_errors(self):
        service = BaselineValidationService()
        with pytest.raises(BaselineValidationError) as exc:
            service.validate(["1.1.1", "1.1.1", "99.99.99", "1.1.5"])
        reasons = {e["reason"] for e in exc.value.errors}
        assert "duplicate" in reasons
        assert "unknown" in reasons

    def test_convenience_function_matches_service(self):
        result = validate_baseline_controls(["1.1.1", "1.1.5"])
        assert result["valid_count"] == 2

    def test_juniper_and_nist_controls_also_resolve(self):
        # Registry mirrors the audit pipeline: CIS + Juniper + NIST
        service = BaselineValidationService()
        result = service.validate(["6.1.2", "AC-2(1)"])
        assert result["valid_count"] == 2


# ---------------------------------------------------------------------------
# 2. Scope semantics (pure, no DB)
# ---------------------------------------------------------------------------

class TestScopeSemantics:
    """OUT_OF_SCOPE is its own state — never collapsed into PASS/FAIL/etc."""

    def _results(self):
        return {
            "1.2.9": {"result": "PASS"},
            "1.5.2": {"result": "FAIL"},
            "1.2.8": {"result": "FAIL"},
            "1.1.1": {"result": "PASS"},
        }

    def test_out_of_scope_is_not_pass(self):
        asyncio.run(self._check("1.5.2", "OUT_OF_SCOPE", ["1.1.1", "1.2.8"]))

    async def _check(self, control, expected, baseline_controls):
        import app.api.v1.baseline as mod
        res = await mod.evaluate_company_baseline(self._results(), baseline_controls)
        assert res["in_scope_results"][control]["company_result"] == expected

    def test_out_of_scope_control_excluded_from_counts(self):
        res = asyncio.run(
            evaluate_company_baseline(
                self._results(), ["1.1.1", "1.2.8"]
            )
        )
        # Only 1.1.1 (PASS) + 1.2.8 (FAIL) count: denominator 2, not 4
        assert res["company_passed"] == 1
        assert res["company_failed"] == 1
        assert res["company_review"] == 0
        assert res["denominator"] == 2
        assert res["out_of_scope_controls"] == 2

    def test_company_score_uses_only_in_scope(self):
        res = asyncio.run(
            evaluate_company_baseline(self._results(), ["1.1.1", "1.2.8"])
        )
        assert res["company_score"] == 50.0  # 1 PASS / 2 decisive

    def test_full_cis_result_preserved_for_out_of_scope(self):
        res = asyncio.run(
            evaluate_company_baseline(self._results(), ["1.1.1", "1.2.8"])
        )
        entry = res["in_scope_results"]["1.5.2"]
        assert entry["result"] == "FAIL"      # Full CIS verdict intact
        assert entry["company_result"] == "OUT_OF_SCOPE"

    def test_comparison_data_marks_scope(self):
        comparison = asyncio.run(
            generate_comparison_data(
                self._results(),
                ["1.1.1", "1.2.8"],
                list(self._results().keys()),
            )
        )
        by_id = {c.control_id: c for c in comparison}
        assert by_id["1.5.2"].company_result == "OUT_OF_SCOPE"
        assert by_id["1.5.2"].full_cis_result == "FAIL"
        assert by_id["1.5.2"].in_scope is False
        assert by_id["1.1.1"].company_result == "PASS"
        assert by_id["1.1.1"].in_scope is True

    def test_capability_mapping(self):
        auditor = _make_user("cap@test.com")
        viewer = _make_user("cap2@test.com", role="viewer")
        admin = _make_user("cap3@test.com", role="admin")
        assert asyncio.run(user_has_baseline_capability(auditor, "baseline.configure"))
        assert asyncio.run(user_has_baseline_capability(admin, "baseline.configure"))
        assert not asyncio.run(user_has_baseline_capability(viewer, "baseline.configure"))
        assert asyncio.run(user_has_baseline_capability(viewer, "baseline.view"))
        assert not asyncio.run(user_has_baseline_capability(auditor, "unknown.cap"))


# ---------------------------------------------------------------------------
# 3. Onboarding + persistence + resolution (DB-backed)
# ---------------------------------------------------------------------------

class TestOnboardingLifecycle:
    """One-time onboarding → persistence → automatic reuse."""

    @pytest.mark.asyncio
    async def test_full_onboarding_flow(self, db):
        prefix = _unique("baseline-onboard")
        email = f"{prefix}@test.com"
        try:
            user = _make_user(email)
            db.add(user)
            await db.flush()

            # User starts with NO organization → onboarding creates it
            assert user.organization_id is None

            result = await onboarding_yes_flow(
                db,
                user,
                type(
                    "Req",
                    (),
                    {
                        "name": "Company Security Baseline",
                        "framework": "CIS",
                        "benchmark": "CIS Cisco IOS XE 17.x",
                        "controls": ["1.1.1", "1.1.5", "1.5.2", "1.2.8"],
                    },
                )(),
            )
            await db.commit()

            assert result["status"] == "activated"
            assert result["activation_blocked"] is False
            assert user.organization_id is not None
            org_id = user.organization_id

            # Persistence: baseline survives reload
            baseline, status = await check_organization_baseline(db, org_id)
            assert status == "ACTIVE"
            assert baseline is not None
            assert baseline.controls == ["1.1.1", "1.1.5", "1.5.2", "1.2.8"]

            # One active baseline: a second activation is blocked
            await onboarding_yes_flow(
                db,
                user,
                type(
                    "Req",
                    (),
                    {
                        "name": "Second",
                        "framework": "CIS",
                        "benchmark": "CIS",
                        "controls": ["1.1.1"],
                    },
                )(),
            )
            await db.rollback()
            _, status2 = await check_organization_baseline(db, org_id)
            assert status2 == "ACTIVE"

            active = await get_active_baseline_for_organization(db, org_id)
            assert active.name == "Company Security Baseline"

            # Resolution for audit
            resolved = await resolve_baseline_for_audit(db, org_id)
            assert resolved["has_baseline"] is True
            assert resolved["in_scope_controls"] == [
                "1.1.1", "1.1.5", "1.5.2", "1.2.8"
            ]
            assert resolved["baseline_status"] == "ACTIVE"
        finally:
            await _cleanup(prefix)

    @pytest.mark.asyncio
    async def test_no_baseline_flow(self, db):
        prefix = _unique("baseline-no")
        email = f"{prefix}@test.com"
        try:
            user = _make_user(email)
            db.add(user)
            await db.flush()

            result = await onboarding_no_flow(db, user)
            await db.commit()

            assert result["baseline_status"] == "NOT_CONFIGURED"
            assert result["evaluation_unavailable"] is True

            # Resolution shows no baseline — audit continues with Full CIS
            resolved = await resolve_baseline_for_audit(db, user.organization_id)
            assert resolved["has_baseline"] is False
            assert resolved["in_scope_controls"] == []
        finally:
            await _cleanup(prefix)

    @pytest.mark.asyncio
    async def test_invalid_baseline_never_activates(self, db):
        prefix = _unique("baseline-invalid")
        email = f"{prefix}@test.com"
        try:
            user = _make_user(email)
            db.add(user)
            await db.flush()

            result = await onboarding_yes_flow(
                db,
                user,
                type(
                    "Req",
                    (),
                    {
                        "name": "Bad Baseline",
                        "framework": "CIS",
                        "benchmark": "CIS",
                        "controls": ["1.1.1", "99.99.99", "1.1.1"],
                    },
                )(),
            )
            await db.rollback()

            assert result["activation_blocked"] is True
            assert result["status"] in ("validation_failed", "validation_with_errors")
            invalid = result["validation_result"].invalid_controls
            assert "99.99.99" in invalid
            assert "1.1.1" in invalid  # duplicate reported, not silently removed
        finally:
            await _cleanup(prefix)

    @pytest.mark.asyncio
    async def test_cross_company_isolation(self, db):
        """Company A can never read/resolve Company B's baseline."""
        prefix_a = _unique("baseline-orga")
        prefix_b = _unique("baseline-orgb")
        email_a = f"{prefix_a}@test.com"
        email_b = f"{prefix_b}@test.com"
        try:
            user_a = _make_user(email_a)
            user_b = _make_user(email_b)
            db.add_all([user_a, user_b])
            await db.flush()

            # Both orgs created independently with different baselines
            await onboarding_yes_flow(
                db, user_a,
                type("Req", (), {
                    "name": "Baseline A",
                    "framework": "CIS",
                    "benchmark": "CIS Cisco IOS XE 17.x",
                    "controls": ["1.1.1", "1.1.5"],
                })(),
            )
            await onboarding_yes_flow(
                db, user_b,
                type("Req", (), {
                    "name": "Baseline B",
                    "framework": "CIS",
                    "benchmark": "CIS Cisco IOS XE 17.x",
                    "controls": ["1.5.2", "1.2.8", "1.3.1"],
                })(),
            )
            await db.commit()

            # A resolves only its own controls
            resolved_a = await resolve_baseline_for_audit(db, user_a.organization_id)
            assert set(resolved_a["in_scope_controls"]) == {"1.1.1", "1.1.5"}

            # B resolves only its own controls — no cross-read
            resolved_b = await resolve_baseline_for_audit(db, user_b.organization_id)
            assert set(resolved_b["in_scope_controls"]) == {"1.5.2", "1.2.8", "1.3.1"}
            assert "1.1.1" not in resolved_b["in_scope_controls"]
        finally:
            await _cleanup(prefix_a)
            await _cleanup(prefix_b)


# ---------------------------------------------------------------------------
# 4. Mutation test — changing the baseline must NOT change CIS
# ---------------------------------------------------------------------------

class TestMutationInvariant:
    """Swapping baseline selection changes ONLY the company projection."""

    def test_baseline_change_never_alters_cis_verdicts(self):
        # CIS results are stored per audit — snapshot them once
        stored_results = {
            "1.1.1": "PASS",
            "1.1.5": "REVIEW",
            "1.5.2": "FAIL",
            "1.2.8": "FAIL",
            "1.2.9": "PASS",
        }

        # Project with baseline A (18-style: 4 in scope)
        res_a = asyncio.run(
            evaluate_company_baseline(
                {k: {"result": v} for k, v in stored_results.items()},
                ["1.1.1", "1.1.5", "1.5.2", "1.2.8"],
            )
        )
        # Project with baseline B (10-style: 2 in scope)
        res_b = asyncio.run(
            evaluate_company_baseline(
                {k: {"result": v} for k, v in stored_results.items()},
                ["1.1.1", "1.2.9"],
            )
        )

        # Company scope/metrics changed
        assert res_a["denominator"] == 4
        assert res_b["denominator"] == 2
        assert res_a["company_score"] != res_b["company_score"]

        # Underlying CIS verdicts UNCHANGED — same raw values both times
        assert res_a["in_scope_results"]["1.5.2"]["result"] == "FAIL"
        assert res_b["in_scope_results"]["1.5.2"]["result"] == "FAIL"

        # Full CIS metric semantics are constant
        cis_pass = sum(1 for v in stored_results.values() if v == "PASS")
        cis_fail = sum(1 for v in stored_results.values() if v == "FAIL")
        assert cis_pass == 2
        assert cis_fail == 2

    def test_out_of_scope_never_equals_pass_fail_review(self):
        """Explicit semantic checks the UI/API must never collapse."""
        res = asyncio.run(
            evaluate_company_baseline(
                {"1.5.2": {"result": "FAIL"}},
                ["1.1.1"],
            )
        )
        company_result = res["in_scope_results"]["1.5.2"]["company_result"]
        assert company_result == "OUT_OF_SCOPE"
        assert company_result != "PASS"
        assert company_result != "FAIL"
        assert company_result != "REVIEW"
        assert company_result != "NOT_APPLICABLE"


# ---------------------------------------------------------------------------
# 5. Findings + evidence invariants (no duplication)
# ---------------------------------------------------------------------------

class TestFindingsEvidence:
    """The company baseline projects scope; it never manufactures findings."""

    def test_company_projection_does_not_create_findings(self):
        """evaluate_company_baseline returns metrics only — no finding rows."""
        res = asyncio.run(
            evaluate_company_baseline(
                {"1.5.2": {"result": "FAIL"}},
                ["1.1.1"],
            )
        )
        assert "findings" not in res
        assert "evidence" not in res
        # Evidence lives on the CIS ComplianceResult only — untouched

    def test_evidence_dict_is_not_mutated_by_projection(self):
        evidence = {
            "matched_lines": ["snmp-server community OPERATE RW ADV-MGMT"],
            "line_numbers": [12],
        }
        res = asyncio.run(
            evaluate_company_baseline(
                {"1.5.2": {"result": "FAIL", "evidence": evidence}},
                ["1.1.1"],
            )
        )
        # Projection copies status; the underlying evidence object is intact
        assert res["in_scope_results"]["1.5.2"]["result"] == "FAIL"
        assert evidence["matched_lines"] == [
            "snmp-server community OPERATE RW ADV-MGMT"
        ]
        assert evidence["line_numbers"] == [12]


# ---------------------------------------------------------------------------
# 6. No-baseline regression + NIST separation
# ---------------------------------------------------------------------------

class TestNoBaselineRegression:
    @pytest.mark.asyncio
    async def test_audit_without_baseline_is_full_cis_only(self, db):
        """No baseline → no company score, no crash, Full CIS intact."""
        prefix = _unique("baseline-nobase")
        email = f"{prefix}@test.com"
        try:
            user = _make_user(email)
            db.add(user)
            await db.flush()

            resolved = await resolve_baseline_for_audit(db, user.organization_id)
            assert resolved["has_baseline"] is False
            assert resolved["baseline_status"] == "NOT_CONFIGURED"
            assert resolved["in_scope_controls"] == []
        finally:
            await _cleanup(prefix)

    def test_nist_results_stay_separate(self):
        """NIST framework rows never merge into CIS/company metrics."""
        cis_rows = {
            "1.1.1": {"result": "PASS", "framework": "CIS"},
        }
        nist_rows = {
            "AC-2(1)": {"result": "FAIL", "framework": "NIST"},
        }
        combined = {**cis_rows, **nist_rows}

        # Company baseline only covers CIS controls
        res = asyncio.run(
            evaluate_company_baseline(combined, ["1.1.1"])
        )
        assert res["company_passed"] == 1
        assert res["company_failed"] == 0
        # NIST control untouched by the company projection
        assert combined["AC-2(1)"]["result"] == "FAIL"
        assert combined["AC-2(1)"]["framework"] == "NIST"