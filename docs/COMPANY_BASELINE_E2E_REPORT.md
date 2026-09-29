# COMPANY BASELINE E2E VERIFICATION REPORT

Verified end-to-end: USER → FRONTEND → API → AUTHORIZATION → ORGANIZATION BASELINE →
PERSISTENCE → AUTOMATIC AUDIT RESOLUTION → CIS EVALUATION → COMPANY SCOPE → FULL CIS →
NIST → EVIDENCE → FINDINGS → METRICS → REPORT.

## 1. Architecture Inspection

**Frontend**
- Company Baseline page: **MISSING** → now IMPLEMENTED (`frontend/app/settings/baseline/page.tsx`)
- Route: **MISSING** → now IMPLEMENTED (`/settings/baseline`, deep-linkable)
- Navigation: **MISSING** → now IMPLEMENTED (`frontend/components/layout/Sidebar.tsx` — "System → Company Baseline")
- API client: **MISSING** → now IMPLEMENTED (`baselinesAPI` in `frontend/lib/api.ts`: status / validate / onboarding / onboarding/no / resolve-for-audit)
- Types: **MISSING** → now IMPLEMENTED (`frontend/types/index.ts`: BaselineStatusResponse, BaselineValidateResponse, BaselineOnboardingResponse, BaselineResolveResponse, PerFrameworkCompliance, CompanyBaselineProjection)
- Audit creation flow: IMPLEMENTED (never asked for baseline — verified `app/audit/new/page.tsx` has no baseline field; unchanged, correct)
- Audit result UI (Company/FULL CIS/NIST separation + OUT_OF_SCOPE + comparison): **MISSING** → now IMPLEMENTED (`app/audit/[id]/page.tsx`)
- `ResultBadge` OUT_OF_SCOPE / NOT_APPLICABLE distinction: **MISSING** → now IMPLEMENTED (`components/ui/Badge.tsx` + `badge-out-of-scope` in `globals.css`)
- Loading/error/empty states: IMPLEMENTED per page (PageLoader / Alert / EmptyState), followed in the new page

**Backend**
- Models (`Organization`, `CompanyBaseline`, `User.organization_id`): IMPLEMENTED (correct org-level relationships)
- Baseline validation service: **BROKEN** → FIXED (`app/services/baseline.py` — empty `ControlRegistry()` rejected every control as "unknown"; now registers the same CIS+Juniper+NIST benchmarks as the audit pipeline; empty submissions explicitly rejected)
- Baseline API: **PARTIAL** → FIXED (`app/api/v1/baseline.py` — org auto-creation for new users, removed dead `created_by` kwarg (no such column), removed broken dead helper, added `POST /validate`, real org name in status, capability checks on configure)
- Audit pipeline baseline resolution: **BROKEN** → FIXED (`app/api/v1/audit_execution.py` — dead block referenced undefined `current_user`; now resolves org from `user_id`, logs `BASELINE_RESOLVED` audit-trail event)
- Audit summary endpoint (frontend data for Company/FULL CIS/NIST + comparison): **MISSING** → IMPLEMENTED (per-framework compliance + `_compute_company_baseline_projection` with control-by-control comparison)
- Reporting: PARTIAL → FIXED (`app/engines/reporting.py` — deleted two dead/broken helpers; Full CIS summary now conditional so an empty audit stays one page, restoring V11-10)
- Alembic migrations: **MISSING** → IMPLEMENTED (`009_company_baseline_tables.py` — organizations, company_baselines, users.organization_id backfill)

**Persistence**: IMPLEMENTED (JSONB controls; one ACTIVE baseline per org enforced by `check_organization_baseline` + `onboarding_yes_flow`; survives restart — verified by test + E2E)

**Authorization**: IMPLEMENTED (capability-oriented: `baseline.configure` / `baseline.view` / `baseline.compare`; auditor+admin; enforced server-side on every baseline endpoint — frontend hiding is cosmetic only; viewer gets 403)

## 2. Frontend Onboarding

- Configuration page: `frontend/app/settings/baseline/page.tsx`
- Route: `/settings/baseline` (sidebar "System → Company Baseline"; deep-linking works)
- Upload: drag-drop `.json` matching the backend contract `{name, framework, benchmark, controls[]}` or manual entry; format hint shown
- Validation: client parse → `POST /baseline/validate` → VALIDATING spinner → success (N controls selected) or per-control errors (duplicate / unknown / malformed listed, never silently removed)
- Activation: review screen (framework, benchmark, control count, control chips) → explicit "Activate Baseline" → `POST /baseline/onboarding` (server re-validates)
- Active state: ACTIVE badge, name, benchmark, control count, configured date, "View Controls" (fetches `resolve-for-audit`), explicit copy: applied automatically to future audits, one active baseline in MVP, no Replace button (backend does not support it)
- No-baseline state: NOT CONFIGURED badge, explanation, "No baseline — continue with Full CIS" (`POST /baseline/onboarding/no`), Full CIS auditing remains available, no fake company score

## 3. Audit Lifecycle (verified live)

```
Organization (admin@configshield.com, auto-created, baseline ACTIVE)
→ CompanyBaseline "CIS Baseline" — 5 CIS controls, JSONB, one per org
→ Device audit (POST /audit-execution/execute — config only, NO baseline field)
→ parse → normalize → canonical security state (unchanged pipeline)
→ Full CIS evaluation stored (53 controls: 17 PASS / 2 FAIL / 34 REVIEW — audit 1)
→ Company Baseline projection (5 in scope: 2 PASS / 0 FAIL / 3 REVIEW; 48 OUT_OF_SCOPE)
→ NIST: real 126-control registry exists; evaluated only when NIST/dual framework requested (CIS-only run → NIST section shows "no NIST evaluation")
→ Report: Company Baseline section + Full CIS section + 53-row comparison table with 48 OUT_OF_SCOPE (verified via pdftotext)
→ Audit 2 (different config, same org): baseline auto-resolved again — no upload (5 in scope: 0/0/5)
```

## 4. One-Time Baseline Verification

"Is the baseline configured once at organization onboarding and automatically reused for future audits?"

**Answer: PASS**
- Evidence: `onboarding_yes_flow` / `onboarding_no_flow` (`app/api/v1/baseline.py`) create the org on demand and persist status; `resolve_baseline_for_audit` + audit pipeline `BASELINE_RESOLVED` event reuse it per audit; two live E2E audits auto-resolved the same baseline with no upload; `tests/test_baseline.py::TestOnboardingLifecycle::test_full_onboarding_flow` + `test_no_baseline_flow` assert it; `app/audit/new/page.tsx` has no baseline input (unchanged).

## 5. Scope Semantics

OUT_OF_SCOPE != PASS, != FAIL, != REVIEW, != NOT_APPLICABLE:
**PASS** — asserted in `TestScopeSemantics::test_out_of_scope_is_not_pass` and `TestMutationInvariant::test_out_of_scope_never_equals_pass_fail_review`; distinct `badge-out-of-scope` visual + "Out of Scope" label; API emits the literal `OUT_OF_SCOPE` string only for out-of-scope controls, with the Full CIS verdict intact alongside.

## 6. Metrics

- Company denominator = selected controls only: **PASS** (18-style → denominator 4, 10-style → denominator 2, OUT_OF_SCOPE never counted; verified in tests + live summary: 5 in scope / 48 excluded)
- Full CIS denominator unchanged: **PASS** (53 controls, PASS/FAIL/REVIEW identical to pre-baseline behavior; summary `compliance.CIS` = 53/17/2/34)

## 7. Evidence

**PASS** — Company baseline is a pure projection over stored `ComplianceResult` rows; no re-parse, no duplicated or fabricated evidence, line numbers untouched (`TestFindingsEvidence::test_evidence_dict_is_not_mutated_by_projection`; reports read the same stored evidence).

## 8. Findings

**PASS** — baseline projection returns metrics only, never finding rows; an out-of-scope FAIL keeps exactly one CIS finding; no "company baseline failure" duplicates (`TestFindingsEvidence::test_company_projection_does_not_create_findings`; live audit 1 produced the same findings as a normal CIS audit).

## 9. NIST Separation

**PASS** — NIST SP 800-53 is genuinely implemented (126 controls, universal-model evaluation in dual/NIST mode) and stored under `framework="NIST"`; summary/UI render it as a separate card only when NIST rows exist; company baseline never touches NIST rows (`TestNoBaselineRegression::test_nist_results_stay_separate`; no invented CIS↔NIST mappings in the feature).

## 10. Security

- Authorization: **PASS** — `user_has_baseline_capability` on every configure/validate endpoint; viewer → 403 (tested: `test_capability_mapping`; verified live 403 semantics)
- Organization isolation: **PASS** — org derived server-side from authenticated user only; no org ID is ever accepted from the client; `test_cross_company_isolation` proves A cannot resolve B's controls
- IDOR: **PASS** — baseline endpoints take no IDs from the client; status/resolve read the authenticated user's org
- Frontend bypass: **PASS** — server-side checks are authoritative; UI capability gating is additive

## 11. Regression

- V3: **PASS** (Cisco V3 suites green in full run)
- V4: **PASS** (`tests/test_cisco_v4_router.py` green)
- E12 / validation corpus: **PASS** (1034 passed; the two previously failing source-scan contracts — V09-45, V11-10 — fixed at the correct layer; validation test DB upgraded with the missing org columns, exactly the migration gap found)
- Audit integrity: **PASS** (audit-trail tests green, incl. new `BASELINE_RESOLVED` path)
- Determinism: **PASS** — projection is a pure function of stored rows + org baseline; no random behavior; same audit twice → identical verdicts (engine determinism suites green)
- Mutation tests: **PASS** (`TestMutationInvariant::test_baseline_change_never_alters_cis_verdicts` — baseline swap changes only company scope/metrics)
- Ruff/type checks: **PASS** (`ruff check app/ tests/` clean; `tsc --noEmit` clean; `next lint` clean)
- Full suite: **1719/1719 passed** (backend `tests/` + `tests/validation`), 0 failed, 0 errors

## 12. Files Changed

Backend:
- `app/services/baseline.py` — validation service loads real benchmark registries; empty-baseline rejection (first wrong layer fix)
- `app/api/v1/baseline.py` — org auto-creation (`_ensure_organization`), removed `created_by` TypeError + dead broken helper, `POST /validate`, real org name in status
- `app/api/v1/audit_execution.py` — fixed dead `current_user` baseline block → real resolution + `BASELINE_RESOLVED` audit event; summary endpoint: per-framework compliance + `_compute_company_baseline_projection` (company metrics + comparison); backward-compatible `getattr(current_user, "organization_id", None)`
- `app/api/v1/reports.py` — `List` import; defensive org_id access
- `app/engines/reporting.py` — deleted dead/broken `_evaluate_company_baseline` / `_generate_comparison_table`; Full CIS summary conditional (V11-10 single-page empty report restored)
- `alembic/versions/009_company_baseline_tables.py` — organizations, company_baselines, users.organization_id (new)
- `tests/test_baseline.py` — 24 tests (validation, scope semantics, onboarding lifecycle, isolation, mutation, findings/evidence, no-baseline, NIST separation) (new)

Frontend:
- `app/settings/baseline/page.tsx` — full configuration page (new)
- `app/audit/[id]/page.tsx` — Company Baseline / Full CIS / NIST cards + control comparison table with OUT_OF_SCOPE (new sections)
- `components/layout/Sidebar.tsx` — "System → Company Baseline" nav item
- `components/ui/Badge.tsx` — ResultBadge OUT_OF_SCOPE / NOT_APPLICABLE
- `app/globals.css` — `.badge-out-of-scope` (neutral slate, not green/red)
- `lib/api.ts` — `baselinesAPI` (5 calls)
- `types/index.ts` — baseline + projection + comparison types; `AuditExecutionSummary` extension

## 13. Remaining Gaps (real only)

1. **Baseline replacement** — not supported (by design, MVP = one active baseline). UI states this instead of pretending.
2. **Audit-level baseline snapshot** — the projection is computed against the *current* org baseline over *stored* CIS rows. If the org baseline changes after an audit, the old audit's company projection reflects the new scope. This is the chosen architecture (scope is a live projection); the CIS verdicts themselves are immutable.
3. **NIST in the report comparison table** — the table covers Company vs Full CIS; NIST renders as its own card only when NIST rows exist (CIS-only runs show "no NIST evaluation"). Wiring NIST into the comparison table requires dual-baseline audits (backend supports them via framework="CIS+NIST"/"NIST") — left as UI follow-up, no fabricated data.
4. **Frontend automated tests** — no frontend test infrastructure exists in the repo (no jest/playwright/cypress). Verified via `tsc`, `next lint`, dev-server compile, and live E2E against the running stack.

## 14. Final Acceptance Matrix

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Organization-level baseline | PASS | `Organization`/`CompanyBaseline` models; org created from authenticated user |
| One-time onboarding | PASS | `onboarding_yes_flow`/`no_flow` + UI; never per-audit |
| No baseline upload per audit | PASS | `audit/new` unchanged (no baseline field); 2 live audits w/o upload |
| Frontend configuration UI | PASS | `/settings/baseline` + sidebar nav + validation/review/activate flow |
| Backend persistence | PASS | JSONB `controls`, survives restart (E2E + tests) |
| Validation | PASS | duplicate/unknown/malformed/empty; real registry; errors never silently dropped |
| One active baseline | PASS | `already_active` guard + `check_organization_baseline` (tested) |
| Automatic audit resolution | PASS | pipeline `BASELINE_RESOLVED`; summary projection; 2 live audits |
| Company scope semantics | PASS | denominator = in-scope only; score from in-scope decisive |
| OUT_OF_SCOPE semantics | PASS | distinct state; != PASS/FAIL/REVIEW/NOT_APPLICABLE; badge + literal string |
| Full CIS unchanged | PASS | 53 controls / verdicts identical; mutation test; live summaries |
| Metrics correct | PASS | summary + report + tests |
| Evidence preserved | PASS | same stored rows; projection is read-only |
| Findings preserved | PASS | no duplicates; CIS finding remains the single source |
| NIST separated | PASS | real evaluation; separate card; untouched by baseline |
| Authorization | PASS | capability checks; viewer 403; server-side |
| Org isolation | PASS | cross-company test; no client-supplied org IDs |
| V3 regression | PASS | full suite green |
| V4 regression | PASS | full suite green |
| E12 | PASS | 1034 validation tests green (incl. V09-45, V11-10 restored) |
| Determinism | PASS | pure projection; engine suites green |
| Full suite | PASS | 1719 passed, 0 failed |