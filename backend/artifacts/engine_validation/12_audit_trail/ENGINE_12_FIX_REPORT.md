# Engine 12 — Audit Trail Final Validation Report

## 1. Scope

Engine 12 (spec §10.12, `docs/PROJECT_MASTER_SPEC.md`) maintains complete audit history:
store all audit results, track configuration changes, maintain version history, support audit queries.
Implementation: `backend/app/repositories/audit_trail.py` (507 lines — `AuditTrailError`,
`normalize_action/uuid`, `sanitize_details`, `log/log_ai_interaction/log_compliance_evaluation/
log_finding_update/log_audit_event/log_mapping_event/get_entries/count_entries`),
served via `GET /audit-trail` (`app/api/v1/audit_trail.py`), wired into lifecycle
(`audits.py` AUDIT_CREATED/CANCELLED, `audit_execution.py` STARTED/COMPLETED/FAILED),
uploads (`configurations.py` CONFIG_UPLOADED fresh + replay), KB versions (`training.py`),
finding transitions (`findings.py`). Canonical event: `AuditTrail` row
(`app/models/__init__.py`) — id, action (`AuditAction`, 18 values), entity_type,
entity_id, user_id, details (JSONB), ip_address, user_agent, created_at.

## 2. Existing Implementation

Found complete and contract-hardened: typed errors at call site (never bare
uuid/DB errors), JSONB-safe sanitization (Decimal→float, datetime→ISO, Enum→value,
UUID→str, sets→sorted lists, NUL stripped, non-finite stringified, depth-bounded),
client metadata truncation (IP 45, UA 500), bounded pagination (MAX_TRAIL_PAGE 1000),
exact-set filtered queries shared by list + count (`_filter_conditions`).
Validation: 40-test suite (`tests/validation/test_v12_audit_trail.py`, 1425 lines,
categories A–K), corpus sweep (`scripts/engine_validation/sweep_audit_trail.py`),
report builder (`report_audit_trail.py`), 9 artifact files.

## 3. Initial Validation State

| Check | Before fixes | Category |
|-------|-------------|----------|
| E12 suite (40 tests) | 14 passed, **26 skipped** — throwaway DB `engine_validation_test` not provisioned | environment |
| Full validation (E01–E12) | V01 2 failed (FK violation on upload trail), V08 1 failed (perf ratio under load) | test-fixture defect + timing flake |
| Unit (non-validation) | 1 failed (`test_juniper_findings_have_remediation`: validation `NO_SUBSTANTIVE_CONTENT` on `##`-prefixed Juniper) | implementation defect (E02, working tree) |
| Sweep regeneration | **Blocked** — hardcoded `C:\Users\priye\...` corpus path + `assert == 480` | validation-script defect |
| Artifacts on disk | 40/40 PASS but **stale** (other machine's 480-file corpus, unreproducible here) | environment |

Failure matrix:

| Test | Failure | Root Cause | Category | Fix |
|------|---------|------------|----------|-----|
| 26× E12 DB tests | SKIP, no evidence | `engine_validation_test` DB absent | environment | provisioned DB + schema via `dbutil.create_schema()` |
| V01-58, V01-60 | FK violation `audit_trail_user_id_fkey` → endpoint 500 | `_UploadClient` never persisted its actor `User` row | test-fixture defect | `session.add(user)+flush` in `__aenter__` (teardown rolls back) |
| juniper remediation | `validation failed NO_SUBSTANTIVE_CONTENT` | `_strip_comments` treated Juniper `##` show-config lines as `#` comments | implementation defect (E02) | keep `##`-prefixed lines active |
| V08-82 large batch | `rate4 <= rate1*1.5` fails only in 44s full runs | 46k `datetime.utcnow()` DeprecationWarnings distort timing | implementation defect (perf hygiene) | naive-UTC helper in hot per-finding paths; warnings 46k→5k |
| sweep script | `AssertionError: expected 480, got 0` | hardcoded Windows path + fixed count | validation-script defect | `E12_CORPUS` / `E12_EXPECTED_FILES` env override + missing `import os` |

## 4. Root Cause Analysis

1. **Skipped E12 tests** — `trail_db`/`db_env` fixtures skip when `schema_available()` is false.
   No postgres role `postgres`, no `engine_validation_test` DB on this machine.
2. **V01 FK failures** — correct FK behavior; fixture created an in-memory `User`
   without persisting, then the (correct) `CONFIG_UPLOADED` trail write referenced it.
3. **Juniper validation** — `_COMMENT_TOKENS = (^\|\s)(!\|#\|//\|/\*)` matches the first
   `#` of Juniper `## system {` lines, stripping all content → comment-only → gate closed.
4. **V08 perf flake** — per-`Finding` `field(default_factory=datetime.utcnow)` +
   pydantic `Field(default_factory=datetime.utcnow)` emit a DeprecationWarning per object
   (46,432 warnings/full run); warning machinery overhead scales non-linearly under load,
   breaking the 1.5× linearity ratio only in full-suite runs (passes solo, passes v01–v08).
5. **Sweep portability** — absolute Windows path, fixed 480 assertion, missing `import os`.

## 5. Fixes Applied

- `scripts/engine_validation/sweep_audit_trail.py`: `E12_CORPUS`/`E12_EXPECTED_FILES`
  env override (defaults preserved), added missing `import os`. Assertion logic unchanged.
- `tests/validation/test_v01_ingestion.py` (`_UploadClient.__aenter__`): persist actor
  user before ASGI calls. No production change; no assertion change.
- `app/engines/validation.py` (`_strip_comments`): lines starting with `##` stay active
  (Juniper show-config; parser strips `##` downstream). Single `#`/`!`/`//` handling unchanged.
- `app/engines/compliance/findings.py` + `app/benchmarks/models.py`: `_utcnow_naive()`
  (`datetime.now(timezone.utc).replace(tzinfo=None)`) replaces `datetime.utcnow` in hot
  per-object factories — identical values, naive semantics preserved for
  `TIMESTAMP WITHOUT TIME ZONE`, zero deprecation warnings. DB column defaults untouched
  (asyncpg rejects aware datetimes — deliberately out of scope).
- `tests/validation/test_v08_findings.py` (`test_v08_82`): discarded warmup `run(100)`
  before timing; **assertion unchanged** (`rate4 <= rate1*1.5`).
- Provisioned `engine_validation_test` DB + schema (env setup, not code).
- No Engine 12 production code needed changes — implementation was already correct.

## 6. Contract Validation

- E12 suite: **40/40 PASS** (2 consecutive runs), 26 previously-skipped DB tests now execute.
- Sweep contract on local 26-file corpus (19 sample + 7 demo): **C1/C1t/C2/C3/C4/C5/C6/C7
  all PASS, 0 violations** (26 files, 590 findings sanitized, residue 0).
  `contract_results.json`: verdict PASS, violations_total 0.
- Full validation suite (E01–E12): **1034/1034 PASS**.

## 7. Security Validation

- Suite rows V12-28…V12-31 + G-rows V12-25…27 (security_results.csv): **7/7 PASS** —
  1 MB payload round-trip, metadata truncation (IP 45/UA 500), 422 on malformed filters,
  typed numerics (bool/negative/NaN rejected), hostile markup/unicode/emoji verbatim,
  per-actor scoping (auditor sees own, admin sees all).
- Sweep C2/C4: raw Decimal rejected pre-sanitize, persisted as float. No new issues found.
- `security_results.csv`: 7 rows, all PASS.

## 8. Corpus Validation

- Local corpus `/tmp/e12_corpus` (26 files): 26 ok, 0 errors, 590 findings, all payloads
  sanitized+serialized, 0 residue. `dataset_results.csv`: 26 rows, 0 errors.
  `dataset_summary.json`: files 26, verdict PASS.
- Note: original 480-file Windows corpus is absent on this machine; local corpus is the
  honest reproducible substitute (19 sample + 7 demo configs, multi-vendor).
  Multi-vendor: cisco/juniper/fortinet represented; vendor/platform/device preserved
  per finding payload (C3) and per `file_details`.

## 9. Determinism Validation

- E12 suite twice: 40/40 both runs. Sweep twice: 26/26 files, 590/590 findings,
  verdict PASS both. `determinism_results.csv`: 3 rows PASS (V12-23/24 + SWEEP-C6).
  IDs/timestamps legitimately differ; logical sets identical.

## 10. Performance Validation

- Sweep log+flush: p50 0.4ms, p95 0.7ms, max 2.5ms (budget 5000ms). V12-36: p50 0.2ms,
  p95 0.4ms, max 1.6ms. V12-37: 10 rows list+count 2.1ms. `performance.csv`: 3 rows.
- Suite warnings 46,432 → 4,947 after utcnow fix (same suite, 1034 tests).

## 11. Regression Validation

- Unit (non-validation): **433/433 PASS** (was 432+1 juniper failure).
- Full validation E01–E12: **1034/1034 PASS** (was 1032+2: V01 FK ×2 fixed by fixture,
  V08 flake fixed by utcnow hygiene + warmup).
- E01–E11 untouched except: E02 `##` fix (restores committed behavior for Juniper),
  E08 test warmup (assertion unchanged). No E12 production changes needed.
- Backend imports OK; `/health` healthy; frontend 200. No unrelated failures remain.

## 12. Remaining Limitations

1. Local corpus is 26 files, not the original 480-file Windows dataset — coverage is
   honest but smaller; re-run sweep with `E12_CORPUS` pointed at the full dataset
   where available (`E12_EXPECTED_FILES=480`).
2. `datetime.utcnow()` remains in cold paths (models column defaults, auth, audit
   endpoints, reporting) — intentionally left naive-UTC to avoid asyncpg
   aware-datetime breakage; warning count is now 4,947 (mostly those cold paths
   under validation). A repo-wide aware-datetime migration is out of E12 scope.
3. V08-82 remains a timing assertion by nature; warmup + warning hygiene make it
   stable here (3 consecutive full-suite passes), but loaded CI runners should be
   watched.

## 13. Final Status

READY
