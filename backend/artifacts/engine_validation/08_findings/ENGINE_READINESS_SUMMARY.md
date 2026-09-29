# ENGINE_READINESS_SUMMARY - Engine 08 - Finding Engine (spec 10.8)

**Scope:** `backend/app/engines/compliance/{findings,models,evidence,executor}.py`
(step 6), `backend/app/api/v1/{findings,audit_execution,audits,router}.py`,
`backend/app/schemas` (FindingResponse/FindingStatus/Remediation/
FindingStatusUpdate), `app/models.Finding`, `app/repositories/audit_trail.py` +
their contract with `docs/PROJECT_MASTER_SPEC.md`
(§9.1 step 7/13, §10.8, §10.9 boundary, §12 Finding/Remediation/EvidenceChain,
§13.4, §14.3.2, §19.1 DDL, §19.2 indexes, §20.2 endpoints, §20.7 evidence
visibility)
**Evidence:** 91 pytest rows (91 passed, 0 failed) - 480-file corpus sweep
(0 errors, 71,236 findings) - 1 runtime probe - 0 production files modified
**Overall verdict:** **FAIL** (four disagreeing Finding shapes, no complete §12
evidence chain on findings, non-§12 remediation, missing/drifted list endpoints
with a dead severity filter, wrong-vendor findings, unaudited status changes,
lowercase severity vocabulary - not generation logic, persistence round-trip,
determinism or performance)
**Date:** 2026-09-26

---

## Scoreboard

| Status | Count | % |
|---|---|---|
| PASS | 68 | 75% |
| PARTIAL | 0 | 0% |
| FAIL | 23 | 25% |
| **Total** | **91** | 100% |

| Classification | Count |
|---|---|
| CONFIRMED BEHAVIOR | 68 |
| BUG | 9 |
| DESIGN LIMITATION | 8 |
| RECOMMENDATION | 4 |
| MISSING | 2 |

| Category | Rows | Status |
|---|---|---|
| A spec structure (§12 / DDL / §19.2) | 10 | PASS 4, FAIL 6 |
| B generation contract (§9.1 step 7, §10.8) | 14 | PASS 14, FAIL 0 |
| C severity / confidence / risk (§10.8, §10.9 boundary) | 9 | PASS 9, FAIL 0 |
| D evidence chain linkage (§10.8, §12) | 8 | PASS 7, FAIL 1 |
| E persistence + API (§14.3.2, §20.2) | 10 | PASS 6, FAIL 4 |
| F drift: two list implementations | 8 | PASS 3, FAIL 5 |
| G SEPARATE RECORD - wrong/unsupported vendor | 4 | PASS 0, FAIL 4 |
| H semantic fidelity invariants | 6 | PASS 6, FAIL 0 |
| I pipeline integration (§9.1) | 8 | PASS 7, FAIL 1 |
| J determinism | 3 | PASS 3, FAIL 0 |
| K performance (measurement only) | 3 | PASS 3, FAIL 0 |
| L hostile / boundary input | 8 | PASS 6, FAIL 2 |

---

## Hypotheses (15 CONFIRMED - 11 REJECTED - 0 unverifiable)

CONFIRMED: H08-01 **one Finding concept, four field sets** (no
`compliance_result_id` on the dataclass, engine-only `audit_id/risk_score/
priority/result`, 15-column table vs 10-column DDL) - H08-02 **`FindingResponse`
omits `control_id`** (API consumers cannot link findings to controls) - H08-03
**severity vocabulary lowercase** at the enum and in `findings.severity` where
§12/DATA_MODEL mandate `CRITICAL|HIGH|MEDIUM|LOW` - H08-04 **evidence not the
§12 chain** - typed `Optional[dict]`, `result_reasoning` instead of `reasoning`,
no `security_control`, empty `raw_config` (0/71,236 complete; upstream context
V07-46/47) - H08-05 **remediation misses §12 keys** `finding_id/finding_title/
risk_description` (all 71,236 findings) - H08-06 **status changes unaudited**
(`log_finding_update` ships with zero callers) - H08-07 **`notes` dropped** by
the status handler - H08-08 **spec endpoint `GET /api/v1/audits/:id/findings`
not routed** - H08-09 **two list endpoints drift** (created_at DESC vs severity
lexicographic with LOW before MEDIUM; enum vs free-form status filter) -
H08-10 **`?severity=CRITICAL` returns 0 rows** on both endpoints - H08-11
wrong-vendor attribution: **declared vendor, not true vendor** - juniper as
cisco: 164 vs 119 findings, 9 missed, 8 false positives (separate record;
upstream context V07-72/73) - H08-12 unsupported arista + absent text ->
**decisive CM-7/CM-7(1) FAIL findings** (upstream context V07-74) - H08-13
empty config -> **CM-7/CM-7(1) FAIL findings** instead of REVIEW - H08-14
step text **advertises "ML risk scoring (RandomForest)"** when only the formula
runs - H08-15 hostile inputs surface **raw internal errors** (None ->
`AttributeError`; 1 MB device -> `StringDataRightTruncation`).

REJECTED: H08-16 "happy-path generation contract fails" (one finding per
FAIL/REVIEW, PASS never leaks, counts/ids/linkage correct) - H08-17
"severity/confidence/risk assignment violates its contract" - H08-18 "findings
not linked to compliance results/evidence" - H08-19 "findings not persisted /
endpoints do not serve them" - H08-20 "the two list endpoints return different
record sets" - H08-21 "pipeline does not wire findings end to end" - H08-22
"non-deterministic generation" - H08-23 "performance unusable / super-linear"
(linear ~5 ms/finding) - H08-24 "hostile inputs bypass validation entirely" -
H08-25 "status vocabulary / NOT NULL / §19.2 indexes / title limits wrong" -
H08-26 "fidelity invariants violated".

---

## Blocking findings (must be fixed before this engine is ready)

1. **F1 - Four disagreeing Finding shapes.** Spec §12 says
   `compliance_result_id + control_id + evidence: EvidenceChain`; the dataclass
   has no `compliance_result_id` (V08-01), `FindingResponse` drops `control_id`
   (V08-02/58), and the table stores 15 columns vs the §19.1 DDL's 10 - the DDL
   omits `evidence` §12 requires (spec self-contradiction, V08-05).
   (V08-01/02/05/58, H08-01/02)
2. **F2 - Findings expose no complete §12 evidence chain.** Evidence typed
   `Optional[dict]` (V08-06); executor-built chain has `result_reasoning`
   instead of `reasoning`, no `security_control`, empty `raw_config` - **0 of
   71,236 corpus findings carry all 8 §12 keys**, contradicting §20.2
   "Findings always show evidence chain". (V08-06/37 + corpus, H08-04)
3. **F3 - Remediation is not the §12 interface.** `executor.py:336-347` builds
   `title/description/confidence`, never `finding_id/finding_title/
   risk_description` - every one of the 71,236 corpus findings misses §12 keys.
   (V08-09, H08-05)
4. **F4 - Documented endpoint missing; the two live list implementations
   drift.** `GET /api/v1/audits/:id/findings` not routed (V08-49); orders
   differ (V08-53); severity order is lexicographic - **LOW lists before
   MEDIUM** (V08-54); `?severity=CRITICAL` -> **0 rows** on both endpoints
   (V08-56); status filter enum on one endpoint, free-form on the other where
   an invalid value silently matches nothing (V08-55).
   (V08-49/53/54/55/56, H08-08/09/10)
5. **F5 - Wrong/unsupported-vendor inputs produce findings describing the
   wrong device (separate record).** Generator trusts `evaluation.vendor`
   (V08-60); juniper-declared-cisco: **9 missed + 8 false-positive findings**
   (V08-61); unsupported arista/empty input: decisive CM-7/CM-7(1) FAIL
   findings (V08-62); empty config: same FAIL findings instead of §13.4 REVIEW
   (V08-63). Corpus: **158 files / 22,820 findings** attributed off-label,
   **113 files / 14,238 findings / 574 FAIL-derived** on unsupported vendors.
   Upstream context only: E07 V07-72/73/74/75. (H08-11/12/13)
6. **F6 - Status changes leave no history; notes vanish.** Status handler
   writes only status (V08-47) with no audit-trail row although
   `log_finding_update` (`audit_trail.py:142`) has zero callers (V08-46) -
   §9.1 step 13 unmet for the finding-state workflow. (V08-46/47, H08-06/07)
7. **F7 - Severity vocabulary lowercase at source and in storage.** `Severity`
   enum `critical/high/medium/low` (`models.py:15-20`) and
   `finding.severity.value` persisted lowercase (V08-42) vs §12/DATA_MODEL
   uppercase - the API uppercases on output, but the column, filters and
   reports see the wrong case (mechanism behind F4's dead severity filter).
   (V08-03/42, H08-03)

Secondary: **F8** step text advertises "ML risk scoring (RandomForest)"
(`audit_execution.py:434`) when the formula fallback runs (V08-77) - **F9**
hostile inputs surface raw internal errors: None -> `AttributeError` (V08-84),
1 MB `affected_device` -> `StringDataRightTruncation` (V08-89) - **F10**
Engine 09 boundary observations: **0 CRITICAL findings** corpus-wide and
**24,639 (34.6%) empty priorities** (risk < 40 has no §12 representation).

---

## What is solid

Generation contract: one finding per FAIL/REVIEW, PASS never leaks (0/71,236
corpus leaks), counts = failed+review, unique ids, control/title/reasoning/
status/audit linkage - severity maps without the silent MEDIUM default,
confidence copied from the evaluation within [0,1], risk 0-100 and monotonic
with severity - evidence **linked and ordered** per finding - persistence
round-trip: severity/status counters, summary buckets, status persistence,
pagination, ownership, 404 - both list endpoints return the **same record set**
- status enum + SQL/injection payloads rejected, unicode safe - fidelity
invariants (no fabricated severity, no "failed" wording on REVIEW) - offline
pipeline runs the findings step end to end with a complete response contract -
deterministic - linear performance (~4-5 ms/finding, 432 ms full executor run,
95 findings in ~400 ms).

## Corpus measurements (480 files - 0 errors - 71,236 findings)

| Measure | Value |
|---|---|
| files with findings | **480/480** (101-200 per file; executor status `completed` on all) |
| severity (stored) | high 27,887 - medium 25,791 - low 17,558 - **critical 0** - outside-vocab 0 |
| status | `open` 71,236 (100%) |
| priority (§10.9 boundary) | P1 0 - P2 19,396 - P3 27,201 - **empty 24,639 (34.6%)** |
| evidence vs §12 | **0/71,236 with all 8 keys**; gaps `reasoning`, `security_control`, empty `raw_config` |
| remediation vs §12 | present on all - **all missing ≥1 §12 key** (structurally: `finding_id`, `finding_title`, `risk_description`) |
| G flags | `wrong_vendor_attributed` **158** (22,820 findings) - `findings_on_unsupported_vendor` **113** (14,238 findings, **574 FAIL-derived**) - empty-input 0 - PASS-leak 0 |
| detected (input) | cisco 323, unknown 73, juniper 44, fortinet 29, paloalto 11 |
| by label | Cisco 252 -> 39,369 findings - FRR 63 -> 9,176 - Arista 38 -> 6,056 - Juniper 41 -> 5,532 - PaloAlto 38 -> 4,788 - Fortinet 30 -> 3,780 - F5 11 -> 1,511 - A10 3 -> 441 - NAPALM 4 -> 583 |
| timing | 451.8 s total; p50 878 ms / p95 1,646 ms / max 2,825 ms per file |

Directory labels are hints only; no detection accuracy is claimed (Engine 02
owns it). Attribution follows detection, so the finding engine propagates
Engine 02's mis-attribution into the record users see.

## Performance (measurement only)

Full executor per corpus file p50 **878 ms** / p95 **1,646 ms** / max
**2,825 ms** (451.8 s / 480 files); generation ~4-5 ms per finding and
**linear** (1k: 5.1, 4k: 5.5 ms/finding; 10k = ~92 s); profiling attributes
the constant to one single-sample `sklearn.predict` per finding
(`findings.py:103`) - batch predict would collapse it (observation, not a
conformance row); full `AuditExecutor.execute` on a secure config: 432 ms.

## Regression / integrity

- Full suite before E06: 845 collected / 819 passed / 26 failed -> after E06:
  950/924/26 -> after E07: 1045/1019/26 -> after E08: **1136 / 1110 / the
  same 26 pre-existing failures** (91 new tests). Failure composition
  unchanged: `test_benchmark_execution` 6, `test_detection` 2,
  `test_frontend_integration_support` 2, `test_juniper_benchmark` 7,
  `test_phase5_integration` 2, `test_phase8_hardening` 6, `test_vertical_slice`
  1.
- `git diff -- backend/app/` **empty**; `git status --porcelain --
  backend/app/` **empty**; working tree matches the recorded pre-existing
  baseline.
- New files only: `tests/validation/test_v08_findings.py`,
  `scripts/engine_validation/{sweep,report}_findings.py`,
  `artifacts/engine_validation/08_findings/*`, plus the conftest engine mapping
  for `08_findings`. Throwaway probe `_probe08.py` deleted.
- Engines 02/05/07 treated as **upstream context only** per the user's
  directive - cited where vendor selection (V08-60..63) or evidence-chain
  drift (V08-37) originate, never assumed fixed, never re-tested.

## NOT APPLICABLE / NOT VERIFIABLE

ML quality (deferred) - risk formula / priority semantics (Engine 09 owns
§10.9; only computation location and blank priorities recorded) - detection
accuracy (Engine 02) - evidence chain content correctness (Engine 07 owns the
chain source; interface completeness only here) - remediation content quality
(Engine 10) - DDL vs §12 interface adjudication (spec contradicts itself -
recorded as drift) - findings UI rendering (§20.7, frontend not exercised) -
concurrency/locking/transactions (single-threaded probes) - auth testing (not
in contract; ownership/404 only) - bulk Postgres write performance.

## Limitations of this validation

Corpus sweep takes detection as input, not truth (mismatch flag does not
decide who is right); category G probes exercise the generator's public
contract with a declared vendor - production reachability through the
executor's re-detection is noted per finding and corroborated by the 158
corpus files; the 8-key checks are interface checks, not semantic checks of
chain content; performance numbers are single-machine measurements, not a
readiness score; hypothesis conclusions derive only from the recorded evidence
rows.

---

**Readiness:** NOT READY - 7 blocking findings (F1, F2, F3, F4, F5, F6, F7).
**Next:** Engine 09 (Risk Engine, spec 10.9) - pending user approval.
