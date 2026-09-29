# Engine 08 - Finding Engine (spec 10.8)

**Date:** 2026-09-26
**Verdict:** **FAIL - NOT READY** (7 blocking findings)
**Evidence:** 91 pytest rows (91 passed, 0 failed) - 480-file corpus sweep (0 errors,
71,236 findings) - 1 runtime probe - 0 production files modified

---

## 1. Method

Each requirement below was turned into a pytest assertion in
`tests/validation/test_v08_findings.py` and recorded through the shared
`Recorder` (categories A-L, ids `V08-01..V08-91`), dumped to
`artifacts/engine_validation/08_findings/raw_results.jsonl`. The corpus sweep
(`scripts/engine_validation/sweep_findings.py`) ran the **production path**
(`AuditExecutor.execute`, the same wiring the audit API uses) over every file in
`C:\Users\priye\Downloads\SIH Config\final-dataset`. `report_findings.py`
derives the CSVs, the hypotheses and `summary.json` from those two inputs and
refuses to emit a report if any non-PASS row is unreferenced by a hypothesis
(0 unreferenced, all 91 rows referenced). Classification vocabulary:
`CONFIRMED BEHAVIOR | BUG | MISSING | DESIGN LIMITATION | RECOMMENDATION`;
statuses `PASS | FAIL` only (no numeric readiness score; no invented
"industry standard"). Ground rules held: no edits under `backend/app/**`
(`git diff -- backend/app/` empty), detectors treated as input not truth, and
findings from Engines 02/05/07 are cited as *upstream context only* - never
assumed fixed, never re-tested.

## 2. Contract under test

Spec claims (docs/PROJECT_MASTER_SPEC.md):

- **§9.1 step 7** (:384-388): "Create finding with evidence chain / Assign
  severity / Calculate confidence" for every non-PASS evaluation; **step 13**
  "Audit Trail stores complete history".
- **§10.8 Finding Engine** (:538-549): input `ComplianceResults`, output
  `Findings`; create records, assign severity, calculate confidence, link
  evidence chains.
- **§10.9 Risk Engine** (:551-561): the risk formula and priority belong to
  Engine 09 - recorded here as a boundary, not judged.
- **§12 Finding** (:841-855): fields `id, compliance_result_id, control_id,
  title, description, severity (CRITICAL|HIGH|MEDIUM|LOW), confidence, evidence
  (EvidenceChain), affected_device, affected_vendor, remediation, status
  (open|in_progress|resolved|accepted)`; **§12 Remediation** (:857-869):
  `finding_id, finding_title, risk_description, why_it_matters, vendor,
  platform, recommended_config, verification_steps, rollback_steps,
  references`; **§12 EvidenceChain**: 8 keys (`raw_config, parsed_value,
  normalized_value, security_control, expected_value, actual_value, result,
  reasoning`).
- **§13.4**: insufficient evidence -> REVIEW, never decisive FAIL.
- **§14.3.2** persistence; **§19.1 DDL** findings (:1441-1452, 10 columns);
  **§19.2** indexes (:1490-1492); **§20.2 endpoints** (:1537-1540):
  `GET /api/v1/audits/:id/findings`, `GET /api/v1/findings/:id`,
  `PUT /api/v1/findings/:id/status`; **§20.7 / :1253** "Findings always show
  evidence chain"; **DATA_MODEL** validation: `CRITICAL|HIGH|MEDIUM|LOW`;
  **P0 table :1698**: "Findings - Generate findings with evidence".

Code under test: `app/engines/compliance/{findings,models,evidence,executor}.py`
(step 6), `app/api/v1/{findings,audit_execution,audits,router}.py`,
`app/schemas` (`FindingResponse/FindingStatus/Remediation/FindingStatusUpdate`),
`app/models.Finding`, `app/repositories/audit_trail.py`.

## 3. What the finding engine actually does (observed)

1. `FindingGenerator.generate_findings(evaluation, audit_id, device_name, ...)`
   (`findings.py:163-196`) walks the evaluations and emits a `Finding` for every
   `FAIL` and `REVIEW` result; `PASS` is skipped (`:182-196`). One finding per
   non-PASS evaluation, ids are uuid4-unique, title = control title,
   description carries the evaluation's reasoning, status defaults `open`.
2. Severity is copied from the control's severity through
   `_benchmark_to_compliance_evaluation`'s `sev_map` (unknown -> silent
   `MEDIUM`, `executor.py:299-305`); confidence is copied from the evaluation;
   `SeverityCalculator` (`findings.py:71-150`) adds vendor/category multipliers
   to a base risk (`critical 10 / high 7.5 / medium 5 / low 2`), normalises
   `risk_score = weighted/15.6*100` and derives priority `P1>=80, P2>=60,
   P3>=40`, otherwise an **empty** priority string (`:96-101`). The ML path
   (`app.ml.model.get_risk_predictor`, one `sklearn.predict` per finding) is
   attempted inside `calculate_risk_score` with a deterministic formula
   fallback (`:117-131`).
3. Evidence on a generated finding is the **executor-built legacy chain's
   `to_dict()`** (`executor.py:308-328` -> `evidence.py:53-73`): 18 keys,
   `result_reasoning` instead of `reasoning`, no `security_control`, and
   `raw_config` empty even for a 1.4 KB config (probe, 164-finding run).
4. Remediation for non-PASS findings is built at `executor.py:336-347` with
   keys `title/description/why_it_matters/vendor/platform/recommended_config/
   verification_steps/rollback_steps/references/confidence` - not the §12
   `finding_id/finding_title/risk_description` shape.
5. Persistence (`audit_execution.py:389-407`) stores `finding.severity.value`
   **lowercase**, then rebuilds the audit counters with `.upper()`
   (`:447-451`) and the summary buckets with `.upper()` keys (`:742-759`).
6. Two list implementations exist: `findings.py:15` (`order by created_at
   DESC`, enum-typed `finding_status`) and `audit_execution.py:657`
   (`order by Finding.severity` lexicographic, free-form `status_filter:
   Optional[str]`), plus an un-routed third shape (spec's
   `GET /audits/:id/findings` does not exist).
7. `PUT /findings/:id/status` (`findings.py:111-146`) writes only the status;
   `notes` are dropped and no audit-trail row is created
   (`log_finding_update`, `audit_trail.py:142`, has zero callers).

## 4. Results by category

| Cat | Scope | Rows | PASS | FAIL | Headline |
|---|---|---|---|---|---|
| A | Spec structure (§12, DDL, §19.2) | 10 | 4 | 6 | no `compliance_result_id` on the dataclass; response missing `control_id`; lowercase severity enum; 15 vs 10 column table; evidence typed `Optional[dict]`; remediation misses §12 keys |
| B | Generation contract (§9.1 step 7, §10.8) | 14 | 14 | 0 | one finding per FAIL/REVIEW, PASS never leaks, counts/ids/linkage correct |
| C | Severity / confidence / risk (§10.8, §10.9 boundary) | 9 | 9 | 0 | severities map without the silent default, confidence copied and in [0,1], risk 0-100 monotonic with severity |
| D | Evidence chain linkage (§10.8, §12) | 8 | 7 | 1 | chains are linked and ordered - but only 6/8 §12 keys present (`reasoning`, `security_control` missing) |
| E | Persistence + API (§14.3.2, §20.2) | 10 | 6 | 4 | lowercase stored severity; status changes unaudited; notes dropped; spec endpoint missing |
| F | Drift: two list implementations | 8 | 3 | 5 | different ordering, lexicographic severity (LOW before MEDIUM), free vs enum status filter, unusable `?severity=CRITICAL` |
| G | SEPARATE RECORD - wrong/unsupported vendor | 4 | 0 | 4 | declared-vendor attribution, 9 missed / 8 false findings, unsupported -> CM-7 FAIL findings, empty config -> CM-7 FAIL findings |
| H | Semantic fidelity invariants | 6 | 6 | 0 | severity always enum, confidence/evidence copy the evaluation, wording matches the verdict |
| I | Pipeline integration (§9.1) | 8 | 7 | 1 | step runs offline, response contract fields present, 404/ownership enforced - step text advertises unimplemented ML scoring |
| J | Determinism | 3 | 3 | 0 | repeat runs byte-identical |
| K | Performance (measurement only) | 3 | 3 | 0 | ~4-5 ms/finding, linear scaling, full executor run ~430 ms |
| L | Hostile / boundary input | 8 | 6 | 2 | PASS-only/empty evals yield no findings, enums and injection handled - None evaluation and 1 MB device surface raw internal errors |
| | **Total** | **91** | **68** | **23** | 68 CONFIRMED BEHAVIOR, 9 BUG, 8 DESIGN LIMITATION, 4 RECOMMENDATION, 2 MISSING |

## 5. Expectations (and where they come from)

No external "industry standard" is invoked. The expectations are:

1. **The project's own specification** (§9.1 step 7/13, §10.8, §12, §13.4,
   §14.3.2, §19.1/§19.2, §20.2) - a written contract this code claims to
   implement (`audit_execution.py` is annotated "per SPEC section 9").
2. **The spec's own cross-references**: §12 fixes the Finding field list, the
   severity/status vocabularies, the EvidenceChain key list and the Remediation
   field list; DATA_MODEL validation repeats `CRITICAL|HIGH|MEDIUM|LOW`; §20.2
   names three endpoints that must exist.
3. **Internal consistency**: one Finding concept must not be four different
   field sets (spec interface / engine dataclass / table / API response);
   two list endpoints over the same table must return the same set in the same
   order; a filter value the API documents must find the rows it stores.
4. **Consequences, not just clauses**: a defect counts only when it changes an
   observable outcome - a missing field a consumer needs, zero rows returned
   for a documented query, a finding that describes the wrong device, a status
   change that leaves no history.
5. **Boundaries**: the risk formula / priority semantics (§10.9, Engine 09),
   ML quality (deferred) and detection accuracy (Engine 02) are not judged here
   - only whether §10.8's own claims (severity, confidence, evidence linking)
   hold.

## 6. Hypotheses (15 CONFIRMED, 11 REJECTED, 0 unverifiable)

CONFIRMED: H08-01 **one concept, four field sets** - spec-only
`compliance_result_id`, dataclass-only `audit_id/risk_score/priority/result/
affected_platform`, 15-column table vs 10-column DDL (V08-01/05/58) - H08-02
**`FindingResponse` omits `control_id`** so no API consumer can see which
control a finding came from (V08-02) - H08-03 **severity vocabulary lowercase**
at the enum and in the stored column where §12/DATA_MODEL mandate uppercase
(V08-03/42) - H08-04 **evidence deviates from §12** - typed `Optional[dict]`,
chain carries `result_reasoning`, no `security_control`, empty `raw_config`
(V08-06/37; upstream context V07-46/47) - H08-05 **remediation misses §12
keys** `finding_id/finding_title/risk_description` (V08-09) - H08-06 **status
changes unaudited** - `log_finding_update` ships zero callers (V08-46) -
H08-07 **`notes` accepted by the schema are dropped** (V08-47) - H08-08
**spec endpoint `GET /api/v1/audits/:id/findings` not routed** (V08-49) -
H08-09 **the two list endpoints drift** - created_at DESC vs severity
lexicographic (LOW listed before MEDIUM), enum vs free-form status filter
(V08-53/54/55) - H08-10 **`?severity=CRITICAL` returns 0 rows** on both
endpoints while the stored value is `critical` (V08-56) - H08-11 wrong-vendor
attribution: **declared vendor, not true vendor** - juniper-declared-cisco
yields 164 findings with 9 missed and 8 false positives (V08-60/61, separate
record, upstream context V07-72/73) - H08-12 unsupported vendor (arista) gets
**decisive CM-7/CM-7(1) FAIL findings from absent text** (V08-62, upstream
context V07-74) - H08-13 empty config yields **CM-7/CM-7(1) FAIL findings**
instead of REVIEW/none (V08-63) - H08-14 **step text advertises "ML risk
scoring (RandomForest)"** even when the formula fallback runs (V08-77) -
H08-15 **hostile inputs surface raw internal errors** - None evaluation ->
`AttributeError`, 1 MB device -> `StringDataRightTruncation` (V08-84/89).

REJECTED: H08-16 "happy-path generation contract fails" (REVIEW always becomes
a finding, PASS never leaks, counts = failed+review, unique ids, control/title/
reasoning/status/audit linkage all present - V08-11..24) - H08-17
"severity/confidence/risk assignment violates its contract" (V08-25..33) -
H08-18 "findings are not linked to compliance results / evidence" (V08-34..41
except the §12 key-shape row) - H08-19 "findings not persisted / endpoints do
not serve them" (counters, summary, status persistence, pagination, ownership
all correct - V08-43/44/45/48/50/51) - H08-20 "the two list endpoints return
different record sets" (same set, only order/filter differ - V08-52/57/59) -
H08-21 "pipeline does not wire findings end to end" (V08-70..76) - H08-22
"non-deterministic generation" (V08-78/79/80) - H08-23 "performance unusable
or super-linear" (linear ~5 ms/finding, full run 432 ms - V08-81/82/83) -
H08-24 "hostile inputs bypass validation entirely" (PASS-only/empty evals -> no
findings, invalid status rejected, injection payloads inert, unicode safe -
V08-85/86/87/88/90/91) - H08-25 "status vocabulary / NOT NULL / §19.2 indexes /
title limits are wrong" (all conform - V08-04/07/08/10) - H08-26 "fidelity
invariants violated" (V08-64..69).

## 7. Dataset sweep (480 real files, 480 processed, 0 errors)

`AuditExecutor.execute` (full production path incl. finding generation) over
the corpus: **71,236 findings**, 451.8 s total.

### 7.1 Findings produced

| Measure | Value |
|---|---|
| files with findings | **480 / 480** (101-200 findings per file) |
| severity (as stored) | high 27,887 (39.1%) - medium 25,791 (36.2%) - low 17,558 (24.6%) - **critical 0** - outside-vocab 0 |
| status | `open` 71,236 (100%) - other 0 |
| priority (§10.9 boundary) | P1 0 - P2 19,396 - P3 27,201 - **empty 24,639 (34.6%)** |
| evidence vs §12 8-key interface | **0 findings with all 8 keys**, 71,236 partial; structural gaps `reasoning`, `security_control` (+ empty `raw_config` on this path) |
| remediation vs §12 interface | present on all 71,236 - **every one missing ≥1 §12 key**; structurally absent `finding_id`, `finding_title`, `risk_description` |
| PASS leaked into findings | 0 |
| severity outside spec vocab | 0 |
| executor status | `completed` 480/480 |
| detected vendor (input) | cisco 323, unknown 73, juniper 44, fortinet 29, paloalto 11 |
| timing | p50 878 ms, p95 1,646 ms, max 2,825 ms per file |

By label: Cisco 252 files -> 39,369 findings (10 G-flagged), FRR 63 -> 9,176
(63), Juniper 41 -> 5,532 (5), Arista 38 -> 6,056 (38), PaloAlto 38 -> 4,788
(38), Fortinet 30 -> 3,780 (30), F5 11 -> 1,511 (11), A10 3 -> 441 (3),
NAPALM 4 -> 583 (0).

### 7.2 Category-G consequences on the corpus

| Flag | Files | Findings |
|---|---|---|
| `wrong_vendor_attributed` (= `label_detection_mismatch`) | **158** | 22,820 findings describe a device whose attributed vendor differs from its corpus label |
| `findings_on_unsupported_vendor` | **113** | 14,238 findings, **574 FAIL-derived** (CM-7 family regex verdicts on absent text) |
| `findings_on_empty_input` | 0 (no zero-byte files) | - |
| `pass_became_finding` | 0 | - |

Attribution follows detection, not the label: every finding on a mis-detected
file is stamped with the detected vendor (`affected_vendor == det_vendor`), so
the finding engine faithfully propagates Engine 02's mis-attribution into the
record the UI and reports show. Directory labels are hints only; no detection
accuracy is claimed (Engine 02 owns it).

## 8. Performance (measurement only - not a readiness score)

- Full executor over one corpus file: **p50 878 ms / p95 1,646 ms / max 2,825
  ms** (451.8 s for 480 files, cold interpreter included).
- `generate_findings` on a 95-finding audit: ~400 ms (~4.2 ms/finding,
  V08-81); full `AuditExecutor.execute` on a secure config: 432 ms
  (V08-83).
- Scaling is **linear**: 1,000 -> 5.1 ms/finding, 2,000 -> 5.3, 4,000 -> 5.5
  (V08-82); 10,000 findings = ~92 s. Profiling attributes the constant to one
  single-sample `sklearn.ensemble.RandomForest.predict` **per finding**
  (`findings.py:103` -> `_forest.py:1044`, joblib overhead per call) - a batch
  `predict` would collapse it; recorded as observation, not a conformance row.

## 9. Findings

### Blocking (must be fixed before this engine is ready)

1. **F1 - The Finding contract is four disagreeing shapes.** Spec §12 says
   `compliance_result_id + control_id + evidence: EvidenceChain`; the engine
   dataclass has no `compliance_result_id` but carries `audit_id/risk_score/
   priority/result/affected_platform` (V08-01), `FindingResponse` drops
   `control_id` so API consumers cannot link a finding to its control
   (V08-02, V08-58), and the table stores 15 columns where the §19.1 DDL
   declares 10 - the DDL omits `evidence` that §12 requires (spec contradicts
   itself; V08-05). (H08-01, H08-02)
2. **F2 - Findings do not carry the §12 evidence chain.** The API types
   evidence `Optional[dict]` (V08-06); the executor-built chain has
   `result_reasoning` instead of `reasoning`, no `security_control`, and empty
   `raw_config` - **0 of 71,236 corpus findings expose all 8 §12 keys**
   (V08-37, corpus), contradicting §20.2's "Findings always show evidence
   chain". Same drift engine 07 recorded at the chain source (V07-46/47,
   upstream context). (H08-04)
3. **F3 - Remediation on findings is not the §12 Remediation interface.**
   The executor builds `title/description/confidence` and never sets
   `finding_id`, `finding_title`, `risk_description` (V08-09,
   `executor.py:336-347`) - all 71,236 corpus findings miss ≥1 §12 key.
   (H08-05)
4. **F4 - The documented findings API does not exist and the two that do
   drift.** `GET /api/v1/audits/:id/findings` (§20.2) is not routed
   (V08-49); the live endpoints order differently - created_at DESC vs
   severity (V08-53) where the severity ordering is lexicographic, so
   **LOW lists before MEDIUM** (V08-54); `?severity=CRITICAL` returns **0
   rows** on both while the stored value is lowercase (V08-56); the status
   filter is enum-typed on one and free-form on the other, where an invalid
   value silently matches nothing instead of 422 (V08-55). (H08-08, H08-09,
   H08-10)
5. **F5 - Wrong/unsupported-vendor inputs produce findings that describe the
   wrong device (separate record).** The generator trusts
   `evaluation.vendor` (V08-60): juniper content declared cisco yields 164
   findings where the true-vendor audit yields 119 - **9 missed findings and
   8 false positives** (V08-61); unsupported arista + empty input yields
   decisive `CM-7/CM-7(1)` FAIL findings (V08-62); an empty configuration
   yields the same FAIL findings instead of §13.4 REVIEW (V08-63). Corpus:
   158 files / 22,820 findings attributed to a vendor that differs from the
   label, 113 unsupported files / 574 FAIL-derived findings. Upstream context
   only: Engine 07 V07-72/73/74/75. (H08-11, H08-12, H08-13)
6. **F6 - Status changes leave no history and notes vanish.**
   `PUT /findings/:id/status` writes only the status (V08-47) and creates no
   audit-trail row although `log_finding_update` ships in
   `repositories/audit_trail.py:142` with zero callers (V08-46) - §9.1 step 13
   "Audit Trail stores complete history" is unmet for the one workflow that
   changes finding state. (H08-06, H08-07)
7. **F7 - Severity vocabulary drifts from the spec at the source.**
   `Severity` defines lowercase `critical/high/medium/low`
   (`engines/compliance/models.py:15-20`) and persistence stores
   `severity.value` lowercase (V08-42) where §12 and DATA_MODEL mandate
   `CRITICAL|HIGH|MEDIUM|LOW`; the API uppercases on output but filters,
   reports and the database column all see the wrong case (this is the
   mechanism behind F4's dead severity filter). (H08-03)

Secondary: **F8** step text advertises "Generating N findings with ML risk
scoring (RandomForest)" (`audit_execution.py:434`) even when the ML model is
unavailable and the formula fallback runs (V08-77) - **F9** hostile inputs
surface raw internal errors: None evaluation -> `AttributeError` text
(V08-84), 1 MB `affected_device` -> `StringDataRightTruncation` at the driver
instead of an API validation error (V08-89) - **F10** observations for
Engine 09: 0 of 71,236 corpus findings are CRITICAL (the tier never fires) and
24,639 (34.6%) carry an empty priority because risk < 40 - blank priority is
not a §12/§10.9 value, recorded at the boundary, not adjudicated here.

### What works

The generation contract itself is solid: every FAIL/REVIEW evaluation becomes
exactly one finding, PASS never leaks (V08-11..14, V08-20/21, corpus 0 leaks),
ids are unique within and across runs (V08-22), each finding records the
control_id/title/reasoning/status/audit/device linkage the engine record has
(V08-16..19/24), severity maps without the silent MEDIUM default and
confidence is copied from the evaluation within [0,1] (V08-25..28), risk stays
0-100 and increases with severity (V08-29/31), evidence is linked and ordered
per finding (V08-34..36/38..41), persistence round-trips - severity/status
counters, summary buckets, status persistence, pagination, ownership and 404
all correct (V08-43/44/45/48/50/51/74/75/76), the two list endpoints return
the same record set (V08-52), status enum and injection payloads are rejected
(V08-86/87/88), fidelity invariants hold - no fabricated severity, no
"failed" wording on REVIEW findings (V08-64..69), the offline pipeline runs
the findings step end to end (V08-70..73), generation is deterministic
(V08-78..80), and performance is linear at ~4-5 ms/finding with a 432 ms full
executor run.

## 10. Cross-engine baseline (E01-E07 artifacts, read-only)

- Engine 01 (PARTIAL), 02 (FAIL), 03 (FAIL), 04 (FAIL), 05 (FAIL), 06 (FAIL),
  07 (FAIL). Category G cites Engine 07 only as *upstream context* (V07-72/73/
  74/75 for vendor selection, V07-46/47 for evidence-chain drift) - never
  assumed fixed, never re-tested. Detection accuracy remains Engine 02's claim
  (158 label mismatches recorded as input, not adjudicated).
- Full suite before E06: 845 / 819 / 26 -> after E06: 950 / 924 / 26 -> after
  E07: 1045 / 1019 / 26 -> after E08: **1136 collected / 1110 passed / the
  same 26 pre-existing failures** (91 new tests). Failure composition
  unchanged: 6 `test_benchmark_execution.py`, 2 `test_detection.py`, 2
  `test_frontend_integration_support.py`, 7 `test_juniper_benchmark.py`, 2
  `test_phase5_integration.py`, 6 `test_phase8_hardening.py`, 1
  `test_vertical_slice.py::test_cisco_ios_full_pipeline`.
- `git diff -- backend/app/` **empty**; `git status --porcelain --
  backend/app/` **empty**. Working tree matches the recorded pre-existing
  baseline (requirements.txt, frontend package files, plus the untracked
  validation/artifacts/scripts directories).
- New files only: `tests/validation/test_v08_findings.py`,
  `scripts/engine_validation/{sweep,report}_findings.py`,
  `artifacts/engine_validation/08_findings/*`, plus the conftest engine
  mapping for `08_findings`. Throwaway probe `_probe08.py` deleted.

## 11. NOT APPLICABLE / NOT VERIFIABLE

- **ML model quality** - deferred by instruction (all 12 engines validated
  before ML); only the *claim* in the step text is tested (V08-77).
- **Risk formula / priority semantics (§10.9)** - Engine 09 owns them; this
  engine records only that risk_score/priority are computed inside §10.8 and
  discarded at persistence, and that blank priorities exist (F10).
- **Detection accuracy** - Engine 02 owns it; category G records attribution
  consequences only.
- **Evidence content correctness ("is the chain true?")** - Engine 07 owns the
  chain source; here only interface completeness and linkage are tested.
- **Remediation content quality** - Engine 10 owns fix content; only the §12
  shape is tested (F3).
- **Whether the spec's DDL or §12 interface should win** on the missing
  `evidence` column - the spec contradicts itself; recorded as drift (V08-05),
  not adjudicated.
- **UI rendering of findings (§20.7)** - frontend not exercised in this
  engine's contract.
- **Concurrency, locking, transactional behaviour** - single-threaded probes.
- **Authentication/authorization testing** - not in this engine's contract
  (ownership/404 behaviour only).
- **Postgres write performance at audit volume** - persistence verified for
  correctness on small runs; no bulk-insert benchmark.

## Limitations of this validation

- Corpus sweep takes detection output as *input*, not truth; the mismatch flag
  does not decide who is right (Engine 02 owns that).
- Category G probes exercise the generator's public contract with a declared
  vendor; production reachability through the executor's re-detection is noted
  per finding (F5) and corroborated by the 158 corpus files.
- The 8-key/§12 shape checks are interface checks, not semantic checks of the
  chain's content.
- Performance numbers are single-machine measurements, not a readiness score;
  the ~5 ms/finding constant is a profiling observation, not a conformance
  requirement.
- Hypothesis conclusions derive only from the recorded evidence rows; no claim
  goes beyond them.

---

## 12. Verdict

**FAIL - NOT READY.** Seven blocking findings:

- **F1** four disagreeing Finding shapes; API response cannot link findings to
  controls; DDL/interface contradiction.
- **F2** findings expose no complete §12 evidence chain (0/71,236).
- **F3** remediation on findings is not the §12 interface (all 71,236 miss
  keys).
- **F4** documented list endpoint missing; the two live endpoints drift in
  order, severity ranking and filter validation; `?severity=CRITICAL` is dead.
- **F5** wrong/unsupported-vendor inputs produce findings describing the wrong
  device (158 corpus files, 9 missed + 8 false on the juniper probe, 574
  FAIL-derived on unsupported files, empty config -> decisive FAILs).
- **F6** status changes leave no audit history; notes are dropped.
- **F7** severity vocabulary lowercase at source and in storage vs the spec's
  `CRITICAL|HIGH|MEDIUM|LOW`.

What is solid: the generation contract, evidence *linkage*, persistence
round-trip, determinism, fidelity invariants and linear performance.

**Next:** Engine 09 (Risk Engine, spec §10.9) - pending user approval.
