# ENGINE_READINESS_SUMMARY - Engine 07 - Control Selection / Compliance (spec 10.7)

**Scope:** `backend/app/benchmarks/{registry,execution,models,cisco_ios_xe_controls,
juniper_junos_controls,nist_sp800_53_controls,framework_mappings}.py`,
`backend/app/engines/compliance/{models,loader,engine,evidence,executor,findings,
cisco_controls}.py`, `backend/app/api/v1/{compliance,audit_execution,reports}.py` +
`app/models.ComplianceResult` + their contract with `docs/PROJECT_MASTER_SPEC.md`
(§9.1 step 6, §10.7, §12, §13.1-13.4, DDL `compliance_results`)
**Evidence:** 95 pytest rows (95 passed, 0 failed) - 480-file corpus sweep (0 errors) -
3 runtime probe suites - 0 production files modified
**Overall verdict:** **FAIL** (framework selection no-op, case-dependent selection,
mislabelled framework rows, partial evidence chains, dual score, wrong-vendor verdicts,
missing confidence model - not determinism, speed or verdict integrity)
**Date:** 2026-09-25

---

## Scoreboard

| Status | Count | % |
|---|---|---|
| PASS | 48 | 51% |
| PARTIAL | 0 | 0% |
| FAIL | 47 | 49% |
| **Total** | **95** | 100% |

| Classification | Count |
|---|---|
| CONFIRMED BEHAVIOR | 48 |
| BUG | 18 |
| DESIGN LIMITATION | 16 |
| MISSING | 8 |
| RECOMMENDATION | 5 |

| Category | Rows | Status |
|---|---|---|
| A spec structure (§13.1/§13.2) | 10 | PASS 5, FAIL 5 |
| B control selection (§10.7 / §9.1 step 6) | 17 | PASS 8, FAIL 9 |
| C evaluation logic (§13.3/§13.4) | 18 | PASS 11, FAIL 7 |
| D evidence chains (§13.3 step 3 / §12) | 9 | PASS 5, FAIL 4 |
| E framework attribution + persistence | 8 | PASS 2, FAIL 6 |
| F drift: legacy vs canonical | 9 | PASS 1, FAIL 8 |
| G SEPARATE RECORD - wrong/unsupported vendor | 4 | PASS 0, FAIL 4 |
| H semantic fidelity invariants | 3 | PASS 3, FAIL 0 |
| I pipeline integration (§9.1) | 6 | PASS 5, FAIL 1 |
| J determinism | 3 | PASS 3, FAIL 0 |
| K performance (measurement only) | 3 | PASS 3, FAIL 0 |
| L hostile / boundary input | 5 | PASS 2, FAIL 3 |

---

## Hypotheses (16 CONFIRMED - 15 REJECTED - 0 unverifiable)

CONFIRMED: H07-01 **`framework`/`framework_version` are no-ops** (CIS=NIST=BOGUS
identical, version never persisted) - H07-02 **case-dependent selection** (`Cisco` drops
53 CIS, `JUNOS` drops 17 juniper, exact-case registry keys) - H07-03 **API filters drop
arguments** (vendor-only returns all 70, platform-only ignores platform, alias missing) -
H07-04 operator vocabularies drift (spec `in` missing, registry `*_or_equal` falls
through to equals, unknown operator silently equals) - H07-05 six controls target
non-existent model paths (permanent REVIEW) + duplicate control_id overwrites the index -
H07-06 **framework labels inferred from id shape and user request**, report list
hardcodes `CIS`, advertised versions don't exist - H07-07 **confidence model
unimplemented** (no rule confidence, normalization confidence constant 0.0, <70% trigger
only in dead path) - H07-08 **evidence chains deviate from §12** (missing keys,
`parsed_value` never set, decisive results without raw evidence / normalized_value,
regex PASS/FAIL) - H07-09 **two overall scores per run** (46.9 vs 95.5) - H07-10 wrong /
unsupported-vendor verdicts incl. empty config -> 2 FAILs (separate record) - H07-11 dual
control inventories with drift (10 vs 196, no NIST in legacy, ios vs ios_xe, is_set/
regex_match semantics) - H07-12 persistence drift (lowercase result enum, DDL link column)
- H07-13 unknown vendors parsed with `CiscoIOSParser` - H07-14 hostile inputs lose error
signals (None -> AttributeError text, failed audit with no failed step, invalid regex ->
confident FAIL) - H07-15 dead module (`framework_mappings`) + dead imports - H07-16
`benchmark_id` from `controls[0]` understates the dual baseline.

REJECTED: H07-17 "selection loses controls under canonical inputs" (179/143/alias all
correct) - H07-18 "operator truth tables wrong" - H07-19 "verdicts fabricated from
missing/manual/empty input" (all REVIEW) - H07-20 "evaluation non-deterministic" - H07-21
"pipeline not end-to-end / findings not wired" - H07-22 "performance unusable /
super-quadratic" - H07-23 "API inventory or framework inference wrong" - H07-24 "legacy
pipeline still executes" (imported, never instantiated) - H07-25 "confidence/remediation
disagree across layers" - H07-26 "inventory misses §13.2 structure" - H07-27 "alias or
NIST fallback broken" - H07-28 "conflicts/negations give unsafe verdicts" - H07-29
"persisted score/counts inconsistent" - H07-30 "per-row evidence lacks operator/reasoning
or is not persisted" - H07-31 "unicode breaks evaluation".

---

## Blocking findings (must be fixed before this engine is ready)

1. **F1 - Framework selection does not exist.** `AuditExecutor.execute` declares
   `framework`/`framework_version` (`executor.py:134-135`) and never reads either; the
   API forwards the user's choice into a dead argument; probe: CIS / NIST / **BOGUS** all
   return the identical 179 results; no persisted row carries framework_version (§12).
   (V07-17/55, H07-01)
2. **F2 - Selection and filters depend on caller casing and call path.** Exact-case
   registry keys: `vendor="Cisco"` -> 126 instead of 179 (53 CIS silently gone),
   `platform="JUNOS"` -> 126 (17 juniper gone); alias only for cisco; API vendor-only
   requests ignore vendor (fortinet -> all 70 controls), platform-only filter ignores
   platform (106 vs 51), API has no alias (ios -> 0). A silent drop looks like a
   compliance result. (V07-14/15/16/19/20/21, H07-02/03)
3. **F3 - Framework labels are inferred, not stored, and reports read them.** Controls
   have no framework field; persistence stamps `is_nist = id-shape` else the **user's
   requested** framework (probe: NIST request stores CIS rows as NIST;
   `SEC-5` -> NIST); `reports.py:54` hardcodes `framework="CIS"` while the same response
   filters on the persisted column; advertised versions (2024.1) don't exist on controls
   (v2.2.1). (V07-03/25/57/58/62, H07-06)
4. **F4 - Evidence chains do not implement §12/§13.3.** Canonical evidence uses
   `raw_config_lines`/`result_reasoning` instead of `raw_config`/`reasoning`, has no
   `parsed_value`/`security_control`; persisted `parsed_value` is None on all rows; 2 of
   77 decisive value results (AC-4, SC-7) have no line numbers or snippet; multi-block
   PASS 1.2.8 records null `normalized_value`; 106 regex-driven controls PASS/FAIL with
   no normalized value where §13.4 says REVIEW. (V07-37/38/46/47/48/49, H07-08)
5. **F5 - Two overall scores per run.** Same run (84/4/91): **46.9** persisted
   (passed/evaluated) vs **95.5** on the evaluation object (passed/(passed+failed)); §12
   mandates one number. (V07-42, H07-09)
6. **F6 - Wrong/unsupported-vendor inputs produce decisive verdicts (separate record).**
   Engine "trusts the caller"; production reachability via detection errors - 158/480
   corpus files disagree with their label; juniper-declared-cisco gets 15 PASS (incl.
   2.1.13-2.2.4); 113 unsupported corpus files received 14,238 raw-regex NIST
   evaluations with **574 decisive FAILs**; empty config -> 126 evaluations, 2 FAILs
   instead of REVIEW. (V07-72/73/74/75 + corpus, H07-10)
7. **F7 - Confidence model unimplemented.** No rule-confidence field, normalization
   confidence constant 0.0 on every evaluation, confidences hardcoded, §13.4 <70% REVIEW
   trigger only in the never-executed legacy path. (V07-43/44, H07-07)

Secondary: **F8** operator vocabulary drift + silent equals-fallback (unknown operator ->
FAIL conf 0.95; 3 juniper controls wrong in registry path) - **F9** six controls with
non-existent model paths (permanent REVIEW) + duplicate-id index overwrite - **F10** dual
inventories (196 vs 10, legacy has no NIST, ios vs ios_xe excludes legacy rules,
is_set('') True-vs-False, regex search-vs-match, dead `framework_mappings`, dead imports)
- **F11** persistence drift (lowercase `pass/fail/review` vs §12 enum; DDL column vs
interface conflict) - **F12** `CiscoIOSParser` fallback for unknown vendors - **F13**
hostile-input error signals lost (None -> AttributeError text; failed audit with zero
failed steps; invalid regex -> confident FAIL everywhere).

---

## What is solid

Deterministic verdicts/scores/inventory across repeat runs - supported operator truth
tables match §13.3 - **no fabricated verdicts** (missing -> REVIEW, manual -> REVIEW,
empty file never PASSes, conflicts -> REVIEW, negations invert) - end-to-end offline
pipeline INGEST->...->FINDINGS with findings derived from the same evaluation and one row
per configuration - correct canonical selection (cisco 179 = 53+126, juniper 143 =
17+126, ios alias, NIST fallback, no duplicates) - correct 70 CIS / 126 NIST inventory -
evidence fields where values exist (expected/actual/operator/reasoning, remediation
null-for-PASS, JSONB persisted) - self-consistent persisted score/counts - legacy pipeline
truly retired - ms-level performance (2.8 ms engine build, 5-9 ms/179 controls, factor
1.38 scaling) - unicode-safe.

## Corpus measurements (480 files - 0 errors - 78,188 verdicts)

| Measure | Value |
|---|---|
| selection | CIS+NIST 364, NIST-only 116 (evaluated {179: 320, 143: 44, 126: 116}) |
| verdicts | 6,952 PASS / 15,266 FAIL / 55,970 REVIEW |
| decision source | mapped 6,579/11,667/12,566; **raw-regex 373 PASS + 3,599 FAIL = 3,972 decisive (17.9% of all decisive) without normalized values** |
| G flags | `label_detection_mismatch` **158**, `unsupported_vendor_evaluated` **113**, `regex_verdicts_on_unsupported_vendor` **113** |
| unsupported outcomes | unknown 73 files / 9,198 eval / 146 FAIL (all regex) - fortinet 29 / 3,654 / 406 FAIL (58 regex) - paloalto 11 / 1,386 / 22 FAIL (all regex); **0 PASS** |
| detected | cisco 323, juniper 44, unknown 73, fortinet 29, paloalto 11 |
| by label | Juniper 41 (5 detected cisco) - FRR 63 (33 detected cisco) - Fortinet 30 + PaloAlto 38 all NIST-only - empty 0, zero-evaluated 0 |
| timing | 58.4 s total (avg ~121 ms/file incl. detection + interpreter) |

Directory labels are hints only; no detection accuracy is claimed (Engine 02 owns it).

## Performance (measurement only)

Engine construction **2.8 ms** (cold first run 1,688 ms incl. imports); warm evaluation of
179 controls **5.4-9.1 ms**; full executor run ~595-600 ms cold; scaling 100 KB = 731 ms
vs 239 KB = 14.2 s (factor 1.38 for 2.4x input - super-linear but bounded); sweep 58.4 s
for 480 files.

## Regression / integrity

- Full suite before E06: 845 collected / 819 passed / 26 failed -> after E06: 950/924/26
  -> after E07: **1045 / 1019 / the same 26 pre-existing failures** (95 new tests).
  Failure composition unchanged: `test_benchmark_execution` 6, `test_detection` 2,
  `test_frontend_integration_support` 2, `test_juniper_benchmark` 7,
  `test_phase5_integration` 2, `test_phase8_hardening` 6, `test_vertical_slice` 1.
- `git diff -- backend/app/` **empty**; `git status --porcelain -- backend/app/`
  **empty**; working tree matches the recorded pre-existing baseline.
- New files only: `tests/validation/test_v07_compliance.py`,
  `scripts/engine_validation/{sweep,report}_compliance.py`,
  `artifacts/engine_validation/07_compliance/*`, plus the conftest engine mapping for
  `07_compliance`. Throwaway probes `_probe07*.py` deleted.
- Engine 05 treated as **upstream context only** per the user's directive - cited where
  an unmapped path forces regex verdicts (V07-74) or a broken model path (V07-05, cross-ref
  V05-55), never assumed fixed, not re-tested. Detection cited the same way for category
  G reachability (Engine 02 owns accuracy).

## NOT APPLICABLE / NOT VERIFIABLE

ML quality (deferred) - detection accuracy (Engine 02) - normalization correctness
(Engine 05) - which denominator the "single" overall_score should use (spec says one
number, not which - dual value recorded, not adjudicated) - `configuration_id` vs
`normalized_configuration_id` (the spec contradicts itself between §12 and the DDL -
recorded as drift) - registry `evaluate_control` live-reachability (no API request logs)
- concurrency/locking/transactions (single-threaded probes) - auth testing (not in
contract) - bulk Postgres write performance.

## Limitations of this validation

Corpus sweep takes detection as input, not truth (mismatch flag does not decide who is
right); category G probes exercise the engine's public contract - production reachability
through the executor's re-detection is noted per finding; confidence is measured for
implementability of the spec formula, not for "right" values (no ground truth exists);
performance numbers are single-machine measurements, not a readiness score; hypothesis
conclusions derive only from the recorded evidence rows.

---

**Readiness:** NOT READY - 7 blocking findings (F1, F2, F3, F4, F5, F6, F7).
**Next:** Engine 08 (pending user approval).
