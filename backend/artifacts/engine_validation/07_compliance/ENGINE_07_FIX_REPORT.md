# ENGINE_07_FIX_REPORT — Control Selection / Compliance (§9.1 step 6, §10.7, §12, §13.1–13.4, §15 DDL)

**Verdict: READY.** All 7 blocking findings fixed, all secondary findings resolved,
116/116 targeted rows PASS, corpus contract PASS with 0 violations, migration 006
executed 9/9, full suite 1329 passed / 1 pre-existing unrelated failure.

**Stop: Engine 08 NOT started. Awaiting explicit approval.**

---

## 1. Executive Summary

Engine 07 (Control Selection / Compliance) was revalidated FAIL/NOT READY with 7
blocking findings (F1–F7) and 6 secondary findings (F8–F13). The root cause of
nearly every finding was the absence of a single canonical contract: framework
selection was a dead argument, vendor/platform filtering was case-sensitive and
scattered across three call paths, framework labels were inferred from control-id
shape, evidence used a competing schema with unpopulated keys, two score formulas
coexisted, wrong/unsupported vendors received decisive NIST verdicts, and the
§13.3 step-4 confidence model existed only in a retired code path.

The fix introduces one domain-level contract module,
`backend/app/benchmarks/selection.py` (normalization, operator vocabulary,
score, confidence, selection service, control validation), stamps authoritative
framework/version/rule-confidence metadata on every control at inventory build
time, rebuilds the evidence chain on the eight §12 keys, composes confidence
from both spec inputs with the 0.70 REVIEW gate in the canonical path, enforces
vendor safety boundaries (unsupported / mismatch / empty / failed normalization
→ explicit zero-verdict statuses), persists control-owned metadata with an
uppercase §12 result enum (migration 006), and retires the legacy pipeline
explicitly (deprecated markers, zero production imports).

Measured outcomes:

| Check | Before | After |
|---|---|---|
| Targeted V07 rows | 95 rows: 54 PASS / 41 FAIL (pre-fix baseline 48/47) | **116 rows: 116 PASS** |
| Hypotheses H07-01–H07-31 | 16 CONFIRMED / 15 REJECTED | **31/31 REJECTED** |
| Framework CIS/NIST/BOGUS | identical 179-control runs | CIS 53 / NIST 126 / dual 179; BOGUS raises |
| Unsupported-vendor corpus verdicts | 113 files, 14,238 evals, 574 decisive FAILs | **141 files, 0 evaluations, 0 verdicts** |
| Corpus regex-miss FAILs | 3,599 | **56** (negated-match only; miss → REVIEW) |
| Corpus contract checks | n/a (new) | **C1–C3/C4–C6/C2: 0 violations** |
| Migration 006 | n/a | **9/9 executed checks PASS** |
| Full suite | 1287 passed / 22 failed (E06 close-out) | **1329 passed / 1 failed (pre-existing, unrelated)** |

---

## 2. Scope

Production:

- `backend/app/benchmarks/selection.py` (NEW — canonical contract)
- `backend/app/benchmarks/{models,registry,execution}.py`
- `backend/app/benchmarks/{cisco_ios_xe,juniper_junos,nist_sp800_53}_controls.py`
  (attribution stamping in `get_registry()`)
- `backend/app/benchmarks/framework_mappings.py` (REFERENCE ONLY marker)
- `backend/app/engines/compliance/{models,loader,engine,evidence,executor,findings,cisco_controls}.py`
- `backend/app/api/v1/{compliance,audit_execution,reports}.py`
- `backend/app/schemas/__init__.py` (EvidenceChain `reasoning` key)
- `backend/alembic/versions/006_uppercase_compliance_results.py` (NEW)

Validation/evidence:

- `backend/tests/validation/test_v07_compliance.py` (95 → 116 rows, A–R)
- `backend/tests/validation/test_v03_detection.py` (V03-57 refined for F6)
- `backend/tests/validation/test_v04_parsing.py` (V04-38 call-contract update)
- `backend/tests/validation/test_v08_findings.py`, `test_v09_risk.py`
  (mechanical §12 key renames only)
- `backend/tests/{test_benchmark_execution,test_juniper_benchmark,test_phase8_hardening,test_compliance}.py`
  (field renames + corrected expectations; one test typo fixed)
- `backend/scripts/engine_validation/{sweep_compliance,report_compliance,validate_migration_006}.py`
- `backend/artifacts/engine_validation/07_compliance/`

Out of scope (untouched semantics): Engine 05 normalization (consumed only),
Engine 02 detection (consumed only), findings risk math, reporting PDF layout.

---

## 3. Files Changed

See §2. No commits were made. Pre-fix artifact backups were stored with the
`_prefix` suffix next to the regenerated artifacts
(`raw_results_prefix.jsonl`, `summary_prefix.json`, `test_results_prefix.csv`,
`dataset_results_prefix.csv`, `dataset_summary_prefix.json`).

---

## 4. Contract

Canonical flow (one implementation of each step):

```
Configuration → Vendor/Platform (selection.normalize_*) → Framework Selection
(validate CIS/NIST/dual; versions from inventory) → Control Selection
(select_for_evaluation: vendor CIS + universal NIST, deduped, ordered) →
Normalized Configuration (single, consumed) → Control Evaluation (canonical
operators; mapped value or explicit-regex raw evidence) → Confidence
(normalization × rule; <0.70 → REVIEW) → EvidenceChain (§12 keys + metadata)
→ ControlResult → ComplianceResult (overall_score = passed/evaluated) →
Findings (FAIL/REVIEW subset, identical evidence) → Persistence (control-owned
framework/version, uppercase enum) / API / Reports (derived, never hardcoded)
```

Safety boundaries (zero evaluations, zero decisive verdicts, named status):
`unsupported_selection`, `vendor_mismatch`, `empty_input`,
`normalization_failed`, plus typed errors (`UnsupportedFrameworkError`,
`UnknownFrameworkVersionError`, `UnsupportedVendorError`,
`InvalidControlError`/`DuplicateControlError`, `ComplianceInputError`).

---

## 5. F1 Framework Selection — FIXED

- `AuditExecutor.execute` validates `framework`/`framework_version` BEFORE any
  work and forwards both to `BenchmarkExecutionEngine.execute` (V07-17, V07-101).
- `normalize_framework`: strip + case-insensitive; `None` → explicit
  `CIS+NIST` dual mode; unknown → `UnsupportedFrameworkError`
  (V07-99/101/113).
- Versions come from the loaded inventory (`versions_for_framework`);
  unknown versions → `UnknownFrameworkVersionError` (V07-100/101).
- Measured: CIS → 53 controls, NIST → 126, dual → 179; BOGUS raises
  (previously all three identical).
- API advertises exactly the carried versions (V07-25: CIS v2.1.0/v2.2.1,
  NIST 5.0); framework list endpoint derives counts/categories from controls
  (V07-84).

## 6. F2 Selection / Filtering — FIXED

- One `ControlSelectionService` used by engine, executor and API; one alias
  map imported from the §25 canonical platform identity (V07-14/15/16/21).
- `Cisco/cisco/CISCO`, `JUNOS/junos`, `ios/ios_xe` resolve identically;
  vendor-only, platform-only, vendor+platform, framework-only,
  framework+version and framework+vendor+platform filters all apply
  conjunctively (V07-19/20/21); unsupported combinations return empty,
  never another vendor's controls.
- Registry keys canonical at register and lookup; platform-only filter fixed;
  duplicate conflicting ids raise instead of overwriting (V07-10).

## 7. F3 Framework Attribution — FIXED

- Every control carries `framework`/`framework_version` stamped by its
  defining benchmark module (V07-03); API responses read them (V07-24).
- Persistence writes `control.framework`/`control.framework_version`
  verbatim — the id-shape heuristic and request-echo are deleted
  (V07-57/58).
- Reports list derives framework per audit from rows; the `framework="CIS"`
  literal is deleted (V07-62); report filter normalizes input, 422 on
  unknown (V07-82 + R tests).

## 8. F4 Evidence — FIXED

- `BenchmarkEvidence` leads with the eight §12 keys; `parsed_value` is the
  vendor statement from the normalization mapping (multi-block: observed
  block raws); `security_control` is the control id (V07-46/47/49).
- Line numbers come from mapping source paths first, keyword fallback
  second; decisive verdicts without reconstructable evidence become REVIEW
  via the sufficiency gate (V07-48).
- Raw-regex rule: explicit-regex controls may decide from matched raw
  evidence (pattern recorded); regex miss → REVIEW unless the control
  explicitly defines absence as verified FAIL (`absence_is_fail`, default
  False); negated controls keep absence-means-compliant semantics
  (V07-37/38/40).
- A real bug found during validation and fixed: the keyword display
  fallback briefly fed the regex verdict (`_match_audit_regex` now
  separates verdict match from display lines).

## 9. F5 Overall Score — FIXED

- ONE formula: `overall_score(passed, evaluated)` = passed over ALL
  evaluated controls, rounded to 1 decimal (REVIEW counts as non-pass).
  Rationale (documented in code): excluding REVIEW lets a 1-pass/178-REVIEW
  audit score 100; the conservative denominator cannot be inflated by
  unevaluable controls.
- Used identically by the benchmark engine, the executor mapping,
  persistence and reports (V07-42/45, V07-116 five-layer agreement test).

## 10. F6 Wrong / Unsupported Vendor — FIXED

- Declared vs detected normalized (vendor, platform) mismatch →
  `vendor_mismatch`, zero evaluations (V07-72/73/111).
- Unsupported declared vendor → `unsupported_selection`, zero evaluations
  (V07-18/74); no Cisco substitution anywhere (V07-83 retained).
- Empty input → `empty_input`; failed normalization stops the audit
  (V07-75/77).
- Corpus: unknown 106 + fortinet 29 + paloalto 6 files → 0 evaluated,
  0 PASS, 0 FAIL (pre-fix: 113 files, 14,238 evals, 574 FAILs).

## 11. F7 Confidence — FIXED

- `BenchmarkControl.rule_confidence` stamped from the control's own
  evaluability (manual 1.0 / mapped 0.95 / explicit-regex 0.85 /
  unevaluable 0.5).
- Normalization confidence comes from the per-path mapping confidence;
  raw-evidence decisions use the documented `RAW_MATCH_CONFIDENCE = 0.85`.
- Composition is multiplicative (bounded, monotonic, non-inflating);
  < 0.70 → REVIEW in the canonical path (V07-43/44; pairs
  .95×.95 / .80×.60 / .50×.90 / .50×.50 verified).
- No hardcoded final confidences remain on decisive paths.

## 12. F8 Operators — FIXED

- One vocabulary (`OPERATOR_VOCABULARY`) + one implementation
  (`apply_operator`), shared by engine and registry; `in` implemented;
  `*_or_equal` correct in both; unknown operators raise
  `InvalidControlError` (never silent equals) and are rejected at registry
  load (V07-07/08/28–34).

## 13. F9 Model Paths / Control Integrity — FIXED

- Registry construction validates operator, regex compilability and model
  path against the Universal Security Model; conflicting duplicate ids
  raise (V07-09/10). The six historically-bad paths are gone (V07-05
  passes; model fixed upstream in E05, asserted here, not claimed).

## 14. F10 Inventory / Legacy Drift — FIXED

- Legacy `ControlLoader`/`RuleEngine`/`cisco_controls` carry explicit
  DEPRECATED markers; the executor imports nothing from them (V07-64/71);
  canonical inventory is 196 (70 CIS + 126 NIST), counts preserved
  (V07-01/63/65/66).
- `framework_mappings.py` is explicitly REFERENCE ONLY (STIG crosswalk,
  Manual-only, zero production evaluation imports) (V07-68).
- Dead `_build_registry` duplicates noted; registry/operator semantics
  unified (V07-67/69/70).

## 15. F11 Persistence — FIXED

- Rows carry control-owned framework/version, uppercase §12 enum,
  full §12 evidence JSONB, and the `normalized_configuration_id` link —
  the §12 interface's relationship and the actual data flow (the spec DDL's
  `configuration_id` disagrees with the spec's own §12 interface; decision
  documented in V07-60).
- Single row-builder (`build_compliance_result`) shared by pipeline and
  tests (V07-54/102/103/105).
- Migration 006 uppercases legacy rows in place; executed 9/9 with
  downgrade + round trip on the throwaway DB (V07-104 +
  `migration_results.json`).

## 16. F12 Vendor Fallback — FIXED

- No `unknown → CiscoIOSParser` and no `unknown → Cisco controls` anywhere
  in the compliance path; unsupported vendors get `None`/boundary before
  evaluation (V07-83 retained + V07-18/74/111).

## 17. F13 Error Handling — FIXED

- None/non-string/NUL inputs → typed `ComplianceInputError` (V07-91/96/97/98).
- Validation failure marks the validation step FAILED with issue codes
  (V07-92).
- Invalid control regex → load-time `InvalidControlError`; direct
  evaluation → REVIEW, never confident FAIL (V07-93).
- Unknown operator → typed error (V07-34); unknown framework/version →
  typed errors/422s (V07-99/100/101).

## 18. API Changes

- `GET /frameworks` + `GET /frameworks/{id}/controls`: canonical selection
  service; conjunctive vendor/platform/framework/version filters;
  framework_version parameter added; 422 on unknown framework/version;
  attribution from control metadata.
- Audit pipeline persists framework/version/score per the canonical
  contract; hardcoded "179 controls" progress string generalized.
- Reports list/detail derive framework and score from persisted rows.

## 19. Security Validation

- Categories G/H/L/Q + sweep C1/C3: 0 violations. Invariants verified:
  no exception becomes PASS (typed errors/boundaries), no missing evidence
  becomes FAIL (REVIEW + sufficiency gate), no unsupported vendor becomes a
  vendor audit, no unknown framework falls back, no unknown operator becomes
  equals, no duplicate silently overwrites, no label inferred from id shape,
  raw secrets never logged (evidence carries matched lines only), regex is
  pure `re` matching (no code/file access), no fabricated confidence
  (composition or REVIEW).

## 20. Determinism

- Repeat runs, fresh engine instances, fresh evaluator instances:
  identical control order, verdicts, confidence, reasoning, lines,
  findings, score, framework/version (V07-85/86/87/106/107).
- Sweep C2: 40 corpus files re-run on fresh engines, 0 mismatches.

## 21. Performance

- Registry build + validation (196 controls): ~214 ms (V07-108, < 10 s).
- 20 dual selections: ~4 ms (V07-109, < 5 s).
- Full 179-control executor audit: ~2.2 s (V07-110, < 60 s).
- 179-control evaluation 5–9 ms range preserved; corpus sweep 44.8 s for
  480 files (measurement only; no validation weakened).

## 22. Corpus Sweep

- 480 files: 307 completed (269×179, 38×143), 147 normalization_failed,
  25 unsupported_selection, 1 typed NUL boundary; 0 untyped errors.
- Verdicts: 3,835 PASS / 2,724 FAIL / 47,026 REVIEW (mapped 1,780/2,668/
  18,089; regex 2,055/56/28,937).
- Contract checks C1/C3/C4-C5-C6/C2: 0 violations; verdict PASS.
- Directory labels used as diagnostic metadata only (`label_detection_mismatch`
  is informational; Engine 02 owns accuracy).

## 23. Regression

- Targeted: V07 116/116; V03+V04 suites 289/289 combined with V07.
- Neighbors fixed as part of this work (all green now):
  `test_benchmark_execution`, `test_juniper_benchmark`,
  `test_phase8_hardening`, `test_compliance`, `test_benchmark_registry`,
  V08, V09 — including 18 previously-failing tests corrected to the
  specified behavior and one test typo (`cfgss`).
- Full suite: **1329 passed / 1 failed**.
- The single failure,
  `test_frontend_integration_support.py::TestRemediationPopulation::test_juniper_findings_have_remediation`,
  is pre-existing and unrelated: verified failing on the pristine tree
  (both frontend tests failed there; this work fixed the other one).
  Cause: E02 validation rejects `juniper_insecure.txt` as
  `NO_SUBSTANTIVE_CONTENT`, so the executor never reaches findings.
- Cross-engine tests updated only where they pinned superseded contracts
  (V03-57 mismatch boundary, V04-38 framework kwargs, V08/V09 §12 keys),
  each cross-referenced to the E07 finding.

## 24. Remaining Limitations

- `absence_is_fail` defaults False on all current controls (extension point
  for control authors; no control currently claims it).
- REVIEW confidence on forced reviews reuses available inputs (0.5 only
  when no input exists) — documented, never decisive.
- The spec's own DDL disagrees with its §12 interface on the link column
  name; the interface + data flow were followed and the disagreement
  recorded (V07-60).
- Corpus `label_detection_mismatch` (202 files) is diagnostic; detection
  accuracy belongs to Engine 02.
- Performance figures are single-machine measurements.

## 25. Cross-Engine Integration

- Engine 05 treated as upstream context only: normalization consumed
  (single authoritative result, per-path confidences, FAILED boundary),
  never revalidated, never claimed fixed. Unmapped paths force regex/REVIEW
  handling here (V07-74 pattern).
- Engine 02 detection consumed (informational + mismatch cross-check);
  accuracy not judged here.
- Findings (E08) consume the canonical evaluation object with identical
  evidence (V07-115 pins the subset relation).

## 26. Final Readiness Verdict

| Requirement | Status |
|---|---|
| F1 fixed | YES |
| F2 fixed | YES |
| F3 fixed | YES |
| F4 fixed | YES |
| F5 fixed | YES |
| F6 fixed | YES |
| F7 fixed | YES |
| F8 resolved | YES |
| F9 resolved | YES (duplicates fail fast; paths valid) |
| F10 canonicalized | YES |
| F11 persistence aligned | YES |
| F12 no silent Cisco fallback | YES |
| F13 hostile input safe | YES |
| Targeted tests pass (116/116) | YES |
| Corpus sweep passes (0 violations) | YES |
| Security tests pass | YES |
| Deterministic runs match | YES |
| No unexplained regression | YES (1 pre-existing unrelated) |
| Framework selection changes selection | YES (53/126/179) |
| Framework/version metadata authoritative | YES |
| One overall score | YES (five-layer agreement test) |
| Evidence chain complete | YES |
| Confidence calculated | YES |
| Unsupported vendors blocked | YES (0 corpus verdicts) |
| API + executor share selection | YES |
| Findings derive from evaluation | YES |
| Persistence matches result | YES |

**VERDICT: READY. Engine 08 NOT started — awaiting explicit approval.**
