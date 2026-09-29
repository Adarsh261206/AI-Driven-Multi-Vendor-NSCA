# ENGINE_09_FIX_REPORT — Risk Engine (§10.9)

**Verdict: READY.** All findings F1–F10 and secondary S1 resolved; 97/97
targeted rows PASS; corpus contract PASS with 0 violations; migration 008
executed 11/11; full suite 1346 passed / 1 pre-existing unrelated failure.

**Stop: Engine 10 NOT started. Awaiting explicit approval.**

---

## 1. Executive Summary

Engine 09 (Risk Engine) was revalidated FAIL/NOT READY with 10 blocking
findings (F1–F10) plus secondary S1. The spec named a Risk Engine with
Findings in and RiskAssessment out, but no such component existed: risk
scoring hid inside the Finding Engine's `SeverityCalculator`, its output
was discarded before storage/API/reports, and two scoring vocabularies ran
in the same function — RandomForest-first vs deterministic formula,
disagreeing on 100% of corpus findings. Category impact matched 0 of 28
production categories, training and serving used different confidence
transforms and vocabularies, hostile inputs manufactured P1 scores out of
NaN, and the published R² measured synthetic-label fit while reading as
real-world accuracy.

The fix creates the canonical boundary the spec requires:
`app/engines/compliance/risk.py` owns one normative deterministic scorer,
one shared feature builder, one category/vendor/severity vocabulary, typed
input validation, the `RiskAssessment` contract, and an isolated advisory
ML path that can never determine a score. The RandomForest was retrained
against the exact deterministic scorer on the exact serving vocabulary
(Option A) with honest formula-emulation labeling. Risk output now
survives engine → dataclass → database (migration 008) → API → reports,
severity is canonical uppercase throughout, status transitions and notes
are audited, and the spec carries an explicit §10.9.1 amendment (no
silent redefinition).

Measured outcomes:

| Check | Before | After |
|---|---|---|
| Targeted V09 rows | 87 rows: 39 PASS / 48 FAIL | **97 rows: 97 PASS** |
| Hypotheses H09-01–H09-19 | 14 CONFIRMED / 5 REJECTED | **19/19 REJECTED** |
| Normative scoring vocabularies | 2 (ML-first vs formula) | **1 (deterministic; advisory isolated)** |
| ML-vs-formula corpus divergence | 100% findings differ >1 pt, 65.2% band flips | **N/A — single vocabulary; advisory max diff 3.8** |
| Category impact active | 0 of 28 production categories | **all mapped production categories** |
| Hostile inputs (NaN/±Inf/out-of-range/None/wrong types) | scored or crashed raw | **typed RiskValidationError** |
| Confidence monotonicity (S1) | violated (MEDIUM 47.0→45.5) | **0 violations over 420 curves** |
| Findings with persisted risk | 0 | **all (columns + write path + API + reports)** |
| Corpus contract checks C1–C7 | n/a (new) | **0 violations** |
| Migration 008 | n/a | **11/11 executed checks PASS** |
| Full suite | 1329 passed / 1 failed (E07 close-out) | **1346 passed / 1 failed (pre-existing, unrelated)** |

---

## 2. Scope

Production:

- `backend/app/engines/compliance/risk.py` (NEW — canonical Risk Engine)
- `backend/app/engines/compliance/findings.py` (RiskEngine wiring;
  SeverityCalculator → thin adapter, moved out to risk.py)
- `backend/app/ml/train_all_engines.py` (shared builder + canonical maps)
- `backend/app/ml/model_artifacts/risk_model.joblib` + `risk_meta.json`
  (retrained emulation model + honest meta; prefixes backed up as
  `risk_model_prefix.joblib` / `risk_meta_prefix.json`)
- `backend/app/models/__init__.py` (findings risk columns)
- `backend/app/schemas/__init__.py` (FindingResponse risk fields)
- `backend/app/api/v1/audit_execution.py` (persistence write, summary
  aggregates)
- `backend/app/api/v1/reports.py` + `backend/app/engines/reporting.py`
  (persisted-risk rendering; risk-gated footer)
- `backend/alembic/versions/008_finding_risk_columns.py` (NEW)
- `docs/PROJECT_MASTER_SPEC.md` (explicit §10.9.1 amendment appendix)

Validation/evidence:

- `backend/tests/validation/test_v09_risk.py` (87 → 97 rows)
- `backend/tests/validation/test_v08_findings.py` (2 contract-alignment
  updates for new dataclass fields)
- `backend/scripts/engine_validation/{sweep_risk,report_risk,validate_migration_008}.py`
- `backend/artifacts/engine_validation/09_risk/`

Untouched semantics: E02 detection, E05 normalization, E07 evaluation,
E08 finding generation contract, E10 remediation content, frontend UI.

---

## 3. Files Changed

See §2. No commits were made. The working tree carries prior sessions'
work (E01–E08, established pattern); E09's production changes are the
files listed above. Pre-fix V09 artifacts were preserved by the
pre-existing `09_risk/` set (the E09 run overwrote derived files only
after the fix; defect evidence rows live in the pre-fix report).

---

## 4. Final E09 Contract

```
Finding-grade inputs (severity, vendor, category, confidence)
  → validation (RiskValidationError on any violation; neutral documented
    defaults only where specified)
  → DeterministicRiskScorer (normative closed-form formula)
  → priority bands (verified 80/60/40)
  → RiskAssessment {finding_id, risk_score, priority, severity,
     confidence, vendor, category, scoring_method, scoring_version,
     advisory_score?, advisory_model?, advisory_model_version?}
  → attach to Finding (risk_score, priority, risk_method, risk_model_version)
  → persistence (migration 008 columns) → API (FindingResponse) → reports
```

`RiskEngine` owns risk assessment only. The overall compliance score
stays owned by the compliance engine (E07 single formula
passed/evaluated) — documented separation, no second score (F10).
The RandomForest is advisory-only: `advisory_score()` + metadata, never
a decision input (F4).

---

## 5. F1 — Risk Output Persistence — FIXED

- `findings` gains nullable `risk_score`, `priority`, `risk_method`,
  `risk_model_version` (safe defaults for historical records; always set
  for new rows).
- The audit pipeline writes all four from the finding (V09-44); the
  summary serves `risk_max`/`risk_mean`/`findings_by_priority` from
  persisted rows (V09-45); reports render persisted values (V09-46);
  `FindingResponse` exposes all four (V09-42/43/47).
- Migration 008 executed 11/11 on the throwaway DB (upgrade → schema
  verification → insert/read → downgrade → verification → round trip →
  metadata restore).

## 6. F2 — Single Scoring Vocabulary — FIXED

- Exactly one normative production scoring path:
  `RiskEngine.assess` → `deterministic_score`. ML availability cannot move
  it (proven: identical 96-combo grids with working vs raising model
  loader, V09-19).
- `SeverityCalculator` survives only as a thin adapter delegating to the
  canonical engine (mission §18 allowance); its tables ARE the canonical
  objects, not copies.

## 7. F3 — RiskEngine / RiskAssessment — FIXED

- `app/engines/compliance/risk.py` delivers `RiskEngine`,
  `RiskAssessment` (+`to_dict`), constructed per finding at runtime
  (V09-01/02/10/12/105).
- Finding generation mints the identity first, assesses finding-grade
  inputs, attaches the assessment, then persists (V09-73).

## 8. F4 — Deterministic vs ML Decision — FIXED

- §4.2 followed without spec amendment: normative = deterministic.
- ML isolated to `advisory_score()` + `advisory_model_info()`; opt-in
  `include_advisory` on `assess()`; retrained model tracks normative
  (max diff 3.8 corpus-wide, ≤10 bound tested in V09-19/99).
- No ML-first branch remains in any production scoring path (V09-05).

## 9. F5 — Category Impact — FIXED

- One canonical map keyed by normalized category
  (strip/lower/underscores-to-spaces/collapsed whitespace), shared by
  scoring, validation, tests and reporting via `normalize_category()`.
- Case variants resolve consistently (`SSH` == `ssh`;
  `access_control` == `Access Control`); unknown/empty resolve to the
  documented neutral 1.0 (V09-34/35/102).
- Documented conflict resolution: serving 1.1 vs training 1.2 for
  "access control" → 1.2 adopted (production-vocabulary table wins;
  V09-15 asserts the adopted value, not the old one).

## 10. F6 — Training/Serving Alignment — FIXED (Option A)

- `train_risk()` imports the canonical maps and `build_risk_features`
  from `risk.py`; labels use `deterministic_score` (the 0.8+0.4c skew is
  gone); seeds, feature order and model family preserved (V09-49/50/51/
  52/55/56).
- Risk model retrained (R² 0.984, MSE 6.77) with meta explicitly scoping
  the metric as formula-emulation fit on synthetic labels
  (`scope`, `label_source`, `label_formula`, `confidence_transform`,
  `vocabulary` keys) — V09-53/54 assert the labeling, not real-world
  accuracy.
- Previous artifacts preserved as `risk_model_prefix.joblib` /
  `risk_meta_prefix.json`.

## 11. F7 — Hostile Input Hardening — FIXED

- `RiskValidationError` (a `ValueError`) for: vendor/category None or
  non-string; confidence None/bool/string/NaN/±Infinity/out-of-[0,1];
  severity None/""/unknown strings/wrong types; non-finite or
  non-numeric scores to `priority_for` (V09-80–86, V09-101 hostile
  matrix: 22 rejections, 10 safe neutral scores, 0 leaks).
- No AttributeError/TypeError/OverflowError/NaN→100 escapes; string
  severities outside the canonical vocabulary are rejected (canonical
  strings like `"HIGH"` score identically via str-enum equality,
  V09-85 preserved).

## 12. F8 — Vendor Impact Boundary — FIXED

- Supported vendors keep documented multipliers (cisco 1.2, juniper 1.1,
  fortinet 1.1, paloalto 1.2); unknown/empty/hostile strings resolve to
  the explicit neutral 1.0 — no silent Cisco fallback, no traversal/
  injection effect, no inflated multiplier (V09-57/58/59/60/61/103).
- Misattribution itself stays upstream E03/E07 scope; E09 proves safe
  consumption of the supplied identity (mission §13).

## 13. F9 — API/UI/Report Exposure — FIXED

- `GET finding` exposes risk_score/priority/method/version from storage
  (V09-42/43); summary aggregates served (V09-45); reports API + PDF
  render persisted values (V09-46, incl. per-finding Risk row).
- PDF footer risk claim gated on risk-model metadata
  (`advisory_model_info`), labeled formula-emulation R² — never the
  vendor-detector flag (V09-69).
- DESIGN DECISION (documented): no dedicated `/risk` endpoint and no UI
  route — risk travels on the finding resource, which the spec's Finding
  interface already defines (V09-70 conformance; V09-71/87 OUT OF SCOPE,
  recorded not hidden).

## 14. F10 — Overall Score Ownership — FIXED

- Documented separation: Compliance Engine → compliance score (E07
  single formula); Risk Engine → risk assessment; `risk.py` and
  `findings.py` compute no overall score (V09-72/104).
- No 46.9-vs-95.5-class second score exists anywhere in the risk path.

## 15. S1 — Confidence Monotonicity — FIXED

- Property test over 0.0→1.0 (step 0.05) × 4 severities × 5 vendors × 4
  categories (420 curves): 0 violations (V09-96); the 0.5 floor is
  preserved explicitly and is itself monotonic (V09-16/22).

## 16. Test Changes

- V09 file: 87 → 97 rows. Defect-asserting rows converted to conformance
  assertions with corrected expectations + E09 evidence references; each
  changed expectation maps to a documented contract change (§25 rule).
- New: V09-96 (S1 property), V09-97 (DB round-trip), V09-98 (advisory
  isolation), V09-99 (retrained parity), V09-100 (migration chain),
  V09-101 (hostile matrix), V09-102 (category contract), V09-103
  (vendor contract), V09-104 (score separation), V09-105 (assessment
  contract).
- Cross-engine updates only where E09 changed the pinned contract:
  V08-01/58 (new documented dataclass fields), V09-48 (new required
  field), V09-68 (truthful step text), V09-85 (uppercase enum fixes the
  documented bug — assertion flipped with updated text).

## 17. Security Validation

- Hostile matrix (V09-101) + L rows (V09-80–86): 22 typed rejections, 10
  safe neutral scores, zero leaks/crashes/traces.
- Verified: no SQL injection (no SQL in the engine; parameterized
  persistence), no path traversal effect (`../../cisco` → neutral), no
  code execution (pure arithmetic + regex-free normalization), no secret
  leakage (scores only), no stack-trace leakage (typed errors), no
  fabricated P1 (NaN→P1 path deleted).

## 18. Corpus Sweep

- 480 files, 0 errors, 14,221 findings (307 files with findings).
- Priorities: P1 0 / P2 5,016 / P3 6,532 / P4 2,673 / invalid 0;
  risk range 15.5–71.2, all in [0,100], all native floats.
- Normative method on 100% of findings; advisory tracked (max diff 3.8)
  without deciding anything.
- Boundary runs carry zero findings; unsupported vendors zero decisive
  findings (C5/C6 green).
- Contract checks C1–C7: 0 violations; verdict PASS. Timing 123 s
  (p50 16 ms / p95 222 ms / max 1.5 s per file).
- Note vs pre-fix: 71,236 → 14,221 findings is the E07 boundary effect
  (unsupported/mismatch/failed runs now carry zero evaluations), not a
  generation-contract change — FAIL→finding and REVIEW→finding preserved
  per file on completed runs.

## 19. Persistence Round-Trip

- Insert + read-back of a fully populated finding row preserves
  risk_score/priority/method/version exactly (V09-97).
- Migration 008: 11/11 executed checks (schema verification, legacy NULL
  survival, risk-row round-trip, downgrade reversal, round trip,
  metadata restore).

## 20. Determinism

- Normative grids ×3, generator ×2, fresh engines, full pipeline ×2:
  identical (V09-74/75/76 + pre-existing J rows).
- Advisory determinism verified (retrained forest, fixed seed).
- Sweep C7: 30 corpus files re-run, 0 mismatches.

## 21. Performance

- Normative scoring is pure arithmetic (V09-78 p50 < 1 ms keeper);
  advisory single-predict latency within the <25 ms sanity bound
  (V09-77 via advisory_score); 100-finding generation < 5 s (V09-79).
- Measurement/sanity bounds only — no spec latency exists; no
  optimization work performed (mission rules).

## 22. Regression

- Targeted: V09 97/97; V07 116/116; V08 98/98.
- Full suite: **1346 passed / 1 failed**. The single failure is
  pre-existing and unrelated, verified on the pristine tree:
  `test_frontend_integration_support.py::TestRemediationPopulation::test_juniper_findings_have_remediation`
  (E02 validation rejects `juniper_insecure.txt` as NO_SUBSTANTIVE_CONTENT,
  so the executor never reaches findings; E08/E09 touch neither).
- V01-65 (ingest latency) passed in this run; its known environment
  sensitivity is recorded in E06/E07 reports, not re-litigated here.

## 23. Cross-Engine Integration

- Engine 02: detection consumed as informational identity only; accuracy
  never judged, never claimed fixed.
- Engine 05: normalization consumed (single result, per-path
  confidences, FAILED boundary); never revalidated, never claimed fixed.
- Engine 07: evaluation/evidence/remediation source consumed; E09 asserts
  interface completeness only, never chain content correctness.
- Engine 08: generator consumes assessments via `attach()`; finding
  contract, linkage and subset relations preserved (V07-115 pattern
  intact; V08-01/58 updated for documented E09 fields).
- Engine 10: owns remediation content quality and risk-formula choice
  beyond the specified contract; E09 guarantees interface + linkage only.

## 24. Remaining Limitations

- Advisory R² (0.984) measures formula-emulation fit on synthetic
  labels — labeled as such in meta + report; not real-world accuracy
  (no labelled outcomes exist to train or validate against).
- P1 unreached corpus-wide (max 71.2): the bands are reachable in unit
  grids (98.6) but corpus maxima stay below 80 — an observation about
  the data, not a defect.
- UI risk rendering remains future work (OUT OF SCOPE, V09-71/87).
- `unknown` vendor key is explicit-but-neutral (equals default); kept
  for train/serve vocabulary parity, documented.
- Performance figures are single-machine measurements.

## 25. Final Readiness Verdict

| Criterion | Status |
|---|---|
| F1 fixed | FIXED |
| F2 fixed | FIXED |
| F3 fixed | FIXED |
| F4 explicitly resolved | FIXED (deterministic normative, advisory isolated) |
| F5 fixed | FIXED |
| F6 fixed (Option A retrain + honest labeling) | FIXED |
| F7 fixed | FIXED |
| F8 safe and documented | FIXED |
| F9 fixed | FIXED |
| F10 resolved | FIXED (documented separation) |
| S1 fixed | FIXED |
| RiskAssessment exists | FIXED |
| One normative scoring vocabulary exists | FIXED |
| No risk score silently discarded | FIXED |
| risk_score survives DB/API round-trip | FIXED |
| priority survives DB/API round-trip | FIXED |
| category impact works with real production categories | FIXED |
| invalid numeric values rejected | FIXED |
| NaN/Infinity rejected | FIXED |
| confidence monotonicity verified | FIXED |
| deterministic behavior verified | FIXED |
| unsupported vendors cannot manufacture normal risk decisions | FIXED |
| ML does not silently override deterministic scoring | FIXED |
| corpus completes without untyped errors | FIXED |
| security suite passes | FIXED |
| migration upgrade/downgrade passes | FIXED |
| performance remains reasonable | FIXED |
| no new unexplained regression | FIXED |
| ENGINE_09_FIX_REPORT.md generated | FIXED |

**VERDICT: READY. Engine 10 NOT STARTED — awaiting explicit approval.**
