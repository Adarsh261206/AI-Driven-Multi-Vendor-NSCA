# ENGINE_08_FIX_REPORT — Finding Engine (§10.8, §9.1 steps 7/13, §12, §13.4, §14.3.2, §19, §20.2, §20.7)

**Verdict: READY.** All 7 blocking findings fixed, all secondary findings resolved,
98/98 targeted rows PASS, corpus contract PASS with 0 violations, migration 007
executed 14/14, full suite 1335 passed / 2 pre-existing unrelated failures.

**Stop: Engine 09 NOT started. Awaiting explicit approval.**

---

## 1. Executive Summary

Engine 08 (Finding Engine) was revalidated FAIL/NOT READY with 7 blocking
findings (F1–F7) plus secondary F8–F10. The defects clustered around missing
contract canonicalization: four disagreeing Finding shapes, no complete §12
evidence on findings, non-§12 remediation, two drifting list implementations
with a dead severity filter and no documented findings route, findings
generated for wrong/unsupported vendors, status changes without history or
notes, and a lowercase severity vocabulary stored end to end.

The fix establishes one canonical Finding contract (engine dataclass +
model + response, each carrying every §12 field, with documented operational
extras only), types evidence as the §12 EvidenceChain everywhere, builds §12
remediation with finding linkage stamped by the generator, consolidates all
three list endpoints onto one `FindingQueryService` (canonical ordering,
validated filters, routed `GET /audits/{id}/findings`), blocks unsafe
evaluations from ever becoming findings (via the E07 boundary contract —
zero new detection logic), records every accepted status transition
(including explicit no-ops) in the audit trail with notes preserved,
uppercases severity at the source with a data migration, removes the
unconditional ML claim, and validates hostile input before any DB write.

Measured outcomes:

| Check | Before | After |
|---|---|---|
| Targeted V08 rows | 91 rows: 71 PASS / 20 FAIL | **98 rows: 98 PASS** |
| Hypotheses H08-01–H08-26 | 15 CONFIRMED / 11 REJECTED | **26/26 REJECTED** |
| Findings with full §12 evidence (corpus) | 0 / 71,236 | **14,221 / 14,221** |
| Findings with §12 remediation (corpus) | 0 (all missed keys) | **14,221 / 14,221** |
| Unsupported-vendor decisive findings (corpus) | 113 files / 574 FAIL-derived | **0** |
| PASS leakage (corpus) | 0 | **0** |
| Severity outside vocabulary (corpus) | 0 (lowercase everywhere) | **0 (uppercase everywhere)** |
| Corpus contract checks C1–C7 | n/a (new) | **0 violations** |
| Migration 007 | n/a | **14/14 executed checks PASS** |
| Full suite | 1329 passed / 1 failed (E07 close-out) | **1335 passed / 2 failed (both pre-existing, unrelated)** |

---

## 2. Scope

Production:

- `backend/app/engines/compliance/{findings,models}.py` (Finding contract,
  severity vocabulary, generator validation + remediation linkage)
- `backend/app/api/v1/{findings,audits,audit_execution}.py` (canonical
  query service wiring, routed audits findings endpoint, status workflow,
  persistence linkage, truthful step text)
- `backend/app/repositories/{findings,audit_trail}.py` (NEW query service;
  notes/no-op in trail entries)
- `backend/app/schemas/__init__.py` (FindingResponse.control_id, typed
  evidence, nullable-honest EvidenceChain)
- `backend/app/models/__init__.py` (findings.control_id, length/NUL
  validation)
- `backend/alembic/versions/007_finding_severity_control_link.py` (NEW)

Validation/evidence:

- `backend/tests/validation/test_v08_findings.py` (91 → 98 rows, A–O)
- `backend/tests/validation/test_v09_risk.py` (3 mechanical contract updates)
- `backend/scripts/engine_validation/{sweep_findings,report_findings,validate_migration_007}.py`
- `backend/artifacts/engine_validation/08_findings/`

Untouched semantics: Engine 02 detection (consumed only), Engine 05
normalization (consumed only), Engine 07 evaluation/evidence source
(consumed only), Engine 09 risk math, Engine 10 remediation content.

---

## 3. Files Changed

See §2. No commits were made. Pre-fix artifact backups were stored with the
`_prefix` suffix next to the regenerated artifacts
(`raw_results_prefix.jsonl`, `summary_prefix.json`, `test_results_prefix.csv`,
`dataset_results_prefix.csv`, `dataset_summary_prefix.json`).

---

## 4. Canonical Finding Contract

One §12 interface carried by all four representations (V08-01/58):

- id, compliance_result_id, control_id, title, description, severity,
  confidence, evidence, affected_device, affected_vendor, remediation, status.
- Documented operational extras (mission §2 allowance, identical in engine
  and API shapes): audit_id, risk_score, priority, result, affected_platform,
  created_at, updated_at.
- The engine dataclass gained `compliance_result_id` (attached at
  persistence time from the compliance row map); the DB model gained an
  indexed `control_id` (backfilled by migration 007); the response gained
  mandatory `control_id` and typed `evidence`.
- Pipeline `evaluation → Finding → persistence → API` verified lossless for
  every contract field (V08-94/95 round-trips, V07-115 subset relation).

**F1 status: FIXED.**

Database/DDL contradiction (mission §3): explicit **Option A** — evidence
persists as JSONB on the finding row. The §19.1 10-column DDL (which omits
evidence the §12 interface requires) is NOT followed where it contradicts
§12; no §12-required information disappears, and no operational column was
removed (V08-05 records the decision).

---

## 5. F1 — Finding Shape — FIXED

See §4. `FindingResponse.control_id` is mandatory, so API consumers identify
exactly which control produced each finding (V08-02/73).

## 6. F2 — EvidenceChain — FIXED

- Findings carry the canonical §12 chain produced upstream (E07): all eight
  keys with honest nulls where nothing was observed (V08-34/35/36/37).
- `FindingResponse.evidence` is the typed `EvidenceChain` schema — no
  `Optional[dict]` escape hatch (V08-06); the schema's `EvidenceChain`
  mirrors §12 keys with nullability matching honest storage (V08-38
  detail round-trip).
- Corpus: 14,221/14,221 findings expose the full interface (pre-fix 0/71,236).

## 7. F3 — Remediation — FIXED

- Executor builds `finding_id/finding_title/risk_description/why_it_matters/
  vendor/platform/recommended_config/verification_steps/rollback_steps/
  references` (+ retained `confidence`); the generator stamps
  `finding_id/finding_title` where the identity exists (V08-09).
- Mapping (documented): `finding_title` ← control title;
  `risk_description` ← evaluated risk statement (reasoning);
  `why_it_matters` ← control title; `vendor/platform` ← affected context.
  Nothing invented beyond these sourced mappings; content quality stays
  Engine 10 scope.
- Corpus: 14,221/14,221 remediations carry all §12 keys (pre-fix: all
  missed `finding_id/finding_title/risk_description`).

## 8. F4 — API/List/Filters — FIXED

- One `FindingQueryService` (`app/repositories/findings.py`) backs all
  three list endpoints; the two legacy query implementations are deleted.
- `GET /api/v1/audits/{audit_id}/findings` is routed (V08-49).
- Canonical ordering `created_at DESC, id ASC` everywhere — no
  lexicographic severity ordering (V08-53/54 document the decision).
- Filters: severity (canonical uppercase; case-insensitive input; 422 on
  invalid), status (FindingStatus enum; 422 incl. direct calls), vendor,
  platform, control_id (new), pagination (V08-55/56/57/96/97/98).
- `?severity=CRITICAL` returns CRITICAL rows on every endpoint (V08-56);
  the dead-filter mechanism (lowercase storage) is gone with F7.

## 9. F5 — Vendor Safety Boundary — FIXED

- E08 adds no detection logic: unsafe evaluations never reach the
  generator because the E07 executor builds no evaluation for boundary
  runs (failed/unsupported/mismatch/empty/failed-normalization).
- `FindingGenerator` additionally validates its inputs (None → TypeError;
  missing control id → ValueError) and never converts PASS (V08-84/85/90).
- Tests: juniper-as-cisco → `vendor_mismatch`, zero findings (V08-60/61);
  arista/empty → zero FAIL-derived findings (V08-62/63 retained).
- Corpus: boundary runs carry zero findings; unsupported vendors zero
  decisive findings; PASS leakage 0 (C2/C3 green).

## 10. F6 — Audit Trail/Status History — FIXED

- `update_finding_status` calls `log_finding_update` on every accepted
  transition with finding id, actor, previous/new status, notes and
  timestamp (V08-46).
- Notes ride in the trail details — never dropped (V08-47).
- No-op transitions follow the record-explicit-no-op convention: state
  unchanged, one trail row with `no_op: true` preserving the request and
  its notes (V08-93).
- Full OPEN → IN_PROGRESS → RESOLVED → ACCEPTED lifecycle leaves three
  ordered, complete history rows (V08-92).

## 11. F7 — Severity Vocabulary — FIXED

- `Severity` enum values are `CRITICAL/HIGH/MEDIUM/LOW` at the source;
  control → finding → database → filters → reports → API use one
  representation, no edge-case uppercasing (V08-03/42/59).
- Migration 007 converts pre-existing lowercase rows in place on both
  findings and compliance_results tables, backfills control linkage,
  validates zero lowercase remain; executed 14/14 with downgrade + round
  trip on the throwaway DB (V08-104 + `migration_results.json`).

## 12. Secondary Findings

- **F8 (ML claim): FIXED.** Step text reads "Generating N findings with
  risk scoring..." and the step label "Risk scoring" — no unconditional
  RandomForest claim (V08-77; V09-68 updated to the truthful contract).
- **F9 (hostile input): FIXED.** None/non-string evaluation → typed
  errors; 1 MB device names (and NUL bytes, overlong titles/severities/
  statuses/vendors/platforms) rejected by model-level validation with
  `ValueError` before any DB write (V08-84/89); injection filters → 422
  (V08-87/96); unicode preserved (V08-88).
- **F10 (risk/priority observations): DESIGN DECISION / OUT OF SCOPE.**
  0 corpus CRITICAL findings and empty sub-40 priorities are Engine 09
  risk-formula semantics — recorded, not altered (mission rules 8–10).

## 13. Test Changes

- V08 file: 91 → 98 rows; 20 defect-asserting rows converted to
  conformance assertions (same requirement text, corrected expectation +
  E08 evidence reference); new categories M (V08-92/93 lifecycle), N
  (V08-94 evidence round-trip), O (V08-95 remediation round-trip);
  extras V08-96 (invalid status 422), V08-97 (control_id filter),
  V08-98 (vendor+platform filter).
- Cross-engine updates only where E08 changed the pinned contract:
  V09-48 (new required dataclass field), V09-68 (truthful step text),
  V09-85 (uppercase enum now scores string input correctly — a fixed bug,
  assertion flipped with updated text).
- No test was deleted; no assertion was weakened (failing expectations
  were replaced with the specified behavior, each citing the E08 change).

## 14. Security Validation

- Categories G/H/L + sweep C1/C3/C6/C7: 0 violations.
- Verified: injection severity/status/vendor strings → 422 or boundary
  (never executed, never matched); overlong/NUL inputs → typed ValueError
  pre-write; None/malformed evaluation/remediation inputs → typed errors;
  no stack traces or secrets in responses (parameterized queries, matched
  line snippets only); no fabricated findings on any hostile path.

## 15. Corpus Sweep

- 480 files, 0 errors, 14,221 findings (307 files with findings).
- Severity: HIGH 8,069 / MEDIUM 5,515 / LOW 637 / CRITICAL 0 / other 0;
  status open 100%.
- Evidence full-interface 14,221; remediation §12-complete 14,221;
  PASS leakage 0; unsupported decisive 0.
- Contract checks C1–C7: 0 violations; verdict PASS.
- `wrong_vendor_attributed` (71 files) is the diagnostic
  label-vs-detection mismatch heuristic only — detection output is passed
  through as the finding's affected vendor (E02 owns accuracy); it is not
  a safety violation (C3 proves zero decisive findings off-label).
- Timing: 213.9 s total, p50 558 ms / p95 742 ms / max 3.4 s per file.

## 16. Persistence Round-Trip

- Engine finding → DB → API preserves id, compliance_result_id,
  control_id, severity, confidence, evidence, remediation,
  affected_device/vendor, status (V08-40/41/94/95).
- Severity stays uppercase; control linkage resolves through the stored
  column (V08-41/73/97).

## 17. Determinism

- Repeat generation, fresh generator instances, executor reruns:
  identical semantic multisets (V08-78/79/80).
- Sweep C7: 30 corpus files re-run, 0 finding-count/status mismatches.
- UUIDs differ by design; all semantic fields compared.

## 18. Performance

- Generation ~4–5 ms/finding, linear at 100/1,000/2,000/4,000 findings
  (V08-81/82; measurement only, not a readiness score).
- Full executor audit ~432 ms on secure config (V08-83).
- The per-finding sklearn predict observation is recorded, not optimized
  (Engine 09 scope; mission rule 10).

## 19. Regression

- Targeted: V08 98/98; V07 116/116; V09 87/87.
- Neighbor suites updated only where they pinned superseded contracts
  (field renames, uppercase enum, §12 remediation keys); all green.
- Full suite: **1335 passed / 2 failed**, both classified pre-existing /
  unrelated (verified, not assumed):
  1. `test_frontend_integration_support.py::TestRemediationPopulation::test_juniper_findings_have_remediation`
     — fails identically on the pristine tree (both frontend tests failed
     there; this work fixed the other one). Cause: E02 validation rejects
     `juniper_insecure.txt` as NO_SUBSTANTIVE_CONTENT, so the executor
     never reaches findings. E08 touches neither validation nor that fixture.
  2. `test_v01_ingestion.py::test_v01_65_postfix_ingest_performance` — an
     Engine 01 latency measurement (9.9 MB ingest p50 622 ms vs 535 ms
     threshold). Profiled root cause: the pre-existing working-tree
     `_looks_binary_text` per-character `isprintable()` scan over the full
     text (absent from committed HEAD, untouched by E08). Failing since
     the E06 close-out; passes on pristine HEAD. Left for Engine 01 per
     the no-unrelated-changes rule; classified here, not fixed here.

## 20. Cross-Engine Integration

- Engine 02: detection consumed (informational + mismatch input); accuracy
  never judged, never claimed fixed.
- Engine 05: normalization consumed (single result, per-path confidence,
  FAILED boundary); never revalidated, never claimed fixed.
- Engine 07: evaluation/evidence/remediation source consumed; E08 asserts
  interface completeness only, never chain content correctness.
- Engine 09: owns risk formula/priority semantics and the ML model; E08
  computes-and-carries without redefining (V09-48/68/85 are the only
  E08-driven V09 touchpoints, each documented).
- Engine 10: owns remediation content quality; E08 guarantees interface +
  linkage only.

## 21. Remaining Limitations

- `control_id` is nullable for rows predating the contract (backfilled
  where linkable; always set for new rows).
- No-op status updates are recorded rather than rejected (documented
  convention choice).
- Severity-rank ordering is intentionally not implemented; canonical order
  is created_at DESC, id ASC.
- Corpus CRITICAL count is 0 (control inventory + configs observed; risk
  semantics belong to Engine 09).
- Performance figures are single-machine measurements.

## 22. Final Readiness Verdict

| Criterion | Status |
|---|---|
| F1 one canonical Finding contract | FIXED |
| F2 complete §12 EvidenceChain on 100% of findings | FIXED |
| F3 §12 Remediation interface on 100% of findings | FIXED |
| F4 canonical endpoints, shared list impl, 422s, deterministic order | FIXED |
| F5 no normal decisive findings from unsafe inputs | FIXED |
| F6 history on every accepted transition; notes preserved | FIXED |
| F7 canonical uppercase severity everywhere incl. persistence | FIXED |
| PASS→0 / FAIL→1 / REVIEW→1 findings | FIXED |
| Evidence + remediation survive round-trips | FIXED |
| control_id + compliance_result_id survive API round-trip | FIXED |
| 0 unexplained security violations | FIXED |
| 0 unexplained deterministic mismatches | FIXED |
| No new unexplained regressions | FIXED (2 pre-existing, classified) |
| Corpus completes without untyped errors | FIXED |

**VERDICT: READY. Engine 09 NOT STARTED — awaiting explicit approval.**
