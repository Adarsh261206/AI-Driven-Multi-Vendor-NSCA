# ENGINE_11_FIX_REPORT — Reporting Engine (§10.11)

**Verdict: READY.** Reporting boundary delivered; 40/40 targeted rows
PASS; corpus contract PASS with 0 violations; full suite 1426 passed /
1 pre-existing unrelated failure.

**Stop: no further engine started.**

---

## 1. Executive Summary

Engine 11 (Reporting Engine) had no prior validation cycle — no
readiness summary, no FAIL verdict to overturn, no defect ledger. The
pre-existing state was a validation *absence* hiding concrete defects:
`generate_audit_report` was a bare function with no input contract, and
probing it before the fix confirmed seven crash classes (None/string
scores, None confidences, None audit/file fields, unclosed markup in
data — each aborting the entire PDF), one fabrication (per-device
counts invented by proportional slicing when finding grouping did not
match), and one false claim (an unconditional "Powered by ML" cover
line). The V03-44 recommendation — "escape evidence text before
HTML/PDF rendering (reporting layer)" — was also outstanding.

The fix draws the canonical §10.11 boundary around the existing
renderer: `ReportEngineError` + `validate_report_inputs` own the input
contract (structural violations fail fast and typed; scalar display
values coerce so partial stored data still yields a report); every
Paragraph interpolation escapes untrusted data; per-device attribution
is matched-only with an explicit Unattributed row; the cover carries a
model-agnostic line while per-engine ML availability stays in the
E09-gated footer; page breaks are conditional; and the download
endpoint rejects unknown formats with 422.

Measured outcomes:

| Check | Before | After |
|---|---|---|
| Targeted V11 rows | n/a (no suite) | **40 rows: 40 PASS** |
| Hypotheses H11-01–H11-12 | n/a | **12/12 REJECTED** |
| Crash classes on partial data | 7 confirmed by probe | **0 (typed or coerced)** |
| Per-device attribution | proportional fallback invented counts | **matched-only + Unattributed row** |
| Corpus reports well-formed | unverified | **960/960 PDFs (%PDF…%%EOF)** |
| Corpus finding titles rendered | unverified | **14,221/14,221 present** |
| Unconditional ML claim | on every cover | **0/480 reports** |
| Corpus contract checks C1–C7 | n/a (new) | **0 violations** |
| Report build time p95 | unmeasured | **160 ms (budget 30 s)** |
| Full suite | 1386 passed / 1 failed (E10 close-out) | **1426 passed / 1 failed (pre-existing, unrelated)** |

---

## 2. Scope

Production:

- `backend/app/engines/reporting.py` (contract, coercion, escaping,
  attribution, cover, breaks — renderer otherwise unchanged)
- `backend/app/api/v1/reports.py` (`resolve_report_format` gate)
- `backend/tests/validation/conftest.py` (11_reporting mapping)

Validation/evidence:

- `backend/tests/validation/test_v11_reporting.py` (NEW, 40 rows, A–K)
- `backend/scripts/engine_validation/{sweep_reporting,report_reporting}.py`
- `backend/artifacts/engine_validation/11_reporting/`

Untouched semantics: E02–E10 engines, finding/evidence/remediation/risk
content, report list endpoint, JSON download shape, footer ML gating
(V09-69 invariants verified intact). No migration (no schema change).

---

## 3. Files Changed

See §2. No commits were made. There are no pre-fix E11 artifacts to
preserve (first validation cycle); the E09/E10 artifacts the work builds
on are untouched.

---

## 4. Findings and Fixes

F1 — score/confidence crashes. `:.1f` formatting on `overall_score`
and `*100` on finding confidence raised TypeError/ValueError on None
or string values (2 + 1 sites). Fix: `_score` / `_confidence` /
`_file_confidence` coercion — None means missing (existing defaults),
parseable strings render numerically, garbage renders "N/A".

F2 — None-container crashes. `audit_data=None`, `audit_name=None`,
`filename=None`, `device_type=None`, `platform=None` each crashed a
different site. Fix: `validate_report_inputs` normalizes/validates
containers; `_str` coerces display scalars (None → explicit default,
never the literal "None").

F3 — markup in data kills the document. A stray `<` from config
content (titles, descriptions, evidence values, commands) raised
ValueError and lost the whole PDF; well-formed tags were interpreted
as formatting instead of literal text (V03-44). Fix: `_esc` on every
Paragraph interpolation.

F4 — fabricated per-device counts. When finding grouping did not
match a file, the breakdown sliced the global finding list
proportionally per device (`findings[:len//n+1]`) and presented the
slices as measured counts. Fix: matched-only index (filename, then
hostname) and an explicit Unattributed row; the fallback is deleted
from the source.

F5 — unconditional ML cover claim. "Powered by ML — …" printed with
no models installed; the footer already gates per-engine claims
(V09-69). Fix: model-agnostic cover line; footer untouched
(byte-identical logic, V09-69 re-passing).

F6 — trailing blank pages. Unconditional PageBreaks after the summary
and findings sections left blank pages (empty audit: 2 pages, now 1).
Fix: breaks only when content follows.

F7 — format fall-through. Any `format=` value other than "json"
rendered a PDF. Fix: `resolve_report_format` — pdf/json accepted
(case-insensitive), anything else 422 before any database access.

## 5. Canonical Reporting Contract

```
AuditResult-shaped data (audit_data dict, findings list, results list)
  → validate_report_inputs (ReportEngineError on structural violations)
  → render with coerced scalars (_str/_score/_confidence) + escaped
    Paragraph data (_esc) + matched-only attribution
  → bytes (%PDF…%%EOF) or file write; identical normalized content
    across runs (Generated timestamp excepted and labeled)
```

Structural violations (wrong containers, non-mapping entries) raise
`ReportEngineError`. Display scalars degrade to explicit defaults.
No AttributeError/TypeError/ValueError path remains from data.

## 6. Validation Results

- Targeted: **40/40 PASS** across A(5) B(5) C(4) D(4) E(3) F(3) G(3)
  H(4) I(4) J(2) K(3).
- Hypotheses **H11-01–H11-12: 12/12 REJECTED**; 0 unreferenced rows.
- Corpus: 480 files, 0 errors; 960 reports (matched + unmatched
  variants) all well-formed; 14,221/14,221 finding titles present with
  matching summary counts; Unattributed presence matches expectation
  on all 960 variants; 0/480 unconditional ML claims; 30/30
  deterministic re-runs; p50 143 ms / p95 160 ms / max 351 ms per
  report against the 30 s roadmap budget; verdict PASS.
- Performance: 100-finding and 500-finding reports build inside budget
  (V11-36/37, measurement only).
- Full suite: **1426 passed / 1 failed** — the single failure is
  pre-existing and unrelated, verified on the pristine tree in the E09
  session (E02 validation rejects `juniper_insecure.txt` as
  NO_SUBSTANTIVE_CONTENT, so the executor never reaches findings).

## 7. Test Changes

New suite (no prior V11 tests existed to modify). PDF content is
asserted through dependency-free stream extraction (ASCII85+Flate
decode, TJ-segment joining) in the test module. Two assertion bugs
found during development were test-side, not production: the findings
anchor collided with the breakdown table's "Findings" column header
(re-anchored on the first numbered entry), and a hostile vendor label
is title-cased by design (assertion matches literalness, not case).
Prior suites re-verified: V09 (incl. V09-69 footer gating) and V10
(incl. V10-34 PDF row) pass unchanged — 137/137.

## 8. Security Validation

- Structural violations → `ReportEngineError` (fuzzed across 8
  malformed shapes, V11-04); scalar Nones → defaults, never crashes.
- Markup/script/entity/NUL/bidi-shaped inputs render as inert glyphs
  (V11-11/12/13/14/26/29); mistyped step-lists ignored, not exploded.
- Unknown/empty vendor identification → Unknown labels, no KeyError,
  no invented vendor (G record: V11-25/26/27).
- Unknown download formats → 422 before database access (V11-05).
- No SQL/shell/path use in the renderer; `output_path` writes
  byte-identical files, creating directories (V11-40).

## 9. Remaining Limitations

- ReportLab standard fonts cover WinAnsi: latin-1 glyphs render,
  unencodable glyphs (CJK, emoji) are a font limitation, measured in
  V11-30 — no crash, partial glyphs for those scripts.
- The Generated timestamp varies per run by design; determinism is
  defined and tested on normalized content (V11-22, sweep C6).
- `Severity` enum objects passed directly (bypassing the API/ORM
  string round-trip) render as "Severity.HIGH"; the production path
  serves plain strings, so the contract specifies JSON scalars.
- Very large audits (10k+ findings) were not rendered in-suite; the
  500-finding timing plus linear string/table work predict budget
  headroom, and the corpus max (351 ms) confirms it at real scale.

## 10. Final Readiness Verdict

| Criterion | Status |
|---|---|
| Engine boundary + typed input contract | FIXED |
| Well-formed, ordered, complete documents | FIXED |
| Partial-data robustness | FIXED |
| Hostile-text escaping (V03-44) | FIXED |
| Per-device attribution honesty | FIXED |
| Claims honesty (ML, framework) | FIXED |
| Determinism | FIXED |
| Wrong/unsupported vendor handling | FIXED |
| Hostile/boundary hardening | FIXED |
| Pipeline/API integration | FIXED |
| Performance within budget | FIXED |
| Content consistency | FIXED |
| No new unexplained regressions | FIXED |

**VERDICT: READY. No further engine started.**
