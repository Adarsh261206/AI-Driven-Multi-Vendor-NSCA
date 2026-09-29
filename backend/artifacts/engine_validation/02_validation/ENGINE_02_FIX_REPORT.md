# ENGINE 02 — Configuration Validation: Fix & Hardening Report

Report date: 2026-09-26. Engine: `02_configuration_validation`.
Code: `backend/app/engines/validation.py` (single source of truth, 751 lines) and the
test files required by the fix prompt. Validation evidence:
`backend/artifacts/engine_validation/02_validation/` (pre-fix snapshot preserved in
`02_validation_pre_fix/`).

---

## 1. Scope and identification

Findings covered: **F1–F15** from the ENGINE 02 fix prompt (pre-fix evidence:
`02_validation_pre_fix/summary.json`, hypotheses H02-01…H02-15). Files changed by
this work:

| File | Role |
|---|---|
| `app/engines/validation.py` | Core rewrite — contract, six error codes, syntax/vendor/credential checks, O(n) SNMP mask (739 diff lines) |
| `tests/validation/test_v02_validation.py` | 18 expectations updated to the fixed contract + new V02-36…V02-47 block (86 → 118 evidence rows) |
| `tests/test_validation.py` | 4 legacy expectations updated (`# E02 FIX` at lines 24, 61, 81, 89) |
| `tests/validation/test_v01_ingestion.py` | V01-46 mirror assertion updated to the documented cross-engine boundary (1 site) |
| `tests/validation/test_v07_compliance.py` | V07-75 updated to the F4 executor-gate contract |
| `tests/validation/test_v08_findings.py` | V08-63 assertion inverted to the fixed behaviour |
| `tests/test_vertical_slice.py` | 2 all-commented fixtures uncommented (F5 gate; `# E02 FIX` at lines 129, 197) |
| `tests/sample_configs/juniper_secure.txt` | Fixture repaired: every line was `##`-commented (committed that way in `03ddd52`); uncommented to restore its stated "SECURE sample" intent |
| `scripts/engine_validation/sweep_validation_postfix.py` | 480-file corpus sweep (pre/post comparison, determinism) |
| `scripts/engine_validation/perf_validation_postfix.py` | Size scaling, ReDoS payloads, linearity, block-guard timings |

Out of scope and untouched: production code of Engines 01 and 03–12
(`compliance/executor.py` keeps its unchanged call site at lines 171–179), auth,
AI/queues, the frontend (pre-existing user changes left alone). No test was deleted.

## 2. Status vocabulary

Statuses used in §3, exactly as required: **FIXED**, **NOT FIXED**,
**NOT APPLICABLE**, **DESIGN DECISION**. No numeric scores or readiness grades are
assigned anywhere in this report; counts, latencies and pass/fail tallies are
measurements, not scores.

## 3. Findings F1–F15 — status

| ID | Finding (pre-fix) | Status | What was done | Evidence |
|---|---|---|---|---|
| F1 | Syntax validation claimed in the docstring but not implemented (H02-05 CONFIRMED; V02-15/34 FAIL) | **FIXED** | `_validate_structure` (LONG_LINE) + `_validate_syntax`: value-required keys, numeric-first keys, empty assignment RHS — bounded, deterministic, negation-aware; no per-command vocabulary claimed | V02-15, V02-34, V02-38, V02-39 |
| F2 | Severity was decorative: only `BINARY_CONTENT` could ever make `is_valid=False` (H02-02); warnings/info buckets never populated (H02-12) | **FIXED** | Six error codes each close the gate; WARNING/INFO never gate; `issues`/`warnings`/`info` kept as synchronised subsequences with per-severity counts | V02-07, V02-27, V02-32 |
| F3 | `NULL_BYTE` unreachable — the binary check short-circuited first (H02-01 CONFIRMED) | **FIXED** | NUL scan runs as its own step (after empty, before binary), per split line with accurate 1-based line numbers; analysis stops | V02-06, V02-37 (signature path unmasked by fixture fix) |
| F4 | Empty / whitespace-only content accepted (H02-03); executor had no decisive gate | **FIXED** | `EMPTY_CONTENT` error; executor returns `status="failed"` with no evaluation (`executor.py:174-179`, unchanged); cross-engine boundary with Engine 01 documented | V02-13 ×8, V07-75, V08-63, V01-46 |
| F5 | Comment-only content validated with zero issues (H02-04 CONFIRMED) | **FIXED** | After comment stripping (F11), zero substantive lines → `NO_SUBSTANTIVE_CONTENT`; mixed comment+command content stays valid | V02-14 ×5, 2 vertical fixtures, `juniper_secure.txt` |
| F6 | `vendor_hint` inert; no family recognition, no mixed-vendor, no unknown-content opinion (H02-06/07) | **FIXED** | Independent structural families (cisco/juniper/fortinet/paloalto), alias table, `MIXED_VENDOR`, `UNKNOWN_CONTENT`; does not import Engine 03 | V02-16, V02-17, V02-23, V02-44, V02-46 |
| F7 | Credential detection missed space-separated password, encrypted-password, JUNOS root-auth, FortiOS `set password` forms (H02-08) | **FIXED** | `SENSITIVE_PATTERNS` covers space/`=`/colon assignment styles, PEM key blocks, long key material; SNMP community gated to SNMP context (FortiOS block membership precomputed in O(n)) | V02-19 ×9, V02-40, V02-47 |
| F8 | Insecure detection false-positived on negated commands (`no ip http server`, `no transport input` — H02-09 **BUG**); Juniper/Fortinet telnet forms missing | **FIXED** | `_check_insecure_patterns` skips lines whose first token is `no`/`delete`/`unset`/`negate`; full pattern set (http, telnet, default communities, JUNOS/FortiOS telnet) | V02-20 ×7, V02-38, V02-47 |
| F9 | Routine commands reported as credentials — `crypto key generate ...` (H02-15 **BUG**); bare `key`/`community`/`password` in descriptions matched | **FIXED** | Patterns anchored to credential context: key rule requires actual base64/hex material length; `community` only in SNMP blocks; descriptions/comments/route-policy values never match | V02-21, V02-40, V02-42 (7-class FP battery) |
| F10 | Credential evidence must never echo secret values in issue messages | **FIXED** | Messages carry label + line only (`'label on line N'`); no matched credential text is stored in any issue | V02-41, V02-42 |
| F11 | Comment suppression covered only `!` and `#` (H02-10) | **FIXED** | `!`, `#`, `//`, `/* ... */` (multi-line) plus trailing forms; `//` only after whitespace/boundary (`http://` never a comment) | V02-22 ×7, V02-43 |
| F12 | Binary detection was a dilutable strict >10% density ratio only (H02-11); no signatures (H02-02) | **FIXED** | Four-step policy: NUL → 12 known signatures at offset 0 → any C0 control (except TAB/CR/LF, and ETX on `banner` lines) → >10% non-printable density incl. ZWSP | V02-09 ×5, V02-24, V02-36, V02-37 |
| F13 | `ValidationResult.warnings`/`.info` never populated (H02-12 **BUG**); no determinism contract | **FIXED** | `add_warning`/`add_info` append the same object to `issues` and the bucket; deterministic check order; repeated input → identical codes/messages/lines/ordering | V02-27, module H-category tests, corpus determinism 0 |
| F14 | Non-`str` input raised an untyped `AttributeError` (H02-13) | **FIXED** | `isinstance` guard raises typed `TypeError` with an explicit message before any string method is touched; non-str `vendor_hint` reported, never raised | V02-08, V02-46 |
| F15 | Warnings/info must not stop the audit; errors must (executor inspects only `is_valid`) | **FIXED** | Formalised in the contract and now non-trivially tested — pre-fix hypothesis H02-14 was rejected vacuously because no warnings could exist | V02-32, `executor.py:171-179` unchanged |

No F finding remains NOT FIXED or NOT APPLICABLE. Design decisions behind several
rows are recorded in §8.

## 4. Validation contract architecture

`validate(content, vendor_hint=None)` executes a fixed pipeline; the first failing
gate returns immediately (later stages never run on hopeless input):

1. **Type guard** (F14): non-`str` → `TypeError`.
2. **Strip** → zero length or whitespace-only → `EMPTY_CONTENT` → return (F4).
3. **NUL scan** over `splitlines()` → `NULL_BYTE` (line-accurate) → return (F3).
4. **Binary gate** (F12): signatures → C0-outright (± banner ETX) → density >10%
   → `BINARY_CONTENT` → return.
5. `MIXED_LINE_ENDINGS` info (CRLF vs LF mixing).
6. **Comment stripping** (F11): `!`, `#`, `//`, `/* ... */`, trailing forms →
   zero substantive lines → `NO_SUBSTANTIVE_CONTENT` → return (F5).
7. **Structure**: `LONG_LINE` (F1).
8. **Syntax**: `MISSING_VALUE` / `INVALID_ARGUMENT` — negation-aware, restricted
   to recognised keys (F1).
9. **Vendor**: structural families, `vendor_hint` alias resolution, `MIXED_VENDOR`,
   `VENDOR_HINT_MATCH/_CONFLICT`, `UNKNOWN_VENDOR_HINT`, `UNKNOWN_CONTENT` (F6).
10. **Sensitive** (F7/F9/F10): context-anchored, one issue per line, comments
    excluded, evidence redacted.
11. **Insecure** (F8): one issue per line, negated lines skipped.

Result contract (F13): `issues` is the single ordered list; `warnings`/`info` are
always subsequences of it; counts derive from severity; line numbers are 1-based.

## 5. Error codes, severities and gate semantics

| Severity | Codes | Effect on `is_valid` | Effect on audit |
|---|---|---|---|
| ERROR | `EMPTY_CONTENT`, `NULL_BYTE`, `BINARY_CONTENT`, `NO_SUBSTANTIVE_CONTENT`, `MISSING_VALUE`, `INVALID_ARGUMENT` | `False` | Executor step 1 completes, `status="failed"`, pipeline stops |
| WARNING | `LONG_LINE`, `SENSITIVE_DATA`, `INSECURE_CONFIG`, `UNKNOWN_CONTENT`, `MIXED_VENDOR`, `VENDOR_HINT_CONFLICT`, `UNKNOWN_VENDOR_HINT` | unchanged | Audit continues (F15) |
| INFO | `MIXED_LINE_ENDINGS`, `VENDOR_HINT_MATCH` | unchanged | Audit continues |

Each error code is individually reachable and covered by a regression test.

## 6. Cross-engine consistency

- **Engine 01 mirror (F4/F12 boundary)**: ingestion `_looks_binary_text` keeps the
  strict `>0.1` density rule; validation adds an outranking any-C0 rule. At the
  exactly-10% C0 sample the two deliberately disagree — validation rejects,
  ingestion accepts. V01-46 was updated to assert this documented divergence
  (samples 1/3/4 still agree) rather than unconditional equality. E02 did not
  touch `ingestion.py`.
- **Executor gate (F4/F15)**: `compliance/executor.py:171-179` is unchanged — it
  already returns `status="failed"` before evaluation when `is_valid` is False.
  The fix changes *which inputs reach that branch* (empty and comment-only content
  now fail); V07-75 and V08-63 were updated to the gate contract.
- **Engine 03 detection**: validation never imports it (F6); vendor recognition is
  independent and reports, never blocks, unless content is provably invalid.

## 7. Register of behaviour changes

Each change below is deliberate and tested, relative to the pre-fix code:

1. Empty / whitespace-only content: accepted → `EMPTY_CONTENT` error (gate closes).
2. Comment-only content: accepted with zero issues → `NO_SUBSTANTIVE_CONTENT`
   error (gate closes).
3. NUL bytes: binary short-circuit → own line-accurate `NULL_BYTE` error.
4. Binary detection: density-only → signatures + C0-outright + density
   (banner `^C` delimiters exempted).
5. `MISSING_VALUE` / `INVALID_ARGUMENT`: non-existent → reachable errors.
6. `UNKNOWN_CONTENT`, `MIXED_VENDOR`, `VENDOR_HINT_*`: non-existent → new
   warnings/infos; unknown content stays `is_valid=True` (cannot prove invalid).
7. `vendor_hint`: inert → alias-normalised, compared against structure.
8. Credentials: 4 styles → full form set with context gating and redaction.
9. Insecure lines: flagged through negations → negations skipped.
10. `//` and `/* ... */`: not comments → stripped (with `://` protection).
11. `warnings`/`info` buckets: always empty → always populated and synchronised.
12. Non-`str` input: untyped `AttributeError` → typed `TypeError`.
13. Downstream test fixtures: three all-commented fixtures now fail the F5 gate —
    repaired by uncommenting (vertical fortinet/juniper, `juniper_secure.txt`),
    restoring their stated intent; executor behaviour itself unchanged.
14. Corpus validity: 480/480 → 479/480 (`fork-config.cfg`, comment-only, intended).

## 8. Design decisions

- **C0-outright rule (F12) over density alone**: any disallowed control character
  is proof of binary content; the >10% density rule is retained as defence in
  depth against diluted payloads (incl. non-C0 format characters like ZWSP).
  Consequence: validation is stricter than the ingestion mirror at exactly 10% —
  documented divergence, not an inconsistency (V01-46).
- **Banner ETX exemption**: U+0003 is the standard IOS banner delimiter; rejected
  everywhere except on `banner ...` lines (corpus evidence: `c2811-CUCME.conf`
  validates clean).
- **Comment-only is invalid, unknown content is valid (F5/F6)**: content with
  nothing to audit cannot be assessed (error); content the validator merely fails
  to recognise must not be rejected (warning) — recognition, not rejection.
- **No vendor grammar (F1)**: bounded structural checks only — a fixed key list,
  numeric-first rules, negation exemption. Unknown *commands* are never flagged;
  unknown *content* is reported once as `UNKNOWN_CONTENT`.
- **`fork-config.cfg`**: the corpus's only invalid file — a comment-only pybatfish
  artifact. Intended behaviour of the F5 gate, recorded in the sweep output.
- **Redaction (F10)**: messages are `label on line N`; secret values never enter
  messages, reprs or artefacts.
- **One issue per line**: sensitive/insecure emit at most one issue per line per
  class; duplicate pattern hits do not multiply.
- **Deterministic ordering**: fixed stage order + fixed pattern order ⇒ identical
  output for identical input (verified 0 mismatches over 480 files ×2 passes).
- **O(n) SNMP block membership (F7)**: `_fortinet_snmp_mask` precomputes
  per-line FortiOS `config snmp community` membership in a single pass — the
  pre-fix per-line rescan was O(n²) (see §15).

## 9. Security checklist

| Control | Verified by |
|---|---|
| Secret values never echoed in issue messages | V02-41, V02-42 |
| Negated commands not reported as insecure | V02-20 ×7, V02-38 |
| `crypto key generate` / description `key`/`community`/`password` never reported as credentials | V02-21, V02-42 |
| Documented false-positive battery (7 classes) reports nothing | V02-42 |
| Binary signatures, C0 controls, ZWSP density rejected at the gate | V02-09, V02-24, V02-36, V02-37 |
| NUL rejected line-accurate before any further analysis | V02-06 |
| Comment content never contributes credential/insecure evidence | V02-22 ×7, V02-43 |
| No ReDoS: all patterns bounded, worst adversarial payload ≤ 284 ms | §14 (`redos_payloads`) |
| Warnings cannot gate the audit; only errors can | V02-32 |
| Corpus FP collapse: chic.conf `SENSITIVE_DATA` 688 → 0; lhr-border-02 keeps only the true positive `transport input telnet` (L277) | §13 |
| No new dependencies; no secrets/keys added | `requirements.txt` diff (E01 pins only); diff review |

## 10. Test coverage

`tests/validation/test_v02_validation.py`: **86 → 118 evidence rows** (18
expectations rewritten to the fixed contract; new block **V02-36…V02-47**:
banner ETX, binary signatures, negation syntax, assignment keys, FortiOS SNMP
block gating, secrets-never-echoed, 7-class FP battery, comment boundary rules,
vendor family markers, O(n²)-rescan regression guard, non-str `vendor_hint`,
`insecure.txt` exact-row cross-check). Categories A–N: A functional, B
gate/caller contract, C negative, D boundary, E malformed, F security,
G reliability, H determinism, I error handling, J performance, K integration
(source level), L fix-regression (F1–F13), M input contract, N fixture alignment.

Post-fix row statuses: **116 PASS / 1 PARTIAL (V02-33, E01 cross-file decode row,
status convention deliberately retained) / 1 NOT APPLICABLE (V02-35)**. Legacy
`tests/test_validation.py`: 12 tests, 4 updated. Evidence-row transitions from
`02_validation_pre_fix/summary.json`: 21 FAIL → PASS, 15 PARTIAL → PASS, 49 PASS
retained, 1 NOT APPLICABLE retained; no test deleted.

## 11. Cross-contract test updates (disclosure)

Tests asserting the *old* E02 contract were updated, never weakened; each carries
an `# E02 FIX (Fn):` comment and this register:

| File | Tests | Nature |
|---|---|---|
| `tests/validation/test_v02_validation.py` | 18 updated + 12 new functions | Expectations moved to the fixed contract (e.g. `is_valid` outcomes, NULL_BYTE reachability, comment gate, FP battery) |
| `tests/test_validation.py` | 4 legacy (lines 24, 61, 81, 89) | EMPTY gate, comment-stripped credential, UNKNOWN_CONTENT warnings/bucket counts |
| `tests/validation/test_v01_ingestion.py` | V01-46 | Mirror equality → documented 10% boundary divergence (F4) |
| `tests/validation/test_v07_compliance.py` | V07-75 | "2 FAIL on empty via executor" → executor gate blocks (assert direction inverted to `blocked`) |
| `tests/validation/test_v08_findings.py` | V08-63 | Documented-bug assertion (`assert not ok`) → fixed-contract assertion (`assert ok`) |
| `tests/test_vertical_slice.py` | fortinet, juniper fixtures | All-commented configs uncommented (F5) so the full-pipeline intent is exercised; detection/normalisation assertions unchanged |
| `tests/sample_configs/juniper_secure.txt` | data fixture | Uncommented (was 100% `##` at HEAD, commit `03ddd52`); V08-50/10/26/65 and V07-13/16/78 re-verified green on the repaired fixture |

Production code outside `validation.py` was not modified by E02.

## 12. Regression results (final state, this session)

| Suite | Result |
|---|---|
| `tests/validation/test_v02_validation.py` + `tests/test_validation.py` | **130 passed** (118 + 12) |
| `tests/validation/test_v07_compliance.py` | **95 passed** |
| `tests/validation/test_v08_findings.py` | **91 passed** |
| `tests/validation/` (all validation suites) | **853 passed, 1 failed**, 165.6 s |
| Full repository (`pytest`) | **1255 passed, 27 failed** (1282 collected), 218.3 s |

The 27 failures = the **26 known pre-existing** legacy failures (benchmark ×13,
detection ×2, frontend-integration ×2, phase5 ×2, phase8 ×6, vertical ×1 — the
same set verified at clean HEAD `74ce952` by E01's throwaway-worktree check) plus:

- **V01-65 (ingest performance)** — root-caused, **not an E02 regression**:
  cProfile shows E01's own `_looks_binary_text` (`ingestion.py:528-540`) performs
  a per-character `isprintable()` scan (~500 ms on 9.9 MiB) while the DB insert is
  ~100 ms. The test compares against the *pre-fix* baseline with a
  `5× + 10 ms` threshold = 534.6 ms for that shape; measured p50 was
  616–641 ms across three isolated runs. `git diff` confirms E02 touched only
  `validation.py` + disclosed tests — `ingestion.py` changes are E01's uncommitted
  work. Engine 01 code is frozen for E02 (scope rule), so the failure is
  **documented, not fixed** (§16); recommended follow-up: a `str.translate`-style
  counting loop or re-baselining the threshold under an E01 amendment.

## 13. Dataset re-validation (480 files)

Script: `scripts/engine_validation/sweep_validation_postfix.py` →
`dataset_results_postfix.csv` + `dataset_summary_postfix.json` (determinism pass
included). Corpus: `C:\Users\priye\Downloads\SIH Config\final-dataset`, 480 files,
11.58 MB, originals untouched.

| Measure | Pre-fix | Post-fix |
|---|---|---|
| Valid files | 480 | **479** (`fork-config.cfg` → `NO_SUBSTANTIVE_CONTENT`, intended) |
| Files with zero issues | 223 | 293 |
| `SENSITIVE_DATA` (hits / files) | 9543 / 209 | **97 / 40** |
| `INSECURE_CONFIG` (hits / files) | 134 / 131 | **16 / 12** |
| `UNKNOWN_CONTENT` | — (code absent) | 133 |
| `MIXED_VENDOR` | — (code absent) | 15 |
| `NO_SUBSTANTIVE_CONTENT` | — (code absent) | 1 |
| `MIXED_LINE_ENDINGS` / `LONG_LINE` | 5 / 2 | 5 / 2 (unchanged) |
| EMPTY / BINARY / NULL_BYTE / MISSING_VALUE / INVALID_ARGUMENT | 0 / 0 / 0 / — / — | 0 / 0 / 0 / 0 / 0 |
| E01-ingestible ∧ E02 issues | 183 | 54 |
| E01-ingestible ∧ E02 valid | 256 | 255 (the 1 = fork-config) |
| Determinism mismatches (2 passes) | 0 | 0 |
| Latency p50 / p95 / max | 0.548 / 24.7 / 90.4(p99) ms | 2.34 / 115.4 / 570.7 ms |

Why the totals moved: pre-fix `(community|community-string)\s+\S+` matched
route-policy and literal community values — chic.conf alone carried 688 hits;
the context-anchored rules now report 0 there. Insecure collapse (134 → 16) is
the negation-awareness fix plus default-community context. Sweep wall time
28.8 s for both passes.

## 14. Performance measurements

`performance_postfix.json` (n = 30 / 10 / 5 / 100 as noted):

| Shape | p50 | p95 | max |
|---|---|---|---|
| 1 KiB synthetic | 0.828 ms | 1.28 ms | 1.87 ms |
| 100 KiB synthetic | 84.8 ms | 92.5 ms | 99.8 ms |
| 1 MiB synthetic | 892.0 ms | 949.9 ms | 952.3 ms |
| 1 MiB / 1 KiB ratio | **1077.6** (sub-linear per byte; no super-linear blow-up) | | |
| chic.conf (491 KB, 16221 lines) | 483.1 ms | 499.0 ms | 499.0 ms |
| Executor-shaped typical call | 0.069 ms | 0.11 ms | 0.20 ms |

ReDoS adversarial payloads (worst first): `long_line_1m` 284.1 ms max,
`long_user_chain` 70.3 ms, `long_equals` 56.6 ms, `bangs_200k` 35.7 ms,
`zwsp_100k` 28.6 ms, `repeated_secret` 24.3 ms, `nested_ws` 21.9 ms — all bounded,
no backtracking blow-up.

Linearity bisection: 800 / 1600 / 3200 / 6400 / 16221 lines =
23.8 / 51.3 / 96.3 / 211.3 / 482.7 ms — ≈2× per doubling (linear).

## 15. Determinism and robustness

- **Determinism**: 480 files ×2 sweep passes → **0 mismatches** in codes,
  messages, severities, line numbers and ordering (pre-fix: 0 as well — the
  contract keeps that property while adding codes).
- **O(n²) → O(n)**: pre-fix-style per-line FortiOS SNMP-block rescan cost
  2.55 M regex calls on chic.conf (>90 s, found by cProfile during this fix).
  `_fortinet_snmp_mask` now precomputes block membership in one pass; algorithm
  equivalence vs the old per-line method was verified (PASS), and chic.conf fell
  to ~0.48 s. Regression guard: 5000-line / 1000-block synthetic = 116 ms
  (V02-45).
- **ReDoS**: every pattern is bounded/anchored; §14 payloads all complete
  in ≤284 ms.
- **Hostile content classes**: binary signatures, NUL positions, C0 batteries,
  ZWSP dilution, comment nesting, oversized lines — each rejected or bounded by a
  dedicated test (categories C/D/E/F).

## 16. Change scope, evidence index, limitations, STOP

**Git verification** (`git status` / `git diff --stat`, final state, HEAD
`74ce952`, nothing committed): E02's own production change is
`backend/app/engines/validation.py` (+739 diff lines). Disclosed test/fixture
changes: `tests/test_validation.py` (28), `tests/test_vertical_slice.py` (170),
`tests/sample_configs/juniper_secure.txt` (112), plus untracked
`tests/validation/` (V02/V07/V08/V01 edits inside), `scripts/`, `artifacts/`.
Modified files belonging to E01 (left exactly as E01 delivered them):
`app/api/v1/configurations.py`, `app/config.py`, `app/engines/ingestion.py`,
`app/main.py`, `app/models/__init__.py`, `requirements.txt`. Frontend
(`package.json`, `tsconfig.json`, `package-lock.json`, `.env.example`) is
pre-existing user work — not touched, not reverted.

**Evidence index** — `artifacts/engine_validation/02_validation/`:
`raw_results.jsonl` (118 rows: 116 PASS / 1 PARTIAL / 1 NOT APPLICABLE),
`dataset_results_postfix.csv`, `dataset_summary_postfix.json`,
`performance_postfix.json`, `sweep_validation_postfix.py`,
`perf_validation_postfix.py`; pre-fix snapshot in `02_validation_pre_fix/`
(`summary.json`, `dataset_summary.json`, reports). `report_validation.py` was
intentionally not re-run — its SystemExit on changed statuses would abort, and
the pre-fix reports are preserved as-is in the snapshot.

**Limitations / explicitly out of scope**: V01-65 documented in §12 (Engine 01
code frozen); the 26 legacy failures are pre-existing (§12); the corpus cannot
exercise empty/binary/NUL gates (synthetic tests do); the 10% mirror divergence
is intentional (§6/§8); `juniper_secure.txt` was repaired by uncommenting, not
re-authored (all consuming tests re-verified green, §11).

**Finding status roll-up**: F1–F15 **all FIXED** (design decisions recorded in
§8). Nothing left NOT FIXED or NOT APPLICABLE.

**Engine 02 work is complete. STOP — Engine 03 is not started.**
