# ENGINE_READINESS_SUMMARY — Engine 02 · Configuration Validation Engine

**Scope:** `backend/app/engines/validation.py` (sole caller: `app/engines/compliance/executor.py:171-179`)
**Evidence:** 86 pytest rows (86 passed, 0 failed) · 480-file real corpus sweep · 0 production files modified
**Overall verdict:** **FAIL** (against the module's own documented contract)
**Date:** 2026-09-25

---

## Scoreboard

| Status | Count | % |
|---|---|---|
| PASS | 49 | 57.0% |
| PARTIAL | 15 | 17.4% |
| FAIL | 21 | 24.4% |
| NOT APPLICABLE | 1 | 1.2% |
| **Total** | **86** | 100% |

| Classification | Count |
|---|---|
| CONFIRMED BEHAVIOR | 50 |
| DESIGN LIMITATION | 17 |
| MISSING | 13 |
| BUG | 4 |
| RECOMMENDATION | 1 |
| NOT APPLICABLE | 1 |

| Category | Rows | Status |
|---|---|---|
| A functional | 2 | PASS 2 |
| B gate/caller contract | 2 | PASS 2 |
| C negative | 5 | PASS 4, FAIL 1 |
| D boundary | 10 | PASS 10 |
| E malformed / requested content classes | 17 | PASS 1, PARTIAL 13, FAIL 3 |
| F security | 29 | PASS 14, FAIL 15 |
| G reliability | 1 | PASS 1 |
| H determinism | 1 | PASS 1 |
| I error handling | 14 | PASS 12, PARTIAL 1, FAIL 1 |
| J performance | 1 | PASS 1 |
| K integration contract | 4 | PASS 1, PARTIAL 1, FAIL 1, N/A 1 |

---

## Hypotheses (14 CONFIRMED · 1 REJECTED · 0 UNVERIFIABLE)

CONFIRMED: H02-01 `NULL_BYTE` unreachable · H02-02 `is_valid` can only go False via `BINARY_CONTENT` ·
H02-03 empty/whitespace does not fail · H02-04 comment-only validates clean · H02-05 syntax claim not implemented ·
H02-06 `vendor_hint` inert, no mixed-vendor recognition · H02-07 unknown content never flagged ·
H02-08 credential misses space-separated/non-Cisco forms · H02-09 false positive on negated commands ·
H02-10 comment suppression limited to `!`/`#` · H02-11 dilutable >10% binary ratio ·
H02-12 `.warnings`/`.info` never populated · H02-13 non-str raises untyped error ·
H02-15 `crypto key generate` reported as credential.
REJECTED: H02-14 (warnings can stop an audit) — only `is_valid` gates.

---

## The eight requested content classes

| Class | Outcome |
|---|---|
| NUL bytes | **Rejected** (works) — but the dedicated `NULL_BYTE` error never fires (F3) |
| Binary-looking | **Rejected above a strict >10% ratio**; 9% dilution passes (F12) |
| Empty | **Warning only, `is_valid=True`** — gate opens (F4) |
| Whitespace-only | **Warning only** (space, tab, CRLF, FF, VT, `\x1c`) (F4) |
| Comments-only | **Zero issues, `is_valid=True`** (F5) |
| Malformed | **Accepted as valid** — no syntax rule exists despite docstring (F1) |
| Mixed-vendor | **Accepted** — no detection, `vendor_hint` never read (F6) |
| Unknown / unsupported | **Accepted** — no command vocabulary (F6) |

---

## Real-corpus evidence (480 files · 11,584,713 B)

- `is_valid=False`: **0** · warnings on 257 files · zero issues on 223 files
- `SENSITIVE_DATA` 9,543 hits / 209 files · `INSECURE_CONFIG` 134 hits / 131 files
- Determinism: 0 mismatches · UTF-8 failures: 0
- Cross-engine: 256 ingestible by Engine 01 → **256 valid**, 183 (71.5%) carry warnings, **0 rejected**
- Verified false positives: `chic.conf` line 2777 `community 11537:950;` ×688 reported as "SNMP community string"; `lhr-border-02.cfg:233 no ip http server` reported as "HTTP server enabled"

## Performance (measurement only)

1 KiB p50 0.235 ms · 100 KiB p50 27.4461 ms · 1 MiB p50 294.1773 ms · corpus p50 0.5477 / p95 24.7329 / p99 90.3617 ms · scaling ≈ linear · no regex blow-up.

---

## Blocking findings (must fix before this engine is considered ready)

1. **F1** — documented "Syntax patterns" capability entirely absent (`malformed.txt` validates clean).
2. **F2/F3** — the gate can close for one condition only; `NULL_BYTE` is dead code, no line number ever reported.
3. **F8/F9/F10** — detection accuracy: false positive on IOS negation, on the word `key`, on the word `community` (688× in one real file).

Secondary: **F4/F5** fail-open on empty/comment-only · **F6** `vendor_hint` inert · **F7/F11** detection gaps · **F13** dead `.warnings`/`.info` buckets.

## What is solid

Determinism (pytest + 480-file re-run) · exception-free on 12 adversarial `str` shapes incl. 1 MiB and lone surrogate · boundary arithmetic and 1-based line numbers exact · NUL always rejected (CWE-158) · flags behave as documented and the audit path leaves them on · performance adequate.

---

## Regression / integrity

- Full suite before E02: 499 collected / 473 passed / 26 failed → after: **585 / 559 / same 26 pre-existing failures** (157 new tests = 71 E01 + 86 E02).
- `git diff -- backend/app/` **empty**; `git status --porcelain -- backend/app/` **empty**.
- New files only: `tests/validation/test_v02_validation.py`, `scripts/engine_validation/{sweep_validation,report_validation}.py`, `artifacts/engine_validation/02_validation/*`.

## NOT APPLICABLE / NOT VERIFIABLE

ML evaluation (V02-35) deferred by instruction · vendor grammars don't exist · archives are Engine 01's scope · end-to-end empty-content audit belongs to Engine 11.

## Limitations of this validation

- Corpus is the supplied SIH dataset only; zero rejection across 480 files is a corpus observation, not proof of behaviour on hostile inputs outside those classes.
- Detection accuracy was sampled (4 line-verified files) plus targeted synthetic cases — the full 9,543 `SENSITIVE_DATA` hits were **not** individually adjudicated; the rate of further false positives is unknown.
- Caller behaviour was verified at source level (`executor.py:171-179`), not by executing the full audit — full-pipeline behaviour is Engine 11's scope.
- Performance numbers are single-machine measurements, not a readiness score.

---

**Readiness:** NOT READY — 3 blocking findings (F1, F2/F3, F8/F9/F10).
**Next:** Engine 03 — Detection Engine (pending user approval).
