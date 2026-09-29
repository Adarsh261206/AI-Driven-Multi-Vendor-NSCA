# ENGINE_READINESS_SUMMARY — Engine 03 · Vendor Detection Engine

**Scope:** `backend/app/engines/detection.py` (callers: `compliance/executor.py:188`, `benchmarks/execution.py:165`, `api/v1/audit_execution.py:137/178/215`)
**Evidence:** 66 pytest rows (66 passed, 0 failed) · 480-file corpus × 3 passes · 0 production files modified
**Overall verdict:** **FAIL** (contract instability and robustness, not core capability — see below)
**Date:** 2026-09-25

---

## Scoreboard

| Status | Count | % |
|---|---|---|
| PASS | 49 | 74.2% |
| PARTIAL | 8 | 12.1% |
| FAIL | 9 | 13.6% |
| **Total** | **66** | 100% |

| Classification | Count |
|---|---|
| CONFIRMED BEHAVIOR | 51 |
| BUG | 6 |
| DESIGN LIMITATION | 5 |
| MISSING | 3 |
| RECOMMENDATION | 1 |

| Category | Rows | Status |
|---|---|---|
| A functional (deployed path) | 9 | PASS 8, PARTIAL 1 |
| B path selection / scoring | 13 | PASS 12, FAIL 1 |
| C negative | 3 | PASS 3 |
| D boundary | 7 | PASS 5, PARTIAL 1, FAIL 1 |
| E content classes | 10 | PASS 7, PARTIAL 2, FAIL 1 |
| F security | 5 | PASS 3, FAIL 2 |
| G reliability | 2 | PASS 2 |
| H determinism | 2 | PASS 2 |
| I error handling | 3 | PASS 2, PARTIAL 1 |
| J performance | 2 | PASS 2 |
| K integration contract | 10 | PASS 3, PARTIAL 3, FAIL 4 |

---

## Hypotheses (14 CONFIRMED · 3 REJECTED · 0 UNVERIFIABLE)

CONFIRMED: H03-01 platform depends on which branch ran · H03-02 platform chosen at score 0 ·
H03-03 comment-only content yields a confident vendor · H03-04 mixed vendor never flagged ·
H03-05 unsupported vendors returned as supported · H03-06 one line (or one comment) reassigns the vendor ·
H03-07 documented `detection_method`/evidence contract ≠ implementation · H03-08 ML result has no platform-level evidence ·
H03-09 result depends on caller truncation · H03-10 non-str input raises untyped error ·
H03-11 project's own detection tests don't all pass · H03-12 IOS firmware captured only partially ·
H03-13 implemented scope exceeds documented MVP scope · H03-14 evidence cap of 10 broken on the ML path.

REJECTED: H03-15 non-determinism across calls/instances · H03-16 ML branch unreachable ·
H03-17 `detect()` fails on ordinary configuration input.

---

## Blocking findings (must be fixed before this engine is ready)

1. **F1** — one attacker-supplied line (or a line inside a comment) reassigns `vendor` on **both** branches. Vendor selects the parser and the control set, so this changes the audit result.
2. **F2** — out-of-scope vendors are returned *as* in-scope: 82/119 unsupported corpus files, **33 of the 256 audit-reachable files**, at confidence up to 0.95 → Cisco controls run on Arista/A10/FRR/F5 configs.
3. **F3** — the two branches report different `platform` for identical content (`ios` vs `ios_xe`): **175/256 audit-reachable files** (vendor differs for 0). Two callers already alias around it; two legacy tests fail because of it.
4. **F4** — results depend on caller truncation: API detects on `[:6000]`/`[:4000]`, audit on full content → 17 files change, `unknown` 73→76, one file 0.95 → 0.58.

Secondary: **F5** ML path collects no platform evidence for cisco · **F6** spec/impl drift (3 documented types) · **F7/F8** comment-only and mixed-vendor blind · **F11** evidence cap broken · **F12** IOS firmware truncated · **F16** no consumer applies a confidence threshold (25 audit-reachable files below 0.6, 9 at 0.0) · **F17** up to 4 detections per file per audit.

## What is solid

Determinism (10 calls, 2 instances, **0 mismatches across 480 files × 2 passes**) · crash-resistant on NUL / C0 controls / lone surrogate / non-ASCII / 1 MiB · ML failures degrade to regex instead of propagating · **vendor** agrees between branches on all 256 audit-reachable files · 214/215 directory-label agreement on audit-reachable content · confidence and evidence capped · roughly linear scaling · no regex blow-up.

---

## Corpus measurements (480 files · 11,584,713 B)

| Measure | Value |
|---|---|
| vendor | cisco 323 · unknown 73 · juniper 44 · fortinet 29 · paloalto 11 |
| branch taken | ML 276 · regex 204 |
| platform | ios_xe 239 · ios 81 · unknown 73 · junos 44 · fortios 29 · panos 11 · asa 2 · nx-os 1 |
| device type | router 257 · unknown 143 · switch 54 · firewall 26 |
| confidence | p50 0.6912 · p95 0.95 · max 0.95 · zeros 73 |
| hostname / firmware extracted | 292 / 219 |
| branch disagreement (vendor or platform) | 242/480 — of which **175/256 audit-reachable, all platform-only** |
| `[:6000]` truncation changes the verdict | 17 files (9 audit-reachable) |
| directory-labelled disagreements | 43/361 — incl. **paloalto 11/38 detected, 27 unknown** |
| unsupported-vendor files | 119 → 82 returned as a supported vendor, 37 unknown |
| determinism | **0 mismatches** · UTF-8 decode failures 0 |

Directory labels are not authoritative ground truth; these are disagreement counts only — **ML model quality is not evaluated** (`metadata.json`: `vendor_accuracy 1.0`, `device_type_accuracy 1.0`, `train_size 307` — recorded, not assessed).

## Performance (measurement only)

Corpus: deployed path p50 4.5705 / p95 150.2791 / p99 585.5868 ms; regex path p50 3.3402 / p95 104.4542 / p99 331.5757 ms.
Synthetic: ML 1 KiB 4.4971 → 1 MiB **2018.8630 ms**; regex 1 KiB 1.3242 → 1 MiB **1343.9449 ms** (the ML branch is slower than the regex branch on large inputs).

---

## Regression / integrity

- Full suite before E03: 585 collected / 559 passed / 26 failed → after: **651 / 625 / same 26 pre-existing failures** (223 new tests = 71 E01 + 86 E02 + 66 E03).
- The 26 failures are byte-identical to the pre-validation baseline; **2 of them are this engine's own legacy tests** (`tests/test_detection.py::test_cisco_ios_detection`, `::test_juniper_banner_detection`) — they were written against the regex branch and fail on the deployed ML branch (`ios_xe` vs `ios`, confidence 0.5979 vs >0.7). Pre-existing, unchanged by this work.
- `git diff -- backend/app/` **empty**; `git status --porcelain -- backend/app/` **empty**.
- New files only: `tests/validation/test_v03_detection.py`, `scripts/engine_validation/{sweep,report}_detection.py`, `artifacts/engine_validation/03_detection/*`, plus the conftest engine mapping for `03_vendor_detection`.

## NOT APPLICABLE / NOT VERIFIABLE

ML accuracy/calibration (deferred) · authoritative per-file ground truth (directory hints only) · end-to-end effect of a wrong vendor on findings (Engines 07/11) · live HTTP API behaviour (source-level only) · Palo Alto parsing (no parser exists; Engine 04's scope).

## Limitations of this validation

- Directory-derived labels are a hint, not ground truth — no accuracy number is claimed for either the regex or the ML branch.
- The spoofing findings (F1) were demonstrated on synthetic content and one corpus file; the whole corpus was not adversarially rewritten.
- Evidence content was verified for echo, not for downstream HTML/PDF escaping (that belongs to Engine 12).
- Performance numbers are single-machine measurements, not a readiness score.

---

**Readiness:** NOT READY — 4 blocking findings (F1, F2, F3, F4).
**Next:** Engine 04 — Configuration Parsing Engine (pending user approval).
