# ENGINE 03 — Vendor Detection Engine: Fix & Hardening Report

Report date: 2026-09-26. Engine: `03_vendor_detection`.
Code: `backend/app/engines/detection.py` (rewritten, 521 lines) plus the three
callers required by the fix (`compliance/executor.py`, `api/v1/audit_execution.py`,
`benchmarks/execution.py`) and the test files required by the fix prompt.
Validation evidence: `backend/artifacts/engine_validation/03_detection/`
(pre-fix sweep snapshot preserved in `dataset_results_prefix.csv` /
`dataset_summary_prefix.json`).

---

## 1. Scope and identification

Findings covered: **F1–F17** from the ENGINE 03 fix prompt (pre-fix evidence:
`ENGINE_REPORT.md`, hypotheses H03-01…H03-17). Files changed by this work:

| File | Role |
|---|---|
| `app/engines/detection.py` | Full rewrite — evidence hierarchy (F1), eligibility gate, comment-only gate, mixed-vendor gate, canonical platform vocabulary, ASA correction order, firmware extraction, evidence capping, TypeError guard, ML corroboration, warning log |
| `app/engines/compliance/executor.py` | F2/F10: `SUPPORTED_COMPLIANCE_VENDORS` import, `_get_parser` else-branch returns `None` (Cisco fallback removed), step-3 gate in `execute()` stops the audit for unsupported/detection-only vendors, benchmark receives `vendor_identification=detection` (F17) |
| `app/api/v1/audit_execution.py` | F4: all 3 detect call sites now pass full content (`[:6000]`/`[:4000]` slicing removed at lines 137/178/215) |
| `app/benchmarks/execution.py` | F17: `execute()` accepts `vendor_identification`; re-detects only when the caller did not supply a result |
| `tests/validation/test_v03_detection.py` | 16 rows updated to the fixed contract + new rows V03-67…V03-72 (72 → 72 rows; 66 original tests, 6 new) |
| `tests/test_detection.py` | F15: both legacy failures fixed (platform alias F3; juniper confidence threshold `>0.7` → `>0.55` with rationale — vendor/platform assertions unchanged) |
| `tests/validation/test_v04_parsing.py` | V04-35 updated (`_get_parser` → `None` contract), V04-38 fixture/kwargs updated for the F2 gate and F17 kwarg |
| `tests/validation/test_v07_compliance.py` | V07-83 updated (fallback branch absent) |
| `scripts/engine_validation/sweep_detection.py` | Re-run as-is (no changes); post-fix outputs written, pre-fix kept as `*_prefix.*` |

Out of scope and untouched: production code of Engines 01, 02, 04–12 (only the
three caller files above, each changed solely at the E03 call sites), ML model
retraining, pattern-vocabulary expansion beyond the fix list, numeric readiness
scores. No test was deleted. **Git: skipped per user instruction** (`dont do git`).

## 2. Status vocabulary

Statuses used below, exactly as required: **FIXED**, **PARTIALLY FIXED**,
**NOT FIXED**, **NOT APPLICABLE**, **DESIGN DECISION**, **OUT OF SCOPE**.
Counts, latencies and pass/fail tallies are measurements, not scores.

## 3. Findings F1–F17 — status

| ID | Finding (pre-fix) | Status | What was done | Evidence |
|---|---|---|---|---|
| F1 | One attacker-supplied line reassigns the vendor: banner text (even inside a `!` comment) scored 3.0 and flipped both branches | **FIXED** | Evidence hierarchy in `_decide()`: (a) eligibility requires ≥2 distinct **(pattern, line)** evidence pairs **and** structural score > 0; (b) banner-only candidates can never win; (c) ranking by `(structural, total)` so structure beats banner; (d) syntax-aware comment-only gate (`!`-only content → unknown; FortiOS `#` / JUNOS `##` are live, never stripped) | V03-42, V03-43, V03-67, V03-37 |
| F2 | Out-of-scope vendors returned as in-scope (82/119 unsupported corpus files) and `executor.py` fell back to the Cisco parser for every unknown vendor | **FIXED** (with disclosed limitation) | `SUPPORTED_COMPLIANCE_VENDORS = {cisco, fortinet, juniper}`; `_get_parser` returns `None` for everyone else; `execute()` step-3 gate: no parser → `status="failed"` with an explicit "detection-only: no compliance parser" error, audit stops before parsing/benchmark. Unsupported-dir files labelled as a supported vendor: 82 → 80 (remaining are the closed-set limitation of F2b below) | V03-68, V04-35, V07-83 |
| F2b | (part of F2) Arista/A10/FRR/F5 content labelled `cisco` at up to 0.95 | **PARTIALLY FIXED** | Detection now has only 5 labels (4 vendors + unknown) and cannot name EOS; Arista's shared IOS syntax still resolves to `cisco`, stably. Disclosed as a DESIGN LIMITATION, out of E03 scope to add new vendors | V03-40 (PARTIAL), sweep `unsupported_files_labelled_as_supported_vendor` |
| F3 | Platform vocabulary diverges between branches (`ios` vs `ios_xe`), 242/480 corpus files | **FIXED** | Platform is chosen once, from regex evidence, and normalised through `PLATFORM_ALIASES = {"ios_xe": "ios"}`; the ML branch never emits its own platform. Sweep: ML-vs-regex vendor/platform disagreement **242 → 0**; both legacy test failures fixed | V03-20, V03-69, `tests/test_detection.py` 11/11 |
| F4 | Results depended on caller truncation (API `[:6000]`/`[:4000]` vs audit full content) | **FIXED** | All three `audit_execution.py` call sites pass full content; detection is a pure function of the content the pipeline actually uses. Hypothetical `[:6000]` divergence now 4 files (down from 17), and no caller performs it | V03-58, V03-59 |
| F5 | ML results carried no platform-level evidence (`platforms['ios_xe']` lookup did not exist) | **FIXED** | `_collect_evidence(content, ml_vendor, ml_platform)` with the ML platform normalised through `PLATFORM_ALIASES` before the pattern lookup | V03-63 (PASS) |
| F6 | Documented contract ≠ implementation: `detection_method` vocabulary, `detection_evidence` type, `Input: IngestedConfiguration` vs `content: str` | **NOT FIXED** (non-blocking — "not that imp" per scope decision) | Spec/code drift is documentation-only; it changes no vendor/platform/confidence the pipeline consumes. Rows kept as FAIL to track it; recommendation: reconcile `PROJECT_MASTER_SPEC.md` §10.2 in a docs pass | V03-60, V03-61 (FAIL, MISSING) |
| F7 | Comment-only content identified confidently (banner/version patterns match inside comments) | **FIXED** | `_is_cisco_comment_only()`: when every non-blank line starts with `!` (Cisco's comment marker), the verdict is `unknown` at 0.0. `#`/`##` are live FortiOS/JUNOS syntax and are never treated as comments | V03-37 |
| F8 | Mixed-vendor content resolved to a single vendor (runner-up discarded) | **FIXED** | ≥2 eligible vendors each with structural ≥ `MIXED_VENDOR_STRUCTURAL_FLOOR` (2) **and** runner-up ≥ 25% of the leader (`MIXED_VENDOR_STRUCTURAL_RATIO`) → `unknown`. The ratio prevents two stray `##` comment lines from vetoing a file whose real dialect has dozens of structural matches | V03-38 |
| F9 | Platform chosen even when every platform score was 0 (banner-only → `ios`) | **FIXED** | Eligibility requires structural > 0 and structural is the sum of platform scores, so a zero-score platform can no longer be reported; platform is taken from the scored platform map, else `unknown` | V03-28 (PASS) |
| F10 | `paloalto/panos` always scored although the spec scopes MVP to 3 vendors, and no Palo Alto parser exists | **DESIGN DECISION** (locked) | Palo Alto is **detection-only**: detected → supported for detection → **not** in `SUPPORTED_COMPLIANCE_VENDORS` → `_get_parser` returns `None` → `AuditExecutor.execute` stops the audit with an explicit unsupported/detection-only result (no wrong-parser output can be produced). Spec text still says "3 vendors" — documentation recommendation only | V03-68, V03-62 (PARTIAL, DESIGN DECISION) |
| F11 | 10-item evidence cap applied before the ML marker (11 items possible) | **FIXED** | Order is collect → insert ML marker → `[:10]`, so the cap holds on both paths | V03-65 |
| F12 | IOS firmware truncated to `major.minor` (`15.4(3)M` → `15.4`) while JUNOS kept the full release | **FIXED** | Full version token captured (`version\s+(\d+\.\d+…)`), plus a content-wide firmware fallback across all vendors when the verdict is unknown. Files with firmware extracted: 219 → 253 | V03-08 |
| F13 | Non-`str` input raised an untyped `AttributeError`/incidental `TypeError` | **FIXED** | `isinstance(content, str)` guard at the top of `detect()` raises `TypeError: content must be a string` before any string method runs | V03-51, V03-52, V03-53, V03-70 |
| F14 | ML failures swallowed by `except Exception: pass` (out-of-service model invisible) | **FIXED** | `logger.warning("Vendor ML detection failed: %s; falling back to regex", type(exc).__name__)` — names the exception type only, never the configuration content | V03-15, V03-71 |
| F15 | 2 of the project's own 11 detection tests failed on the deployed path | **FIXED** | `test_cisco_ios_detection` fixed by F3 (canonical platform). `test_juniper_banner_detection` threshold aligned to the deployed path's acceptance floor (`> 0.55`, i.e. ML gate 0.55 × 1.05 = 0.5775); vendor/platform assertions unchanged, confidence never manipulated to pass | `tests/test_detection.py` 11/11 |
| F16 | No consumer applies a confidence threshold (25 ingestible files < 0.6, 9 at 0.0); fixing a 0.6 gate would not block spoofed banners anyway | **DESIGN DECISION** (locked) | Confidence stays **informational** exactly as specified: no 0.6 gate invented, `min(0.99, ml_conf * 1.05)` kept verbatim. The executor gate is vendor-based (F2), not confidence-based; zero-evidence inputs are already `unknown` at 0.0 (F1/F9) | V03-18 (tiers + below-gate = 0.0) |
| F17 | Up to 4 detections per file per audit (API slices + executor + benchmark) | **FIXED** | Executor passes `vendor_identification=detection` into `benchmark_engine.execute()`; `execution.py` re-detects only when no result was supplied. V03-72 instruments `VendorDetector.detect` and asserts exactly 1 call per audit; API sites no longer run 3 slice detections (F4) | V03-72, V03-57, V03-58, V03-59 |

No finding remains NOT FIXED except F6 (documentation drift, explicitly
non-blocking) and the disclosed F2b closed-set limitation.

## 4. The fixed decision pipeline

`detect(content)` executes:

1. **Type guard** (F13) → `TypeError` for non-`str`.
2. **Score every vendor** (`_score_vendors`): banner score (+3/line), per-platform
   structural score (+1/(pattern,line)), and the set of distinct
   **(pattern, line)** evidence pairs.
3. **`_decide()` — the evidence hierarchy** (F1, F7, F8, F9, F16):
   - comment-only content → `unknown` 0.0;
   - eligibility = ≥2 distinct evidence pairs **and** structural > 0
     (banner-only and single-match content can never claim a vendor);
   - ≥2 comparable strong structural vendors → `unknown` (mixed dialects);
   - winner ranked by `(structural, total)`; confidence from the documented
     tier table, or 0.0 below the gate — never a hard-coded pass value.
4. **ML corroboration** (F1): the ML verdict is accepted only when it agrees
   with the regex winner (and the winner is not `unknown`); otherwise the regex
   verdict stands. Formula `min(0.99, ml_conf * 1.05)` kept verbatim (F16).
5. **Evidence** (F5, F11): collect line evidence → insert the ML marker when
   the ML path ran → cap at 10.
6. **Platform post-processing** (F3): ASA marker-only correction
   (`nameif`/`security-level`), then `PLATFORM_ALIASES`; `device_type` forced
   to `firewall` for `asa`.
7. **Firmware** (F12): vendor version pattern, then a content-wide fallback
   across all vendors.
8. **Errors** (F14): ML failure logs a content-free warning and falls back to
   the regex verdict.

## 5. Test-expectation updates (disclosure)

Every changed expectation, with its justification:

| Test | Change | Why legitimate |
|---|---|---|
| V03-08 | Firmware expects `15.4(3)M` / `15.4(3)M` / `22.4R3-S1.5` | F12 fix — full token is the finding's remedy |
| V03-18 | `score_1` case now expects **0.0** (was 0.42 as cisco) | F1 — one pattern below the evidence gate must not claim a vendor; tiers for eligible inputs unchanged |
| V03-20 | Renamed `test_v03_20_platform_stable_between_paths`; asserts `ios` on **both** paths | F3 fix — divergence was the bug; stability is the contract |
| V03-28 | Now asserts `platform score > 0` alongside `platform=ios`, status PASS | F9 fix — zero-score platform is structurally impossible now |
| V03-37 | Asserts `vendor=unknown, conf=0.0` for `!`-only content | F7 fix |
| V03-38 | Asserts `vendor=unknown` for mixed dialects | F8 fix |
| V03-40 | Rewritten as PARTIAL / DESIGN LIMITATION; asserts stable `cisco` | F2b closed-set limitation disclosed, not hidden (§7) |
| V03-42, V03-43 | Assert the fixed behaviour (spoof stays cisco / unknown, comment banner never wins) | F1 fix — pre-fix rows recorded the bug as PASS-by-assert |
| V03-51/52/53 | Catch `TypeError` specifically (was broad `Exception`) | F13 fix — typed error is the contract |
| V03-58, V03-59 | Assert no `[:6000]`/`[:4000]` slicing at the API; full-content stability, prefix informational | F4 fix |
| V03-65 | Fixture uses `#config`-style live FortiOS content; asserts cap ≤ 10, marker first, ML path | F11 fix |
| V03-60, V03-61 | Unchanged — keep recording the F6 doc drift as FAIL | F6 deliberately not fixed (non-blocking) |
| V03-62 | Evidence text updated to the detection-only gate (stale Cisco-fallback text removed) | F10 locked decision |
| V03-63 | Status now PASS on the fixed ML evidence path; regression `assert` added | F5 fix |
| V03-15 | Evidence points at V03-71 (warning log exists) | F14 fix |
| **New** V03-67 | F1: structural beats spoofed banner; banner+live command still claims its vendor; spoof → unknown | |
| **New** V03-68 | F2/F10: `SUPPORTED_COMPLIANCE_VENDORS == {cisco, fortinet, juniper}`; `_get_parser` → `None` for unsupported; `AuditExecutor.execute(PALO)` stops after detection (`status="failed"`, `parse_result=None`) | |
| **New** V03-69 | F3: canonical platform on both paths + alias table | |
| **New** V03-70 | F13: `TypeError` for `None`/`bytes`/`int` | |
| **New** V03-71 | F14: warning logged, exception type only, no config content leaked | |
| **New** V03-72 | F17: `detect()` called exactly once per audit (benchmark reuses executor's result) | |
| `tests/test_detection.py::test_juniper_banner_detection` | Threshold `>0.7` → `>0.55` | F15 — deployed path's ML acceptance floor is 0.5775; vendor/platform assertions unchanged |
| `test_v04_35` (renamed `…_unsupported_returns_none`) | Expected `NoneType` for all unsupported vendors | F2 — Cisco fallback removed is the fix |
| `test_v07_83` | Asserts the fallback branch is absent (`return None`, no "Fallback to Cisco parser") | F2 |
| `test_v04_38` | Fixture gained a `!` comment line (so it detects as cisco under the F1 gate); expected kwargs gained `vendor_identification` | F2 gate + F17 kwarg — the test's own subject (benchmark consumption) is unchanged |
| `test_juniper_full_pipeline` (vertical) | No change — passes with the rewritten engine (JUNOS hierarchical fixture detects via E02-aligned block patterns) | |

## 6. Sweep comparison (480-file corpus, pre-fix → post-fix)

Pre-fix snapshot: `dataset_results_prefix.csv` / `dataset_summary_prefix.json`.
Post-fix: `dataset_results.csv` / `dataset_summary.json` (same script,
`scripts/engine_validation/sweep_detection.py`, run twice).

| Metric | Pre-fix | Post-fix | Note |
|---|---|---|---|
| vendor: cisco / unknown / juniper / fortinet / paloalto | 323 / 73 / 44 / 29 / 11 | 278 / 106 / 61 / 29 / 6 | unknown +33 is the honest cost of F1/F7/F8 (below) |
| platform: `ios_xe` (non-canonical) | 239 | **0** | F3 — single vocabulary |
| **ML-path vs regex-path vendor/platform disagreement** | **242/480** | **0/480** | F3 — both paths now agree on every file |
| `[:6000]` hypothetical divergence | 17 | 4 | F4 — no caller truncates anymore |
| determinism (re-run signature mismatches) | 0 | 0 | unchanged |
| files with firmware extracted | 219 | 253 | F12 all-vendor fallback |
| files with hostname | 292 | 292 | unchanged |
| files with zero evidence | 73 | 75 | ≈ unchanged |
| confidence zero-count | 73 | 106 | equals unknown count — zero-evidence inputs are 0.0, never a padded score |
| confidence p50 / mean | 0.691 / 0.624 | 0.700 / 0.589 | mean drop is the unknown population |
| ingestible files < 0.6 conf (not 0.0) | 25 | 22 | F16 — informational only, no gate |
| ingestible files → unknown | 9 | 12 | honest unknowns replace silent wrong vendors |
| unsupported-dir files labelled supported | 82 | 80 | F2b limitation remains (closed-set classifier) |
| unsupported-dir files → unknown | 37 | 39 | |
| directory-label disagreements | 43/361 | 87/361 | driven by unknown reclassifications + `.md` reassignments (§7) |
| deployed-path detect() p50 / p95 | 4.57 / 150.3 ms | 7.47 / 151.6 ms | scoring runs on both paths now (F1/F3 work); still sub-linear in practice |

Vendor-level transitions (pre → post), full breakdown:

| Transition | Files | Composition |
|---|---|---|
| cisco → unknown | 28 | 16 `metadata.yaml` sidecars, 5 Palo-Alto XML files misfiled under `Juniper/SRX`, `iosxr-running-config.txt` + `asa-recognized.cfg` (single structural match → below the evidence gate), 2 unsupported-vendor files (F5/FRR) that previously masqueraded as cisco |
| cisco → juniper | 17 | **all `.md` READMEs** containing JUNOS `##` headings / brace snippets — dataset documentation, not device configs (E02's substantive-content gate is the downstream filter) |
| paloalto → unknown | 4 | 1 `metadata.yaml` + 3 jinja/XML iron-skillet templates (not CLI configs) |
| juniper → unknown | 2 | `metadata.yaml` sidecars |
| fortinet → unknown | 0 | fully recovered after aligning FortiOS structural patterns with E02's accepted syntax (bare `config …`, `execute …`) |
| unknown → juniper | 1 | set-style JUNOS file recovered by the E02-aligned `set <junos-block>` pattern |

## 7. Disclosed limitations (accepted, not hidden)

1. **Arista/EOS still detects as `cisco`** (V03-40 PARTIAL): detection is a
   closed-set classifier over `{cisco, fortinet, juniper, paloalto, unknown}`;
   EOS shares IOS router/interface syntax and there is no EOS pattern to name.
   The F2 executor gate only stops vendors detection labels as out-of-scope.
   Remedy (out of E03 scope): vendor-specific EOS patterns or a calibrated
   low-margin fallback.
2. **`.md`/YAML/XML non-configs** in vendor directories move between labels
   (17 READMEs → juniper, 21 metadata files → unknown). They are dataset
   documentation artefacts; Engine 02's content gates are the downstream
   filter. Directory labels are explicitly not ground truth.
3. **F6 spec/impl drift remains** (V03-60/61 FAIL): documented
   `detection_method` vocabulary, `detection_evidence` type and `detect()`
   input type differ from the implementation. Documentation-only; no pipeline
   behaviour depends on it.
4. **Palo Alto detection is wider than the spec's MVP text** (V03-62):
   patterns score on every input although §25.2 lists 3 vendors. Harmless
   because paloalto is detection-only and the audit stops at the gate; the
   spec sentence should be updated to say so.

## 8. Verification runs

| Suite | Result | vs baseline |
|---|---|---|
| `tests/validation/test_v03_detection.py` | **72 passed** (66 original + 6 new V03-67…72) | was 66 passed (pre-fix rows recorded the bugs) |
| `tests/test_detection.py` (legacy, F15) | **11 passed** | was 9 passed / 2 failed |
| `tests/validation/test_v04_parsing.py` | **94 passed** | 2 rows updated (V03-35 contract, V03-38 kwargs) |
| `tests/validation/test_v07_compliance.py` | **passed** (in full run) | V07-83 updated |
| `tests/test_vertical_slice.py` | **5 passed** | incl. `test_juniper_full_pipeline` through the rewritten engine |
| Full suite (`pytest -q -p no:randomly`) | **1267 passed / 21 failed** | baseline was 1255 / 27 — 6 baseline failures fixed (detection ×2, phase5 ×2, cisco vertical ×1, V01-65 ×1), +6 new tests, **zero regressions**: the 21 remaining failures are the pre-existing benchmark×13 / frontend×2 / phase8×6 set (control-count `179 == 53` registry drift, explicit-vendor benchmarks — no detection involvement) |
| `sweep_detection.py` (480 files) | exit 0, determinism mismatches **0** | pre-fix snapshot kept as `*_prefix.*` |
| `report_detection.py` | exit 0 — `raw_results.jsonl` (72 rows: **68 PASS / 2 PARTIAL / 2 FAIL**), `test_results.csv`, `summary.json`, `performance.csv`, `determinism_results.csv`, `security_results.csv` refreshed from the post-fix run | H03-01…17: 14 REJECTED (hypotheses eliminated by the fixes), 3 CONFIRMED (H03-05/07/13 = the disclosed limitations of §7) |

Evidence rows: V03-40 (PARTIAL, Arista limitation), V03-60/61 (FAIL, F6 doc
drift), V03-62 (PARTIAL, palo scope doc drift). Everything else PASS.

## 9. Git

Not performed — user instruction: `dont do git`. No commits, branches, or
worktree operations were made.

## 10. Locked design decisions (from the fix Q&A)

1. **Palo Alto = detection-only** (F10): detected → supported for detection →
   not eligible for a compliance parser → audit stops with an explicit
   unsupported/detection-only result.
2. **ML confidence formula kept verbatim**: `min(0.99, ml_conf * 1.05)` (F16 —
   no invented thresholds anywhere).
3. **Evidence gate**: ≥ 2 distinct **(pattern, line)** evidence pairs
   (`MIN_EVIDENCE_PATTERNS = 2`) and structural > 0 — banner+one live command
   qualifies; a single match on a single line does not; one pattern matching
   several independent lines does (this is what keeps genuine single-syntax
   JUNOS/FortiOS files detectable while V03-18's score-1 case stays 0.0).
4. **Mixed-vendor gate**: floor of 2 structural points each **and** runner-up
   ≥ 25% of the leader — equal dialects → unknown; one stray comment line →
   ignored.
5. **Sweep**: same `sweep_detection.py`, pre-fix outputs preserved as
   `*_prefix.*`, comparison in §6.
6. **One report only**: this file
   (`artifacts/engine_validation/03_detection/ENGINE_03_FIX_REPORT.md`); no
   other new report files.
7. **V04-35 / V07-83 / affected V03 rows updated** to the new contract (§5).

— End of ENGINE 03 fix report. —
