# Engine 03 — Vendor Detection Engine

**Scope:** `backend/app/engines/detection.py` only.
**Validated:** 2026-09-25 · **Overall status:** **FAIL** (see §12)

---

## 1. Method

| Item | Value |
|---|---|
| Production code modified | none — `git diff -- backend/app/` is empty |
| Test harness | `backend/tests/validation/test_v03_detection.py` (new) |
| Evidence rows | 66 (`raw_results.jsonl`) from 66 pytest cases — **66 passed, 0 failed** |
| Dataset sweep | 480 real files, 11,584,713 bytes, three passes per file (deployed path, regex path, determinism) + a `[:6000]` truncation probe |
| Database | not required — the engine is pure (no I/O) |
| ML models | **loaded and used** (artifacts present). Model *quality* is not evaluated here — deferred by instruction until all 12 engines are validated |
| Baseline regression | before Engine 03: 585 collected / 559 passed / 26 failed → after: **651 collected / 625 passed / same 26 pre-existing failures** |
| Engines 01 & 02 artifacts | used as baseline evidence (read-only) |

```bash
backend\venv\Scripts\python.exe -m pytest tests/validation/test_v03_detection.py -q -p no:randomly
backend\venv\Scripts\python.exe scripts\engine_validation\sweep_detection.py
backend\venv\Scripts\python.exe scripts\engine_validation\report_detection.py
```

Categories: A functional (deployed path) · B path selection and scoring · C negative · D boundary · E content classes · F security · G reliability · H determinism · I error handling · J performance · K integration contract.

---

## 2. Contract under test

`VendorDetector.detect(content: str) -> VendorIdentification(vendor, platform, confidence, firmware_version, detection_method, detection_evidence, device_type, hostname)` (`detection.py:161`)

**Two mutually exclusive branches:**

| | ML branch (`detection.py:173-211`) | Regex branch (`detection.py:213-291`) |
|---|---|---|
| Selected when | `get_ml_detector().is_available` **and** `ml_conf >= 0.55` **and** `ml_vendor != "unknown"` | any of those fails, or the ML branch raises |
| vendor / platform | from `ml.predict()`; platform via `app/ml/model.py:96-102` (`cisco→ios_xe`, `juniper→junos`, `fortinet→fortios`, `paloalto→panos`) | highest `VENDOR_PATTERNS` score; platform = `max()` of that vendor's platform scores |
| confidence | `min(0.99, ml_conf * 1.05)` (`:203`) | tier table (`:251-258`): ≥5 → `min(0.95, 0.7+0.02s)`; ≥3 → `min(0.90, 0.6+0.02s)`; ≥1 → `min(0.70, 0.4+0.02s)`; else 0.0 |
| `detection_method` | forced `PATTERN` (`:205`) | first evidence item's method, else `KEYWORD` (`:278-280`) |
| evidence | ML marker inserted first (`:194-199`), then `_collect_evidence()` capped at 10 (`:344`) | `_collect_evidence()` capped at 10 |
| scoring | none (model decides) | banner `+3.0` per matching line per pattern (`:222-225`), platform `+1.0` per matching line per pattern (`:228-233`); ties resolve to the first key in `VENDOR_PATTERNS` (`:243-246`, order cisco → fortinet → juniper → paloalto) |
| failures | any exception → `except Exception: pass` (`:210-211`) → silent regex fallback | n/a |

**Shared post-processing:** firmware = first matching `version_patterns` capture (`:293-303`); device type = class with ≥2 distinct pattern hits, else `unknown` (`:346-356`); hostname from 4 patterns (`:358-364`); Cisco-firewall correction `ios_xe → asa` when `nameif|security-level \d+` matches, ML branch only (`:189-191`).

**Callers (all source-level):**

| Caller | Content passed | Effect |
|---|---|---|
| `compliance/executor.py:188` | full content | vendor → parser selection (`:116-128`, unknown → Cisco parser), platform → benchmark platform with `ios→ios_xe` alias (`:214-217`) |
| `benchmarks/execution.py:165` | full content, **second** detection per audit | result carried as `vendor_identification` (`:227`); caller's vendor still wins (`:164-175`) |
| `api/v1/audit_execution.py:137` | `raw_content[:6000]` | live "file details" for the UI |
| `api/v1/audit_execution.py:178` | `raw_content[:4000]` | log line |
| `api/v1/audit_execution.py:215` | `raw_content[:6000]` | live "file details" per file |

Up to four `detect()` calls per file per audit, **on different slices of content**.

---

## 3. Which branch actually runs (observed)

| Input | Branch | vendor / platform | confidence |
|---|---|---|---|
| canonical IOS config | ML | cisco / ios_xe | 0.597 |
| canonical IOS banner | ML | cisco / ios_xe | 0.605 |
| canonical JUNOS config | ML | juniper / junos | 0.657 |
| canonical PAN-OS config | ML | paloalto / panos | 0.675 |
| canonical FortiOS config | **regex** (`ml_conf`=0.5013 < 0.55) | fortinet / fortios | 0.680 |
| NX-OS config | **regex** | cisco / nx-os | 0.800 |
| ASA config | ML (after `asa` correction) | cisco / asa | 0.736 |
| empty / whitespace / prose | **regex** (model returns `unknown`) | unknown | 0.0 |
| 1 MiB interface stanzas | ML | cisco / ios_xe | — |

Branch selection is **content-dependent**: on the corpus, ML ran on 276/480 files and the regex branch on 204/480. Two different platform vocabularies are therefore in daily use for identical inputs.

---

## 4. Results by category

| Cat | Requirement | Rows | Status |
|---|---|---|---|
| A | vendor identification for 4 vendors, result shape, device type, hostname, firmware, evidence | 9 | PASS 8, PARTIAL 1 |
| B | branch selection, confidence formulas and caps, platform divergence, ASA correction | 13 | PASS 12, **FAIL 1** |
| C | empty / whitespace / prose → unknown | 3 | PASS 3 |
| D | device-type threshold, zero-score platform, tie-break, evidence caps | 7 | PASS 5, PARTIAL 1, **FAIL 1** |
| E | NUL, control chars, surrogate, unicode, 1 MiB, comment-only, mixed-vendor, malformed, unsupported vendor | 10 | PASS 7, PARTIAL 2, **FAIL 1** |
| F | banner injection, comment injection, evidence echo, flood cap, regex cost | 5 | PASS 3, **FAIL 2** |
| G | state isolation, ML singleton | 2 | PASS 2 |
| H | determinism (10 calls, 2 instances) | 2 | PASS 2 |
| I | non-str inputs | 3 | PASS 2, PARTIAL 1 |
| J | scaling (ML path, regex path) | 2 | PASS 2 |
| K | executor / benchmark / API contract, spec drift, evidence gap, legacy tests, cross-engine baseline | 10 | PASS 3, PARTIAL 3, **FAIL 4** |

**Totals:** PASS 49 · PARTIAL 8 · FAIL 9.
**Classifications:** CONFIRMED BEHAVIOR 51 · BUG 6 · DESIGN LIMITATION 5 · MISSING 3 · RECOMMENDATION 1.

---

## 5. Expectations

**External standards:** no directly applicable external standard governs vendor/platform classification *from configuration text*. NIST SP 800-53 / SP 800-128 catalogues were checked for an inventory-identification control and no wording specific to this stage could be verified here (the SP 800-53 catalogue PDF exceeds the 5 MB fetch limit; SP 800-128 fetch returned raw PDF bytes). **No external standard is claimed below that was not verified.**

| ID | Expectation | Source | Result |
|---|---|---|---|
| E-1 | "Purpose: Identify vendor, platform, and firmware version" | **Project-defined** — `docs/PROJECT_MASTER_SPEC.md` §10.2 | **PARTIAL** — vendor: yes for in-scope content; platform: not stable (F3); firmware: partial for IOS (F12) |
| E-2 | Responsibilities: pattern matching against known vendor signatures, banner detection, configuration structure analysis, confidence scoring | **Project-defined** — §10.2 | **MET** — all four exist (`:57-159`, `:218-258`) |
| E-3 | `Input: IngestedConfiguration`, `Output: VendorIdentification` | **Project-defined** — §10.2 | **NOT MET** — input is `content: str` (`:161`) |
| E-4 | `detection_method: "pattern" \| "banner" \| "structure" \| "ai"`, `detection_evidence: string[]` | **Project-defined** — §10.2 TS contract | **NOT MET** — 5-value enum, evidence objects (V03-60, V03-61) |
| E-5 | "We don't claim to support every vendor from day one" / "We support Cisco, Fortinet, Juniper in MVP" | **Project-defined** — §6.3, §25.2 | **NOT MET** — out-of-scope content is returned *as* a supported vendor with confidence up to 0.95 (F2); paloalto implemented and always scored (F10) |
| E-6 | Confidence scores are provided so consumers can decide (no "100% accuracy" claim) | **Project-defined** — §25.2 | **MET** — confidence is always populated and capped; but no consumer applies a threshold (F16) |

---

## 6. Hypotheses

**CONFIRMED (14)** — the defect claim was observed:

| ID | Statement | Evidence |
|---|---|---|
| H03-01 | the reported platform depends on which branch ran (`ios` vs `ios_xe`) | V03-20 FAIL |
| H03-02 | platform can be reported from a winner whose platform score is 0 | V03-28 PARTIAL |
| H03-03 | comment-only content still yields a confident vendor | V03-37 PARTIAL |
| H03-04 | mixed-vendor content is never flagged as ambiguous | V03-38 PARTIAL |
| H03-05 | unsupported vendors are attributed to a supported vendor instead of `unknown` | V03-40 FAIL |
| H03-06 | one attacker-supplied line reassigns the vendor, including from inside a comment | V03-42, V03-43 FAIL |
| H03-07 | the documented `detection_method` / evidence contract does not match the implementation | V03-60, V03-61 FAIL |
| H03-08 | an ML result carries no line-level evidence for the platform it reported | V03-63 FAIL |
| H03-09 | the result depends on how much content the caller passes | V03-58 PARTIAL, V03-59 FAIL |
| H03-10 | non-str input raises an untyped error | V03-51 PARTIAL |
| H03-11 | the project's own detection tests do not all pass on the deployed path | V03-64 PARTIAL |
| H03-12 | firmware version is captured only partially for IOS | V03-08 PARTIAL |
| H03-13 | implemented vendor scope exceeds the documented MVP scope | V03-62 PARTIAL |
| H03-14 | the 10-item evidence cap does not hold on the deployed path | V03-65 FAIL |

**REJECTED (3)** — not observed:

| ID | Statement | Evidence |
|---|---|---|
| H03-15 | identical content yields different results across calls or instances | V03-47, V03-49, V03-50 PASS |
| H03-16 | the ML branch is unreachable in this deployment | V03-10 PASS |
| H03-17 | `detect()` fails on ordinary configuration input (1 MiB / unicode / NUL / surrogate / control chars) | V03-32…V03-36 PASS |

---

## 7. Dataset sweep (480 real files)

### Identification distribution (deployed path)

| Vendor | Files | | Platform | Files | | Device type | Files |
|---|---|---|---|---|---|---|---|
| cisco | 323 | | ios_xe | 239 | | router | 257 |
| unknown | 73 | | ios | 81 | | unknown | 143 |
| juniper | 44 | | unknown | 73 | | switch | 54 |
| fortinet | 29 | | junos | 44 | | firewall | 26 |
| paloalto | 11 | | fortios | 29 · panos 11 · asa 2 · nx-os 1 | | | |

Branch taken: **ML 276 · regex 204**. Confidence: p50 0.6912 · p95 0.95 · max 0.95 · zeros 73.
Hostname extracted on 292 files, firmware on 219 files, zero evidence on 73 files (all `unknown`).

### Cross-engine view — the 256 files Engine 01 would store

| Measure | Value |
|---|---|
| Engine 01 ingestible | 256 (all of them `is_valid` per Engine 02) |
| …with a directory-derived vendor label | 215 |
| …of those, label vs. detection **disagreement** | **1** (`Cisco\MultiAS-Lab\mpls-infrastructure\hosts.cfg` → unknown, conf 0.0) |
| per-label | cisco 177/178 · fortinet 17/17 · juniper 15/15 · paloalto 5/5 |
| …from **unsupported** vendor directories (Arista, A10, FRR, F5, NAPALM) | **41 → labelled cisco 33, unknown 8** |
| …with confidence 0.0 | 9 |
| …with confidence < 0.6 | 25 |
| platform split | ios_xe 173 · ios 34 · fortios 17 · junos 15 · unknown 9 · panos 5 · asa 2 · nx-os 1 |
| hostname / firmware extracted | 210 / 174 |

Directory labels are **not authoritative ground truth** and no accuracy figure is reported — ML quality is deferred to the ML evaluation phase.

### Full-corpus measurements

| Measure | Value |
|---|---|
| Directory-labelled files | 361 → **43 disagreements** (cisco 242/252, fortinet 29/30, juniper 36/41, **paloalto 11/38 — 27 return `unknown`**) |
| Unsupported-vendor files | 119 → **82 returned as a supported vendor**, 37 `unknown` |
| Files where the two branches disagree (vendor or platform) | **242 / 480** — among ingestible files: **175, all platform-only, vendor differs for 0** |
| `[:6000]` truncation changes vendor or platform | **17 files** (9 of them ingestible); truncation raises `unknown` from 73 → 76 |
| Determinism (second full pass) | **0 mismatches** |
| UTF-8 decode failures | 0 |

Examples of truncation divergence (ingestible):

| File | Full | `[:6000]` |
|---|---|---|
| `Cisco\Routers\IOS\c2911-router.conf` | cisco / ios / 0.95 | cisco / ios_xe / 0.73 |
| `Cisco\Switches\Catalyst\c3560g-L3Switch.conf` | cisco / ios_xe / 0.6961 | cisco / ios / 0.95 |
| `Arista\Switches\EOS\DC1-LEAF1A.cfg` | cisco / ios / 0.95 | cisco / ios_xe / 0.5833 |
| `Cisco\Switches\Nexus\nxos-connection-log.txt` | cisco / ios / 0.95 | cisco / nx-os / 0.95 |

Non-configuration artefacts are also identified with high confidence — `A10\...\README.md` → juniper 0.94, `Fortinet\...\*-xccdf.xml` → fortinet 0.95, `Cisco\Firewalls\ASA\README.md` → cisco 0.95. All of them are **rejected by Engine 01 on extension**, so they never reach detection in the real pipeline.

---

## 8. Performance (measurements only — not a readiness score)

Synthetic scaling, `time.perf_counter`:

| Branch | 1 KiB p50 | 100 KiB p50 | 1 MiB p50 |
|---|---|---|---|
| deployed (ML), 20/5/3 samples | 4.4971 ms | 209.6540 ms | **2018.8630 ms** |
| regex (ML forced off), 20/5/3 samples | 1.3242 ms | 154.8222 ms | **1343.9449 ms** |

Both branches scale roughly linearly (1 MiB / 1 KiB ≈ 449× ML, ≈ 1014× regex for a 1024× input), but on large inputs the ML branch is the *slower* of the two — 2.02 s vs 1.34 s at 1 MiB, because the full text is vectorised while the regex branch only scans its pattern set.

Real corpus (480 files):

| Pass | p50 | p95 | p99 | mean |
|---|---|---|---|---|
| deployed path | 4.5705 ms | 150.2791 ms | 585.5868 ms | 32.8491 ms |
| regex path | 3.3402 ms | 104.4542 ms | 331.5757 ms | 22.9632 ms |

Adversarial: 200 k-character regex scoring completes in ~23–28 ms (V03-46); a 5000-line banner flood completes in well under 5 s with confidence capped at 0.95 and evidence at 10 (V03-45).

Note: the regex path re-scans **every pattern against every line** (26 patterns), so cost is linear in lines with a large constant — 506 ms for a 456 k-character file measured during inspection.

---

## 9. Findings

| # | Finding | Class | Evidence | Recommendation |
|---|---|---|---|---|
| F1 | **One attacker-supplied line reassigns the vendor.** `hostname R1` + `interface…` + `line vty 0 4` + `Palo Alto Networks PA-220…` → paloalto on *both* branches; `! this is a Juniper Networks lab note` + an IOS hostname → juniper. No comment or position weighting | **BUG** | V03-42, V03-43 | Score banners only outside comments and require ≥1 vendor-specific command match before a banner-only win |
| F2 | **Out-of-scope vendors are returned as in-scope vendors** with confidence up to 0.95 — Arista/A10/FRR/F5/NAPALM: 82/119 corpus files, **33 of the 256 files the pipeline will actually audit**. `executor.py:116-128` then runs the Cisco parser and the Cisco benchmark on them | **BUG** | V03-40, §7 | Emit an `unsupported` state (or require a calibration margin) so out-of-scope input cannot enter a supported-vendor control set |
| F3 | **Platform vocabulary diverges between the two branches** (`ios` vs `ios_xe`); identical content gives a different `platform`. 242/480 corpus files, **175/256 ingestible files** differ — vendor differs for 0 of them. Two callers already carry aliases (`executor.py:214-217`, `execution.py:167-175`) and two legacy tests fail because of it | **BUG** | V03-20, V03-64, §7 | One platform vocabulary produced in one place, aliased only at the API boundary |
| F4 | **Results depend on caller truncation.** API detects on `[:6000]` / `[:4000]` while the audit detects on full content: 17 corpus files change vendor or platform, `unknown` rises 73→76, and one ingestible file moves 0.95 → 0.58. The UI can therefore show a different vendor from the audit for the same file | **BUG** | V03-58, V03-59, §7 | Detect once, on the same content the pipeline uses, and cache the result |
| F5 | **ML results carry no platform-level line evidence.** `_collect_evidence` looks up `VENDOR_PATTERNS['cisco']['platforms']['ios_xe']`, which does not exist (keys: `ios`, `nx-os`, `asa`), so a confident Cisco ML result is explained only by the model marker | MISSING | V03-63 | Map the ML platform back to the pattern keys when collecting evidence |
| F6 | **Documented contract does not match the implementation**: `detection_method` values, `detection_evidence` type, and `Input: IngestedConfiguration` vs `content: str` | MISSING | V03-60, V03-61 | Reconcile spec and code |
| F7 | Comment-only content is identified confidently (banner/version patterns match inside comments) — no "no live commands" condition exists | DESIGN LIMITATION | V03-37 | Flag content that has no substantive command line |
| F8 | Mixed-vendor content resolves to a single vendor; runner-up scores are discarded | DESIGN LIMITATION | V03-38 | Expose the score vector / runner-up |
| F9 | Platform is chosen even when every platform score is 0 (banner-only input → `ios`) | DESIGN LIMITATION | V03-28 | Return `unknown` platform at score 0 |
| F10 | paloalto/panos is implemented and scored for every input although the spec scopes MVP to 3 vendors, and `_get_parser` has no Palo Alto parser | DESIGN LIMITATION | V03-62 | Gate it behind the documented scope or update the spec |
| F11 | The 10-item evidence cap is applied *before* the ML marker is inserted, so ML results can carry 11 items (corpus: `Juniper\Firewalls\SRX\configs_junos-srx-1.cfg`) | DESIGN LIMITATION | V03-65 | Cap after inserting the marker |
| F12 | IOS firmware is truncated to `major.minor` (`15.4(3)M` → `15.4`) while JUNOS keeps the full release string | PARTIAL | V03-08 | Capture the full version token |
| F13 | Non-str input raises untyped `AttributeError`/`TypeError` from inside the method (the guard-less `content.splitlines()` sits outside the ML `try`) | RECOMMENDATION | V03-51 | `isinstance` guard or a documented precondition |
| F14 | ML failures are swallowed with `except Exception: pass` — an out-of-service model is invisible to operators | RECOMMENDATION | V03-15 | Log the fallback reason at warning level |
| F15 | 2 of the project's own 11 detection tests fail on the deployed path (part of the 26-failure baseline) | CONFIRMED BEHAVIOR | V03-64 | Align legacy expectations with the deployed branch |
| F16 | No consumer applies a confidence threshold: 25 ingestible files are identified below 0.6 and 9 at 0.0, and the executor uses the result regardless | DESIGN LIMITATION | §7, `executor.py:188-204` | Threshold → REVIEW, mirroring the spec's confidence-score guidance |
| F17 | Detection runs up to 4× per file per audit (API pre-detects on 3 slices, executor detects, benchmark engine detects again) | DESIGN LIMITATION | V03-57, V03-58 | Detect once per file and share the result |

### What works

- **Deterministic**: 10 repeated calls, 2 instances, and a full second pass over 480 files — **0 signature mismatches** (V03-47/49/50, sweep).
- **Never crashes on real content**: NUL, C0 controls, lone surrogate, non-ASCII, control-character runs, 1 MiB payloads — all return a result (V03-32…V03-36). An ML failure degrades to regex instead of propagating (V03-15).
- **Vendor agreement across branches on the ingestible corpus**: the two branches disagree on vendor for **0** of the 256 files the pipeline audits (only `platform` differs).
- **Directory-label agreement on ingestible content**: 214 of 215 labelled files (the single miss is a `hosts.cfg` with no vendor signature at all).
- Confidence is always populated and capped (0.95 regex / 0.99 ML); evidence is capped (regex path); banner floods cannot inflate past the cap.
- Scaling is roughly linear on both branches; regex scoring is not super-linear (V03-46, V03-54, V03-55).

---

## 10. Cross-engine baseline (Engines 01/02 artifacts, read-only)

| Baseline | Engine 03 observation |
|---|---|
| `01_ingestion` — 256 files would be stored (extension + duplicate rules) | those 256 are exactly the files detection receives in production; 9 return `unknown`, 25 below 0.6 confidence |
| `01_ingestion` F4 — ingestion stores content without sniffing | detection has no content-quality gate either; it will happily identify binary-ish or non-config text (V03-32…35) |
| `01_ingestion` F1 / `02_validation` F3 — unreachable dead code | symmetric defect: on the deployed path `VENDOR_PATTERNS['cisco']['platforms']['ios_xe']` is unreachable for evidence collection (F5) |
| `02_validation` — all 256 files pass the gate with no error | validation does not gate on vendor confidence; F16's unthresholded identifications proceed straight to control selection |
| non-configuration artefacts rejected by Engine 01 (`.md`, `.xml`, `.yaml`) | would have been identified at 0.90–0.95 by detection if they reached it — they do not |

No Engine 01/02 defect is fixed or changed by this validation; these rows are recorded for the later cross-engine analysis.

---

## 11. NOT APPLICABLE / NOT VERIFIABLE

| Item | Status | Reason |
|---|---|---|
| ML model accuracy / calibration / class balance | NOT APPLICABLE here | deferred by instruction until all 12 engines are validated; `metadata.json` reports `vendor_accuracy: 1.0`, `device_type_accuracy: 1.0`, `train_size: 307` — **recorded, not assessed** |
| Authoritative per-file ground truth for vendor | NOT VERIFIABLE | the corpus has directory hints only; used for disagreement counts, not scores |
| End-to-end effect of a wrong vendor on findings | NOT APPLICABLE | belongs to Engines 07/11 (control selection and audit execution) |
| Runtime behaviour behind the HTTP API | NOT VERIFIABLE | requires a live server; API truncation contract verified at source level instead |
| Palo Alto parsing of detected `paloalto` files | NOT APPLICABLE | no Palo Alto parser exists (F10); parser coverage is Engine 04's scope |

---

## 12. Verdict

**FAIL** — measured against this module's documented contract (`detection.py:1-54`, `PROJECT_MASTER_SPEC.md` §10.2/§25.2) and against the requirement that a downstream audit can trust the vendor/platform it is handed.

- **PASS** — vendor identification for in-scope content, determinism, crash-resistance across every content class, confidence caps, degradation instead of propagation, performance, and 214/215 directory-label agreement on the files the pipeline actually audits.
- **PARTIAL** — firmware capture, comment/mixed-vendor handling, platform chosen at score 0, untyped input errors, spec drift, evidence cap.
- **FAIL** — F1 (one line reassigns the vendor), F2 (out-of-scope vendors return as in-scope, 33 audit-reachable files), F3 (branch-dependent platform, 175/256 audit-reachable files), F4 (truncation-dependent results), plus F5/F6 (evidence gap, documented contract mismatch).

Blocking for readiness: **F1, F2, F3, F4** — each one changes the vendor or platform that `AuditExecutor` feeds into parser and control selection, i.e. it changes the audit result itself.

**Scope note:** no production code was modified; findings are reported only. Fixes are out of scope until the user asks for them. ML model quality remains unevaluated by instruction.
