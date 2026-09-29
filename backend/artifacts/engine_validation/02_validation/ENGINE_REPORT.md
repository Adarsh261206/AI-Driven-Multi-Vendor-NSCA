# Engine 02 — Configuration Validation Engine

**Scope:** `backend/app/engines/validation.py` only.
**Validated:** 2026-09-25 · **Overall status:** **FAIL** (against the module's own documented contract — see §12)

---

## 1. Method

| Item | Value |
|---|---|
| Production code modified | none — `git diff -- backend/app/` is empty |
| Test harness | `backend/tests/validation/test_v02_validation.py` (new) |
| Evidence rows | 86 (`raw_results.jsonl`) from 86 pytest cases — **86 passed, 0 failed** |
| Dataset sweep | 480 real files, 11,584,713 bytes (`dataset_results.csv`) |
| Database | not required — this engine is pure (no I/O) |
| Baseline regression | before Engine 02: 499 collected / 473 passed / 26 failed → after: **585 collected / 559 passed / same 26 pre-existing failures** |
| Engine 01 artifacts | used as baseline evidence (`01_ingestion/`), read-only |

```bash
backend\venv\Scripts\python.exe -m pytest tests/validation/test_v02_validation.py -q -p no:randomly
backend\venv\Scripts\python.exe scripts\engine_validation\sweep_validation.py
backend\venv\Scripts\python.exe scripts\engine_validation\report_validation.py
```

Categories: A functional · B functional (gate + caller contract) · C negative · D boundary ·
E malformed / requested content classes · F security · G reliability · H determinism ·
I error handling · J performance · K integration contract.

---

## 2. Contract under test

`ConfigurationValidator.validate(content, vendor_hint=None, check_sensitive=True, check_insecure=True) -> ValidationResult`

**Execution order (observed, `validation.py:120-149`) — every step returns early:**

| # | Check | Code | Severity | Effect on `is_valid` |
|---|---|---|---|---|
| 1 | `if not content.strip()` | `EMPTY_CONTENT` | warning | none — returns with `is_valid=True` |
| 2 | `_has_binary_content` (any NUL, or >10% non-printable) | `BINARY_CONTENT` | **error** | **sets False**, returns |
| 3 | `_has_mixed_line_endings` | `MIXED_LINE_ENDINGS` | info | none |
| 4 | `_validate_structure`: NUL per line / line >10000 chars | `NULL_BYTE` / `LONG_LINE` | error / warning | `NULL_BYTE` would set False |
| 5 | `_check_sensitive_patterns` (skips `!`/`#` lines) | `SENSITIVE_DATA` | warning | none |
| 6 | `_check_insecure_patterns` (skips `!`/`#` lines) | `INSECURE_CONFIG` | warning | none |

**Result object:** `ValidationResult(is_valid, issues, warnings, info)` with `error_count` / `warning_count` properties that count over `issues` only.

**Gate consumer:** `AuditExecutor.execute()` (`compliance/executor.py:171-179`) calls `validate(config_content)` with no flags and aborts the whole pipeline only when `is_valid` is False. Warnings, info and counts are never inspected.

**Callers:** `app/engines/compliance/executor.py:22,111,171` and the repo test suite. No other production caller.

---

## 3. The eight content classes requested for Engine 02

| Class | Observed behaviour | Evidence | Status |
|---|---|---|---|
| **NUL bytes** | rejected: `BINARY_CONTENT` error, `is_valid=False`, single issue, no line number. The separate `NULL_BYTE` error **never fires** — the binary check returns first | V02-05 ×4, V02-06, V02-12 ×3 | PARTIAL (rejection works, dedicated code dead) |
| **Binary-looking content** | rejected only above a strict >10% non-printable ratio (NUL always rejects regardless of ratio). 9% dilution passes | V02-09 ×4, V02-18, V02-24 | PARTIAL |
| **Empty content** | `EMPTY_CONTENT` **warning**, `is_valid=True` — the audit gate opens | V02-13 ×8 | PARTIAL |
| **Whitespace-only content** | same as empty (spaces, tabs, newlines, CRLF, form feed, VT, `\x1c`) | V02-13 ×8 | PARTIAL |
| **Comments-only content** | accepted with **zero issues** — `!`, `#`, `//`, `/* */` and mixed comment files all validate clean | V02-14 ×5 | PARTIAL |
| **Malformed configurations** | accepted as valid; no syntax/grammar rule exists although the docstring claims "- Syntax patterns" | V02-15 (`malformed.txt`), V02-34 | **FAIL** |
| **Mixed-vendor configurations** | accepted; no mixed-vendor code exists; `vendor_hint` is accepted and never read | V02-16, V02-23 | **FAIL** |
| **Unsupported / unknown configurations** | accepted; no command vocabulary, so "unknown" is indistinguishable from "valid" | V02-17 (`unknown_commands.txt`, `juniper_unknown.txt`) | **FAIL** |

---

## 4. Results by category

| Cat | Requirement | Rows | Status |
|---|---|---|---|
| A | result object shape, minimal valid config | 2 | PASS |
| B | severity gate semantics, default flags, caller does not disable them | 2 | PASS |
| C | NUL rejected; declared error codes reachable; typed input contract | 5 | PASS ×4, **FAIL ×1** (V02-07) |
| D | ratio boundary, LONG_LINE boundary, line numbers, NUL position | 10 | PASS ×10 |
| E | the eight requested content classes | 17 | PASS ×1, PARTIAL ×13, **FAIL ×3** |
| F | sensitive/insecure detection, comment styles, vendor_hint, evasion, ReDoS, flags, result buckets | 29 | PASS ×14, **FAIL ×15** |
| G | repeated validation stable | 1 | PASS |
| H | 3-instance determinism | 1 | PASS |
| I | no exception on str input; NULL_BYTE reachability; type guard | 14 | PASS ×12, PARTIAL ×1, **FAIL ×1** |
| J | scaling across 1 KiB / 100 KiB / 1 MiB | 1 | PASS |
| K | executor gate, cross-engine baseline, docstring vs implementation, ML scope | 4 | PASS ×1, PARTIAL ×1, **FAIL ×1**, N/A ×1 |

**Totals:** PASS 49 · PARTIAL 15 · FAIL 21 · NOT APPLICABLE 1.
**Classifications:** CONFIRMED BEHAVIOR 50 · DESIGN LIMITATION 17 · MISSING 13 · BUG 4 · RECOMMENDATION 1 · NOT APPLICABLE 1.

---

## 5. Industry / documented expectations

Sources are cited verbatim; no standard is claimed that was not looked up. "Project-defined" means the expectation comes from this repo's own documentation.

| ID | Expectation | Source | Result |
|---|---|---|---|
| E-1 | NUL characters must not reach downstream components where they can "bypass validation routines and other protection mechanisms" | MITRE **CWE-158**, *Improper Neutralization of Null Byte or NUL Character* — cwe.mitre.org/data/definitions/158.html | **MET** — any NUL ⇒ `BINARY_CONTENT` ⇒ gate closes (V02-05/12). Caveat: the purpose-built `NULL_BYTE` error with a line number is dead code (V02-06) |
| E-2 | validate file content independently of attacker-controlled metadata (content-type/signature) | OWASP Cheat Sheet Series, **File Upload Cheat Sheet** — "Content-Type Validation" and "File Signature Validation" | **MET by design** — `validate()` receives only content; it never reads a MIME type or filename |
| E-3 | validate input "as early as possible in the processing of the user's (attacker's) request" | OWASP Cheat Sheet Series, **Input Validation Cheat Sheet**, opening guidance | **MET inside the audit pipeline** (validation is step 1 of `AuditExecutor`); **NOT met on the ingest path** — Engine 01's `ingest()` never calls this engine (baseline: `01_ingestion` findings F4/F9). Recorded for the cross-engine analysis, not treated as an Engine 02 defect |
| E-4 | fail closed on input the component cannot process | **Project-defined** (this repo's executor treats `is_valid` as a hard gate) | **NOT MET** for empty, whitespace-only and comment-only content — all return `is_valid=True` (V02-13, V02-14) |
| E-5 | "Validates: … Syntax patterns" | **Project-defined** — `validation.py:79-83` class docstring | **NOT MET** — no syntax rule exists; `malformed.txt` validates clean (V02-15, V02-34) |
| E-6 | "Potential security concerns" / "Encoding issues" are detected | **Project-defined** — `validation.py:80-82` | **PARTIAL** — implemented (V02-18, V02-29…) but Cisco-only vocabulary, false positives on negation and on the word `key`, and detection gaps for space-separated passwords (§9) |

---

## 6. Hypotheses

| ID | Statement | Conclusion | Evidence |
|---|---|---|---|
| H02-01 | `NULL_BYTE` is unreachable because the binary check short-circuits first | **CONFIRMED** | V02-06 (FAIL, MISSING) |
| H02-02 | `is_valid` can only ever become False because of `BINARY_CONTENT` | **CONFIRMED** | V02-07 (FAIL) — only 2 `add_error` sites, 1 reachable |
| H02-03 | empty / whitespace-only content does not fail validation | **CONFIRMED** | V02-13 ×8 (PARTIAL) |
| H02-04 | comment-only content validates with zero issues | **CONFIRMED** | V02-14 ×5 (PARTIAL) |
| H02-05 | syntax validation is claimed but not implemented | **CONFIRMED** | V02-15, V02-34 (FAIL) |
| H02-06 | `vendor_hint` is inert; no mixed-vendor recognition | **CONFIRMED** | V02-16, V02-23 (FAIL) — `vendor_hint` occurs 2× in the file, both outside the body |
| H02-07 | unknown / unsupported content is never recognised | **CONFIRMED** | V02-17 (FAIL) |
| H02-08 | credential detection misses space-separated and non-Cisco forms | **CONFIRMED** | V02-19 ×4 FAIL (space password, encrypted-password, JUNOS root-auth, FortiOS `set password`) |
| H02-09 | insecure detection false-positives on negated commands | **CONFIRMED** | V02-20 ×2 FAIL (`no ip http server`, `no transport input telnet`), plus V02-20 ×2 vendor false negatives |
| H02-10 | comment suppression covers only `!` and `#` | **CONFIRMED** | V02-22 ×3 FAIL (`//`, `/* */`, trailing) |
| H02-11 | binary detection is a dilutable strict >10% ratio | **CONFIRMED** | V02-09 ×4 (boundary PASS), V02-24 (FAIL — 9% passes) |
| H02-12 | `ValidationResult.warnings` / `.info` are never populated | **CONFIRMED** | V02-27 (FAIL, BUG) |
| H02-13 | non-str input raises an untyped exception | **CONFIRMED** | V02-08 (PARTIAL) — `AttributeError` / `TypeError` |
| H02-14 | warnings and info issues can stop the audit pipeline | **REJECTED** | V02-32 (PASS) — only `is_valid` is consumed |
| H02-15 | a routine key-generation command is reported as a credential | **CONFIRMED** | V02-21 (FAIL, BUG) |

---

## 7. Dataset sweep (480 real files)

| Measure | Value |
|---|---|
| Files / bytes | 480 / 11,584,713 |
| **`is_valid=True`** | **480 (100%)** |
| **`is_valid=False`** | **0** |
| Files with ≥1 warning | 257 |
| Files with ≥1 error | **0** |
| Files with zero issues | 223 |
| `SENSITIVE_DATA` | **9,543 hits across 209 files** |
| `INSECURE_CONFIG` | 134 hits across 131 files |
| `MIXED_LINE_ENDINGS` | 5 files |
| `LONG_LINE` | 2 files |
| `NULL_BYTE` / `BINARY_CONTENT` / `EMPTY_CONTENT` | 0 / 0 / 0 |
| UTF-8 decode failures | 0 |
| Determinism (2nd pass) | 0 mismatches |

Issue density by extension: `.conf` 8,657 `SENSITIVE_DATA` hits (98.8% of all hits), `.cfg` 702, `.txt` 89, `.xml` 51.

### Cross-engine baseline (Engine 01 artifacts joined on `relpath`)

| Measure | Value |
|---|---|
| Files ingestible by Engine 01 (valid ext, not a duplicate) | 256 |
| …of which Engine 02 reports `is_valid=False` | **0** |
| …of which Engine 02 reports ≥1 warning/info | 183 (71.5%) |
| Files rejected by Engine 01 on extension | 143 |

So on this corpus **the gate never closes**, and 71.5% of the files that reach it leave with warnings.

### Sampled false positives (real corpus, line-verified)

| File | Line | Reported as | Reality |
|---|---|---|---|
| `Juniper\Routers\MX-Series\chic.conf` | 2777, 2783, 2799, 2803 … (**688 hits total**) | `SENSITIVE_DATA` "Potential SNMP community string" | `community 11537:950;` — a BGP/route-policy community value in JUNOS, not an SNMP community |
| `Cisco\MultiAS-Lab\lhr-border\lhr-border-02.cfg` | 233 | `INSECURE_CONFIG` "HTTP server enabled (insecure)" | `no ip http server` — the service is disabled |
| `tests/sample_configs/malformed.txt` | whole file | *(nothing)* | `security passwords min-length` / `ip ssh version` with no value — syntax errors are invisible |

---

## 8. Performance (measurements only — not a readiness score)

Synthetic inputs, `time.perf_counter`, 30 samples per size:

| Input | p50 | p95 | p99 |
|---|---|---|---|
| 1 KiB | 0.235 ms | 0.3264 ms | 0.3526 ms |
| 100 KiB | 27.4461 ms | 30.7824 ms | 31.0688 ms |
| 1 MiB | 294.1773 ms | 318.4208 ms | 320.3508 ms |

Real corpus (480 files): p50 0.5477 ms · p95 24.7329 ms · p99 90.3617 ms · mean 5.7011 ms.

Scaling check: 1024× input costs ~1250× time — approximately linear, no super-linear blow-up (V02-31 PASS).
Adversarial regex payloads (100k–200k chars) completed in 23–28 ms (V02-25 PASS) — no catastrophic backtracking in the current patterns.

---

## 9. Findings

| # | Finding | Class | Evidence | Recommendation |
|---|---|---|---|---|
| F1 | The module docstring claims "Syntax patterns"; no syntax/grammar rule exists, so `malformed.txt` and any unparseable file validate clean | MISSING | V02-15, V02-34 | Implement structural checks or remove the claim |
| F2 | The gate can only ever close for `BINARY_CONTENT` — `is_valid=False` is unreachable for any other reason | MISSING | V02-07, V02-06 | Decide what else must fail closed (empty, unparseable) and add those errors |
| F3 | `NULL_BYTE` error is dead code: the binary check returns before `_validate_structure`, so no line number is ever reported for a NUL | MISSING | V02-06 | Drop the early return or drop the dead branch — reported errors should be accurate |
| F4 | Empty and whitespace-only content is a **warning**; `is_valid=True` opens the gate to detection, parsing and scoring | DESIGN LIMITATION | V02-13 ×8, V02-32 | Define an explicit empty-content policy |
| F5 | Comment-only content validates with **zero issues** — a file with no substantive line is "valid" | DESIGN LIMITATION | V02-14 ×5 | Count substantive lines after comment stripping |
| F6 | No mixed-vendor or unknown/unsupported content recognition; `vendor_hint` is accepted and never read (2 occurrences in the file, both outside the body) | MISSING | V02-16, V02-17, V02-23 | Implement `vendor_hint` or delete it; add a vendor-conflict check if in scope |
| F7 | Credential detection misses `password <value>` (space-separated), `encrypted-password`, JUNOS `root-auth`, FortiOS `set password` — the rule requires `=` or `:` | MISSING | V02-19 ×4 | Add the space-separated CLI forms and vendor variants |
| F8 | Insecure-setting detection false-positives on IOS negation: `no ip http server` / `no transport input telnet` reported as enabled. Confirmed on a real corpus file | **BUG** | V02-20 ×2, §7 | Anchor patterns and exclude the negation keyword |
| F9 | `SENSITIVE_DATA` matches the bare word `key`: `crypto key generate general-keys modulus 2048` is reported as a credential | **BUG** | V02-21 | Require key material (base64/hex blob) or a `key chain` context |
| F10 | `SENSITIVE_DATA` matches the bare word `community`: 688 hits in one JUNOS file on route-policy `community` values | **BUG** (corpus evidence) | §7 | Scope the rule to `snmp-server community` / `set snmp community` |
| F11 | Comment suppression only understands `!` and `#`; `//`, `/* */` and trailing comments still raise credential warnings | DESIGN LIMITATION | V02-22 ×3 | Support the comment syntax of every claimed vendor, or document the limitation |
| F12 | Binary detection is a single global >10% ratio: 9% control characters pass through untouched; a NUL always rejects | DESIGN LIMITATION | V02-09, V02-24 | Reject C0 controls other than `\t\r\n` outright |
| F13 | `ValidationResult.warnings` and `.info` are declared but never written — `add_warning`/`add_info` append only to `issues`. Any future caller reading `.warnings` gets `[]` | **BUG** (latent) | V02-27 | Populate the buckets or delete the fields |
| F14 | Non-str input raises untyped `AttributeError`/`TypeError` from inside the method | RECOMMENDATION | V02-08 | `isinstance(content, str)` guard, or document the precondition |
| F15 | Only `is_valid` is consumed by the pipeline; warnings never stop an audit (by design today) | CONFIRMED BEHAVIOR | V02-32 | Acceptable — but it makes F4/F5 consequential |

### What works

- Deterministic: 100 repeated runs and 3 independent instances produce identical issue lists (V02-28, V02-29); 480-file sweep reproduces exactly (0 mismatches).
- Never raises for `str` input across 12 adversarial shapes including a 1 MiB payload, lone surrogate and control-character runs (V02-30 ×12).
- Boundaries behave as written: strict `>10%` ratio, `>10000` char line, accurate 1-based line numbers (V02-09, V02-10, V02-11).
- NUL content is always rejected (CWE-158 expectation met) regardless of position (V02-05, V02-12).
- No catastrophic backtracking; approximately linear scaling (V02-25, V02-31).
- Detection flags `check_sensitive`/`check_insecure` behave as documented and the audit path leaves both on (V02-04, V02-26).

---

## 10. Cross-engine baseline (Engine 01 artifacts, read-only)

| Engine 01 record | Engine 02 observation |
|---|---|
| `01_ingestion` V01-34 / F4 — ingestion stores arbitrary binary (latin-1) with no sniffing | Engine 02 **would** reject that payload (`bytes(range(1,256))` ⇒ `BINARY_CONTENT`, V02-33) — but only if the content reaches an audit. The ingest path never calls this engine |
| `01_ingestion` V01-24 / F1 — `FileDecodeError` unreachable dead code | Symmetric finding here: `NULL_BYTE` unreachable dead code (F3). Both engines ship an error type/branch they can never raise |
| `01_ingestion` dataset: 256 files ingestible | All 256 are `is_valid=True`; 183 carry warnings (§7) |

No Engine 01 defect is fixed or changed by this validation; the rows above are recorded for the later cross-engine analysis.

---

## 11. NOT APPLICABLE / NOT VERIFIABLE

| Item | Status | Reason |
|---|---|---|
| ML / model-quality evaluation (V02-35) | NOT APPLICABLE | deferred by instruction until all 12 engines are validated; no model logic in `validation.py` |
| Vendor-specific grammars | NOT VERIFIABLE | no vendor grammar exists to compare against (F6) |
| Compression / archive content | NOT APPLICABLE | input is `str`; archives are Engine 01's concern |
| End-to-end audit behaviour on empty content | NOT VERIFIABLE here | would execute `AuditExecutor`, which belongs to Engine 11's scope; recorded as a contract observation (V02-13 + V02-32) |

---

## 12. Verdict

**FAIL** — measured against this module's own documented contract (`validation.py:74-83`) and its role as the pipeline's hard gate.

- **PASS** — determinism, exception-free operation, boundary arithmetic, line-number accuracy, NUL rejection (CWE-158), regex safety, performance, flag handling.
- **PARTIAL** — binary detection (dilutable ratio), empty/comment-only policy (fail-open), cross-engine agreement (V02-33).
- **FAIL** — the engine cannot reject malformed, mixed-vendor or unknown content (F1, F6); `is_valid` can only ever be False for one reason (F2); a declared error path is dead (F3); and the detection layer produces both material false positives (F8, F9, F10 — verified on the real corpus) and material false negatives (F7, F11).

Blocking for readiness: **F1** (documented capability absent), **F2/F3** (gate and error contract), **F8/F9/F10** (detection accuracy on real files).

**Scope note:** no production code was modified; findings are reported only. Fixes are out of scope until the user asks for them.
