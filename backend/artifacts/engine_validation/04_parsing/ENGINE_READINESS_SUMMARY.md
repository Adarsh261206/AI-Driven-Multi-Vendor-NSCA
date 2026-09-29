# ENGINE_READINESS_SUMMARY — Engine 04 — Vendor Configuration Parsing Engines

**Scope:** `backend/app/engines/parsing/{cisco,juniper,fortinet}.py` (callers: `compliance/executor.py:116-128/203-231`, `api/v1/audit_execution.py:308-331`, `ai/semantic.py:112-139`, `ai/adaptive.py:240-243`)
**Evidence:** 94 pytest rows (94 passed, 0 failed) — 480-file corpus — 0 production files modified
**Overall verdict:** **FAIL** (structure, diagnostics and negative-input handling — not parser coverage)
**Date:** 2026-09-25

---

## Scoreboard

| Status | Count | % |
|---|---|---|
| PASS | 55 | 58.5% |
| PARTIAL | 0 | 0% |
| FAIL | 39 | 41.5% |
| **Total** | **94** | 100% |

| Classification | Count |
|---|---|
| CONFIRMED BEHAVIOR | 71 |
| BUG | 13 |
| DESIGN LIMITATION | 8 |
| MISSING | 2 |

| Category | Rows | Status |
|---|---|---|
| A functional (Cisco + section structure) | 14 | PASS 9, FAIL 5 |
| B functional (Junos) | 11 | PASS 10, FAIL 1 |
| C functional (FortiOS) | 10 | PASS 10 |
| D parser selection / pipeline | 9 | PASS 4, FAIL 5 |
| E semantic fidelity (negation, banner, keys, formats) | 10 | PASS 2, FAIL 8 |
| F diagnostics vs spec 10.3 | 7 | PASS 1, FAIL 6 |
| G SEPARATE RECORD — wrong-vendor input | 8 | PASS 2, FAIL 6 |
| H hostile / boundary input | 9 | PASS 4, FAIL 5 |
| I determinism / evidence fidelity | 5 | PASS 5 |
| J performance (measurement only) | 3 | PASS 3 |
| K cross-parser contract consistency | 8 | PASS 5, FAIL 3 |

---

## Hypotheses (19 CONFIRMED · 3 REJECTED · 0 unverifiable)

CONFIRMED: H04-01 IOS sections nest under the previous section · H04-02 Cisco parser can never report an error/warning/unknown · H04-03 Junos never flags unknown sections · H04-04 `no ...` negation lost · H04-05 foreign syntax accepted with 0 errors · H04-06 unsupported vendor routed to the Cisco parser · H04-07 banner body parsed as commands · H04-08 JSON accepted as IOS · H04-09 parse tree not an input to evaluation/normalization · H04-10 errors/warnings discarded at persistence · H04-11 re-analysis hard-codes the Cisco parser · H04-12 deep nesting exhausts the stack · H04-13 Juniper style is one global switch · H04-14 the three parsers disagree on path/value/API · H04-15 `ParseResult` misses contract fields · H04-16 non-`str` input raises untyped errors · H04-17 ACL seq numbers / set-style values become keys · H04-18 `platform` argument never read · H04-19 Juniper warning is a `ParseError`.

REJECTED: H04-20 parsers lose or invent lines for their own vendor (0 unrepresented lines / 323 files) · H04-21 repeated/interleaved parses differ (0 mismatches) · H04-22 hostile content crashes a parser (NUL, C0, surrogate, 1–2 MB).

---

## Blocking findings (must be fixed before this engine is ready)

1. **F1** — IOS sections attach to the previous section instead of starting a sibling: **1,216 of 2,997 section nodes in 132/178 ingestible Cisco files** are nested. `get_section_value('router')` then returns `None`, and `audit_execution.py:309-313` persists **roots only**, so whole sections never reach the stored `ParsedConfiguration`.
2. **F2** — no diagnostics in the chain: Cisco `parse_errors`/`parse_warnings`/`unknown_sections` are initialised and never written (junk, binary, truncated, unrecognised input → 0 errors), Junos never assigns `unknown_sections` and its one warning is a `ParseError`, and `audit_execution.py:325-326` hard-codes `parse_errors=[], parse_warnings=[]` — so even FortiOS's real diagnostics are dropped. Spec 10.3 responsibilities 2–4 unmet end to end.
3. **F3** — wrong-vendor and unsupported-vendor content parses silently: **32/32 (Cisco) and 195/195 (Junos)** foreign ingestible files → 0 errors; **all 46 ingestible unsupported-vendor files are forced through `CiscoIOSParser`** (`executor.py:126-128`); `ai/adaptive.py:240-243` hard-codes the Cisco parser. Direct consequence of E03 F2 — measured here as tree-level impact.
4. **F4** — negation lost: `no ip http server` ≡ `ip http server`, `no shutdown` ≡ `shutdown`, `ConfigNode` has no negation field — **1,220 negation lines in 153/178 ingestible Cisco files**, against spec `:111`.

Secondary: **F5** banner bodies as commands (17 files) · **F6** 3 JSON corpus files ingested as Cisco with 0 errors (CWE-754) · **F7** `RecursionError` at depth 1,500 in `to_dict()`/`find_all()` (CWE-674) · **F8** non-`str` input → `AttributeError`/`TypeError` · **F9** `platform` never read · **F10** adaptive re-analysis hard-codes Cisco · **F11** parse tree not consumed by evaluation/normalization · **F12** `ParseResult` lacks `vendor/platform/id` · **F13** path/`find_all`/section-lookup semantics differ across parsers · **F14** ACL seq numbers & set-style values become keys · **F15** whole-file Juniper style switch · **F16** 8 of the 26 pre-existing failures are this engine's own legacy tests.

---

## What is solid

Own-vendor completeness (**0 unrepresented lines across 323 label-matched files**; `line_number`/`raw_text` always point at the real line) · **FortiOS 10/10** (only parser that reports anything) · Junos functional layer 10/11 (hierarchical + set-style paths, `##` decoding, `}`→error, `{`→warning) · determinism **0 mismatches** (10 repeats, 2 instances, interleaved, full second sweep) · robust to NUL / C0 / lone surrogate / non-ASCII / whitespace / 1–2 MB · p50 < 5 ms on real files, 2 MB < 700 ms · identical `ParseResult`/`ConfigNode` shape across all three parsers · offline pipeline completes with a populated `parse_result`.

---

## Corpus measurements (480 files · 11,282,991 B)

| Measure | Value |
|---|---|
| labels | cisco 252 · juniper 41 · fortinet 30 · arista 38 · a10 3 · f5 11 · frr 63 · napalm 4 · paloalto 38 |
| label-matched parse | 323 files → 199,055 nodes, **0 lines lost**, `to_dict()` exceptions 0 |
| diagnostics on own vendor | Cisco 0 err / 0 warn / 0 unk (252 files) · Junos 0/0/0 (41) · FortiOS 1 err / 5 warn / 2,685 unk (30) |
| **nested IOS sections** | **1,216 / 2,997 nodes, 132/178 ingestible files** (acl 502, nested 464, router 190, interface 56, line 2, crypto 2) |
| negation lines | **1,220 in 153/178** ingestible Cisco files (1,376 in 252) — none distinguishable in the tree |
| banner config | 17 labelled / 14 ingestible Cisco files — body parsed as commands |
| JSON labelled "Cisco" | `csr1000v`, `iosxr`, `nxos` running-config — 250/77/317 nodes, **0 errors**, ingestible |
| wrong-vendor (separate record) | Cisco on 32 foreign → 32 silent · Junos on 195 → 195 silent · FortiOS on 193 → 5 silent, 136 empty, 52 flagged |
| vendor chain | match 315 · mismatch 8 · detected-unsupported/unknown 9; label-supported ingestible 210/210 correct; **46 unsupported ingestible → Cisco parser** |
| Juniper style | set-style 3 / brace 12 (ingestible), 11 / 28 (all); mixed content mis-detected |
| max parse depth | 18 (crash point 1,500) |
| determinism | **0 non-deterministic files** across all three parsers |

Directory labels are hints, not ground truth — no accuracy score is claimed; Engine 03 output was **not** used as parser ground truth (methodology rule), wrong-vendor behaviour is reported only in category G.

## Performance (measurement only)

Corpus label-matched: Cisco p50 0.446 / p95 1.233 / max 6.128 ms · Junos p50 4.757 / p95 64.601 / max 107.095 ms · FortiOS p50 0.196 / p95 1.552 / max 14.698 ms.
Synthetic: Cisco 2.02 MB 618 ms (90,000 nodes) · Junos 1.99 MB 162 ms · FortiOS 354 KB 42 ms. End-to-end `AuditExecutor.execute` ≈ 2.2 s / 6 steps.

---

## Regression / integrity

- Full suite before E04: 651 collected / 625 passed / 26 failed → after: **745 / 719 / same 26 pre-existing failures** (94 new tests); failure set verified byte-identical to the captured baseline.
- The 26 include **8 of this engine's own legacy tests** (`tests/test_juniper_benchmark.py` ×7, `tests/test_vertical_slice.py::test_cisco_ios_full_pipeline` ×1), 2 of E03's `test_detection.py`, 16 in benchmark/phase territory. Pre-existing, unchanged by this work.
- `git diff -- backend/app/` **empty**; `git status --porcelain -- backend/app/` **empty**.
- New files only: `tests/validation/test_v04_parsing.py`, `scripts/engine_validation/{sweep,report}_parsing.py`, `artifacts/engine_validation/04_parsing/*`, plus the conftest engine mapping for `04_parsing`.

## NOT APPLICABLE / NOT VERIFIABLE

Palo Alto / NX-OS / IOS-XR parsers (do not exist — recorded in F3/F6) · ML quality (deferred) · authoritative per-file vendor ground truth · live HTTP behaviour of the persisted parse result (source-level only) · HTML/PDF escaping of `raw_text` (Engine 12) · effect on individual control outcomes (Engines 07/11).

## Limitations of this validation

Directory labels are hints only · the mis-nesting count uses the parser's own section-key set (a broader set would only raise it) · security probes hit parser entry points directly, no fuzzing campaign · performance numbers are single-machine measurements, not a readiness score.

---

**Readiness:** NOT READY — 4 blocking findings (F1, F2, F3, F4).
**Next:** Engine 05 — Universal Model / Normalization (pending user approval).
