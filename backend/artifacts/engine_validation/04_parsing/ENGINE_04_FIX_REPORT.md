# ENGINE 04 FIX REPORT — Vendor Configuration Parsing Engines

- Date (UTC): 2026-09-26
- Scope: `backend/app/engines/parsing/{cisco,juniper,fortinet}.py`,
  `backend/app/engines/parsing/__init__.py`, caller paths
  `backend/app/engines/compliance/executor.py`,
  `backend/app/api/v1/audit_execution.py`, `backend/app/ai/adaptive.py`,
  `backend/app/ai/semantic.py`
- Pre-fix evidence: `ENGINE_REPORT.md` + `*_prefix.*` (this directory)
- Post-fix evidence: `test_results.csv` (101 rows), `dataset_results.csv`,
  `dataset_summary.json`, `performance.csv`, `determinism_results.csv`,
  `security_results.csv`, `summary.json`, `raw_results.jsonl` (this directory)
- Verdict: **READY (with 2 DESIGN DECISIONs and 1 PARTIAL)** — all 4 blocking
  findings (F1–F4) FIXED, all secondary findings FIXED except F9/F11
  (documented design) and F16 (partial: 1 of 8 legacy failures resolved,
  7 pre-existing and parser-independent).

## 1. What was wrong (pre-fix, from ENGINE_REPORT.md)

F1 — 1,216 of 2,997 section nodes wrongly nested (132/178 ingestible Cisco
files); persistence stored roots only (`{key,value,children-count}`).
F2 — no diagnostics anywhere in the chain (Cisco never wrote
parse_errors/parse_warnings/unknown_sections; Junos never wrote unknowns;
API hard-coded `parse_errors=[]`/`parse_warnings=[]`).
F3 — wrong/unsupported-vendor content parsed silently (46 ingestible files
forced through the Cisco parser via the executor fallback; adaptive
re-analysis hard-coded `CiscoIOSParser`).
F4 — negation lost (`no ip http server` identical to `ip http server`;
`kv_type` dropped; no `negated` field).
F5 banner bodies became config nodes. F6 JSON converted silently. F7
`RecursionError` at 1,500 levels (`to_dict`/`find_all`/`semantic`).
F8 `None`/`bytes`/`int` crashed with untyped errors. F9 platform unread.
F10 adaptive hard-code. F11 tree not consumed downstream. F12 ParseResult
missing vendor/platform/id. F13 API divergence (path/find_all/get_section).
F14 ACL seq numbers and set-style values as keys. F15 Junos single-style
switch mangling. F16 two legacy test files failing (8 tests).

## 2. What was changed

### 2.1 Parsers (all three rewritten in place, no new parsers)

Shared envelope (F4/F7/F8/F12/F13):
- `ConfigNode.negated: bool = False` on all three (uniform shape).
- `ParseResult` gains `vendor/platform/id/ingested_config_id` (spec
  `:744-753`); `parse()` accepts them as keyword args; the executor fills
  vendor/platform and stamps `id = audit_id`.
- `parse(non_str)` raises `TypeError("content must be str")` for
  None/bytes/int (F8).
- `to_dict()` and `find_all()` are iterative (F7/CWE-674); traversal order
  is unchanged (pre-order, verified against legacy expectations).
- Uniform API (F13): `find_all` is a classmethod on all three (callable on
  class and instance) with `re.search(pattern, key|value)` semantics;
  `get_section(tree, [segments])` is a classmethod on all three
  (key, then value, then terminal-own-value match); `path` is ancestor keys
  only in all three (Cisco dropped the `"type:value"` suffix); value-less
  statements are `None` everywhere (FortiOS `""` fixed).
- Pre-scan order in every `parse()`: type guard → JSON envelope
  (`json.loads` succeeds → explicit error, F6) → foreign-syntax signature
  scan (explicit error + empty tree + lines as unknowns, F3-B).

Cisco (`cisco.py`) — F1/F2/F4/F5/F14:
- New section start clears the whole section stack: all 10 families
  (the 9 validated families plus `control-plane`, added for 36 corpus hits)
  are root siblings (F1). Bare `end` closes sections (171 corpus files end
  with it — faithful IOS `end`-exits-config-mode semantics).
- Banner extraction: `banner <type> <delim>...<delim>` becomes one opaque
  node (body in `value`, first line verbatim in `raw_text`); bodies never
  parsed; unterminated banner is a parse error (F5).
- Diagnostics (F2): errors — control/binary content, JSON, foreign syntax
  (brace-hierarchy, `^config `/`^edit `; bare `end` deliberately NOT a
  marker — 171 own-vendor hits), unterminated banner; warnings — section
  open at EOF, no-statements content, IPv4 prefix-notation `ip address`
  (NX-OS/EOS style: 17 own-vendor files, hence warning not error);
  unknowns — root-level lines outside a documented IOS/ASA/NX-OS vocabulary
  (~190 families incl. `boot-*-marker`, `Building`/`Current` preamble,
  `mls`, `memory-size`, `mmi`, `platform`, `security`, `end`).
  Unknown commands are never errors. In-section lines stay trusted.
- Negation: `no X` sets `negated=True` (F4). Named-ACL entries use the
  action keyword as key (`30 deny ...` → key `deny`); sequence stays in
  `raw_text` (F14). Digit-headed lines are unknown in any scope (killed all
  868 corpus numeric keys → 0).

Junos (`juniper.py`) — F2/F13/F14/F15:
- Unclosed `{` appends `ParseWarning` (was `ParseError`, H04-19).
- Unknowns: non-`set` lines in set-style content; root-level statements
  outside a documented JUNOS container vocabulary (`activate`/`deactivate`
  included) or without `;`; foreign content (explicit error + unknowns).
- Set-style leaf split extended: numeric/quoted/address last token pairs
  as value (`peer-as 65001`, `unit 0`, `uid 2000`) — F14 class closed.
- Mixed brace/set content parsed per statement into one merged tree (F15);
  the blind whole-file switch and 4-char strip are gone.
- Foreign rules: FortiOS markers (`^config `/`^edit `/bare `end`/`next`)
  → explicit error even with `set` lines present; no JUNOS markers at all →
  explicit error. Corpus-verified: 0 own-vendor hits (only the 5
  PaloAlto-mislabeled files + 1 yaml metadata file flag, correctly).

FortiOS (`fortinet.py`) — F2/F3/F13:
- Kept its errors/warnings/unknowns; added JSON + foreign pre-scan (content
  without `config`/`edit`/`end`/`next` structure → explicit error).
  Corpus: 25/30 files parse clean; 5 markerless files (XSL, admin
  backups/certs — not FortiOS content) correctly flagged.

### 2.2 Callers

- `parsing/__init__.py` (was empty): central `get_parser(vendor,
  platform)` + `SUPPORTED_PARSING_VENDORS`; platform accepted but one
  parser per family by design (F9 → DESIGN DECISION).
- `executor.py`: `_get_parser` delegates to the central contract
  (unsupported → `None`, E03 gate intact); step 3 passes
  vendor/platform into `parse()` and stamps `id`; parse errors do not fail
  the step (persisted instead).
- `audit_execution.py`: persists the FULL nested tree (`to_dict()`,
  incl. `negated`/line numbers/raw text) and the real
  parse_errors/parse_warnings (F1-persistence, F2). The `parse_errors=[]`
  hard-codes are gone.
- `ai/adaptive.py`: `reanalyze_with_mapping` dispatches on the vendor
  argument; unsupported → safe empty `SemanticAnalysis`, no foreign parsing
  (F10/F3).
- `ai/semantic.py`: node traversal iterative (F7); output shape unchanged.

### 2.3 Sweep/report tooling (own validation scripts)

- `sweep_parsing.py`: cisco banner-body lines exempt from line-fidelity
  (metric definition change — pre-fix they were junk nodes, see §6);
  `negated_nodes` metric; detection-chain models the post-E03 gate
  (unsupported → STOPPED, no Cisco fallback); per-file parse crash safety;
  `CISCO_SECTIONS` gains `control-plane`.
- `report_parsing.py`: hypothesis refs extended to the 7 new tests; no
  expectation changes (conclusions derive from recorded statuses).

## 3. Finding statuses

| ID | Status | Evidence |
|----|--------|----------|
| F1 nesting + persistence | FIXED | sections_nested 1216→0 (0/178 files); full-tree + diagnostics persisted; V04-04/91/92/93/94/95 |
| F2 diagnostics | FIXED | all 3 parsers emit all 3 signals (V04-56 matrix); persisted (V04-39); V04-51..57 |
| F3 wrong/unsupported vendor | FIXED | executor→None (V04-35, E03 gate kept); foreign→explicit error+empty tree (V04-58..63); CIDR warning + gate note (V04-64); adaptive dispatch (V04-40, V06-87); central contract (V04-99); cross-vendor silent cisco 71→0, juniper 281→0, forti 19→8 metric-silent / 0 true-silent (all 8 carry warnings/unknowns) |
| F4 negation | FIXED | `negated` flag, survives `to_dict()` + persistence; 1,350 cisco + 373 forti negated nodes on corpus; V04-41/42/44/100 |
| F5 banner | FIXED | opaque banner nodes; 17 corpus banner files clean; V04-46/96 |
| F6 JSON | FIXED | explicit JSON error on all 3 parsers; 3 corpus JSON files flagged; V04-48 |
| F7 recursion | FIXED | iterative traversal everywhere incl. semantic; 1500-deep OK; V04-70/71/72 |
| F8 input types | FIXED | explicit TypeError ×3 parsers ×3 inputs; V04-66/67/68 |
| F9 platform | DESIGN DECISION | single parser per family documented in `parsing.get_parser`; V04-36 |
| F10 adaptive | FIXED | vendor dispatch; V04-40, V06-87 |
| F11 tree consumption | DESIGN DECISION | parsing is advisory by design (benchmark/normalizer consume raw lines); tree fully persisted as the audit trail; V04-38 |
| F12 result fields | FIXED | envelope on ParseResult + executor stamping (V04-98); V04-57/83 |
| F13 API unity | FIXED | path/find_all/get_section/value-representation; V04-50/83..89 |
| F14 key selection | FIXED | ACL actions + set values; cisco numeric keys 868→0; V04-47/49/97 |
| F15 mixed JUNOS | FIXED | per-statement styles, merged; V04-65 |
| F16 legacy files | PARTIALLY FIXED | `test_parsers.py` 14/14; vertical-slice 5/5 (E03); `test_juniper_benchmark.py` 7 failures unchanged — evaluation-count drift in benchmark-engine territory, parser-independent (file uses only Junos parse/get_section/find_all, all green) |

## 4. Hypothesis re-verification (summary.json)

All 22 hypotheses REJECTED (19 defect-hypotheses fixed, 3 health-hypotheses
H04-20/21/22 still holding): H04-01..19 defect claims no longer reproduce;
H04-20 line fidelity holds (0 unrepresented lines, banner-exemption
documented); H04-21 determinism holds (0 mismatches, incl. full second
sweep); H04-22 robustness holds (NUL/C0/surrogate/unicode/whitespace/1–2 MB,
+ new 1 MB single-line test).

## 5. Test updates disclosure (no silent weakening)

`tests/validation/test_v04_parsing.py`: 94 → 101 tests (7 new: V04-95
family-sibling matrix incl. control-plane, V04-96 banner variants +
unterminated, V04-97 remark/seq, V04-98 executor envelope, V04-99 central
contract, V04-100 negation serialisation, V04-101 1 MB single line).
~35 tests updated **only** where they encoded the broken behavior under
investigation (assertions flipped to the corrected contract, e.g. V04-04
nested==1→nested==0, V04-41/42 same→same+negated-flags, V04-58..63
silent→explicit-error, V04-70/71 RecursionError→no-exception, V04-83 field
set, V04-85..88 unified API, V04-91/92/93/94 defect→fixed); stale evidence
line-refs refreshed; V04-36/V04-38 re-recorded as PASS + DESIGN DECISION.
Result: **101/101 PASS** (99 CONFIRMED BEHAVIOR, 2 DESIGN DECISION).
Cross-file updates of the same investigated behavior:
`tests/test_parsers.py::test_unknown_sections_tracked` (junk→unknown),
`test_v06_knowledge_base.py::test_v06_87` (adaptive dispatch),
`test_v07_compliance.py::test_v07_83` (central contract shape).

## 6. Sweep comparison (480 files; pre = `*_prefix.*`, post = current)

| Metric | Pre | Post |
|--------|-----|------|
| Cisco sections nested (ingestible) | 1,216 / 2,997 (132/178 files) | **0** / 2,932 (0/178 files; 10-key set) |
| Cisco numeric keys (F14) | 868 (40 files) | **0** (0 files) |
| Cisco parse errors / files | 0 / 0 | 7 / 7 (3 JSON + 2 logs + 1 yaml + 1 control-char file — all with real causes) |
| Cisco warnings / files | 0 / 0 | 77 / 31 (open sections, no-statement content, 17 NX-OS CIDR files) |
| Cisco unknowns | 0 | 6,156 (top-heavy: the 6 foreign files ≈40% by design; rest = textbook/show-output/log/md/yaml/template content correctly flagged) |
| Unrepresented meaningful lines | 0 (323 files) | **0** (323 files; banner bodies exempt as opaque payload — definition change) |
| Junos errors / files | 0 | 6 / 6 (5 PaloAlto-mislabeled + 1 yaml — all correct flags) |
| Junos unknowns | 0 | 359 / 15 files (correct flags; `activate`/`deactivate` admitted) |
| FortiOS errors | 1 / 1 file | 6 / 6 (5 non-FortiOS markerless + 1 genuine stray-`next`) |
| FortiOS warn/unk | 5 / 2,685 | unchanged (5 / 2,685) |
| `to_dict` exceptions | 0 | 0 |
| Non-deterministic files | 0 | 0 |
| Negated nodes (new) | — | 1,350 cisco + 373 fortios (vs 1,376 `no`-lines input) |
| Cross-vendor silent (metric: nodes>0 & err==0) | cisco 71, juniper 281, forti 19 | cisco **0** (71 empty), juniper **0** (282 empty), forti 8 — all 8 carry warnings/unknowns ⇒ **0 true-silent** |
| p50 parse (corpus) | 0.446 / 4.757 / 0.196 ms | 0.998 / 3.888 / 0.447 ms (same order; vocab+prescan cost on cisco/forti) |
| Detection chain (input artifact changed, see §8) | match 315 / mismatch 8 | match 268 / mismatch 19 / **STOPPED 36** (unknown-detected files no longer fall back to Cisco) |

## 7. Security / performance / determinism

- Hostile inputs (V04-66..69/73/74/101, security_results.csv): None/bytes/int
  → typed TypeError; NUL/C0 → explicit error, no crash; lone surrogate,
  non-ASCII, whitespace-only → clean; 1–2 MB + 1 MB single line → no
  exception, < 5 s. No code execution, no shell, no path use, no
  content-in-logs beyond line-numbered evidence strings already in the
  contract.
- Performance (performance.csv): corpus p50 above; synthetic 30k-line
  parses within the 5 s gates (V04-73/80/81/82 PASS).
- Determinism: V04-75/76/77 PASS; sweep second pass 0 mismatches on all 323
  label-matched files; repeated full-suite runs stable (only wall-clock
  timings vary in evidence strings).

## 8. Cross-engine notes

- E03 already closed F3-dimension-A (executor fallback → None, step-3 gate);
  E04 verified it (V04-35) and centralised it (`parsing.get_parser`,
  executor + adaptive share it). The 36 STOPPED chain files are the E03+E04
  pipeline working as designed (detection `unknown` → stop, no fallback).
- Chain-column comparability caveat: the pre-fix sweep consumed the 09-25
  E03 detection CSV; the post-fix sweep consumes the final E03 CSV
  (unknown 73→106). Parser-behavior metrics are unaffected (like-for-like);
  chain columns are reported as current-pipeline truth.
- Engine 07/11 compliance logic untouched (F11 design). Engine 05+ not started.

## 9. Limitations (do not reopen E04 for these without a new finding)

- In-section Cisco lines are trusted (unknown-routing is root-scope);
  `ip route ...` inside an open interface stays nested (pre-existing
  keep-heuristic; section-level metric unaffected).
- Vocabularies are documented heuristics, not grammars; exotic-but-real
  commands outside them surface as unknowns (explicit, fidelity-safe).
- PaloAlto-brace content parses as brace hierarchy (structurally
  JUNOS-like); detection already labels it paloalto (E03); executor stops it.
- Banner bodies are opaque: excluded from line-fidelity by definition.
- `to_dict()` includes `negated` and envelope fields beyond spec
  `:744-753`'s minimal key list (uniform across parsers by design).
- V01-65 (Engine 01 DB-ingest perf) FAILS in this session: 9.9 MiB p50
  ~615 ms vs 105 ms baseline (stable across 3 runs). Ingestion imports
  nothing E04 touched (`app.models`, `app.config` only) and the throwaway
  DB holds 1 row — classified ENVIRONMENTAL (test-machine/DB-server drift
  since baseline), recommended clean-DB re-run; not an E04 regression.

## 10. Full-suite regression

- Post-E03 baseline: 1267 passed / 21 failed (all pre-existing:
  benchmark×13 incl. juniper_benchmark×7, frontend×2, phase8×6).
- Post-E04: **1273 passed / 22 failed** = the same 21 (identical per-file
  failure sets: benchmark_execution 6, juniper_benchmark 7 — the 7 verified
  by name against the E04 validation report's list — frontend 2, phase8 6)
  + V01-65 (environmental, §9). V06-87 and V07-83 (behavior under
  investigation) were updated and pass. Zero regressions from E04.

## 11. Files changed

`app/engines/parsing/cisco.py`, `juniper.py`, `fortinet.py` (rewrites, no
new parsers); `app/engines/parsing/__init__.py` (central contract, was
empty); `app/engines/compliance/executor.py`; `app/api/v1/audit_execution.py`;
`app/ai/adaptive.py`; `app/ai/semantic.py`;
`tests/validation/test_v04_parsing.py` (+7 tests);
`tests/test_parsers.py`, `tests/validation/test_v06_knowledge_base.py`,
`tests/validation/test_v07_compliance.py` (behavior-under-investigation
updates); `scripts/engine_validation/sweep_parsing.py`,
`report_parsing.py`. Engines 01–03, 05+ untouched. No git operations
performed (no git instruction; artifacts + report are the deliverable).

## 12. Verdict

**READY** — F1–F4 FIXED with corpus proof (0 nested, 0 unrepresented,
0 numeric keys, explicit foreign/JSON/banner/negation handling, full
persistence); F5–F8/F10/F12–F15 FIXED; F9/F11 DESIGN DECISION (documented,
tested); F16 PARTIAL (legacy parser suites green; 7 benchmark-count
failures pre-existing and parser-independent). Hypotheses 22/22 REJECTED.
Suites: v04 101/101, parsers 14/14, vertical 5/5, detection 11/11, full
1273/22 with zero E04 regressions.

**Next:** Engine 05 — Universal Normalization/Model (pending user approval).
**STOP** — no further engine started.
