# Engine 04 - Vendor Configuration Parsing Engines

**Scope:** `backend/app/engines/parsing/{cisco,juniper,fortinet}.py` plus the parser-selection
contract in `backend/app/engines/compliance/executor.py:116-128`.
**Evidence:** 94 pytest rows (94 passed, 0 failed) + 480-file corpus sweep + report CSVs
(`test_results.csv`, `performance.csv`, `determinism_results.csv`, `security_results.csv`,
`summary.json`).
**Date:** 2026-09-25.
**Production code modified:** none (`git diff -- backend/app/` empty).

---

## 1. Method

Sequence followed: INSPECT -> CONTRACT -> INDUSTRY EXPECTATIONS -> TEST -> DATASET -> SECURITY
-> REPORT -> STOP.

Methodology rule applied to this engine (user instruction): **the Engine 03 detector output is
never treated as ground truth for parser behaviour.** Parser correctness is tested with known
vendor/input pairs, and the "detector supplied the wrong or an unsupported vendor" case is
recorded *separately* in category **G (WRONG-VENDOR)** so that Detection defects are not
attributed to the parsers and vice versa.

Statuses: `PASS / PARTIAL / FAIL / NOT VERIFIABLE / NOT APPLICABLE` (no PARTIAL rows were
produced). Classifications: `CONFIRMED BEHAVIOR | BUG | MISSING | DESIGN LIMITATION |
RECOMMENDATION`. No numeric readiness score is computed anywhere.

Evidence rows are written by the pytest recorder into
`artifacts/engine_validation/04_parsing/raw_results.jsonl`; corpus measurements come from
`scripts/engine_validation/sweep_parsing.py`; report tables are built by
`scripts/engine_validation/report_parsing.py`.

---

## 2. Contract under test

| # | Contract source | What it requires |
|---|---|---|
| C1 | `docs/PROJECT_MASTER_SPEC.md:473-484` (Sec 10.3) | a parser returns a structured tree, parse errors, parse warnings, unknown/unsupported sections |
| C2 | `docs/PROJECT_MASTER_SPEC.md:744-753` (`ParsedConfiguration`) | carries `id, vendor, platform, parse_tree, parse_errors, parse_warnings, unknown_sections` |
| C3 | `docs/PROJECT_MASTER_SPEC.md:111` | `no ip http server` and `ip http server` are different statements |
| C4 | `docs/PROJECT_MASTER_SPEC.md:1692-1694` | three parsers (IOS, JUNOS, FortiOS) are peer deliverables |
| C5 | `executor.py:116-128` `_get_parser(vendor, platform)` | vendor (and platform) select the parser; unknown handling is explicit |
| C6 | `executor.py:203-231` | the parse result is stored and handed to the next pipeline stages |
| C7 | `api/v1/audit_execution.py:308-331` | the persisted `ParsedConfiguration` exposes the tree and the diagnostics |
| C8 | `ai/semantic.py:112-139`, `ai/adaptive.py:240-243` | consumers read the tree through `get_section*` / `find_all` |

External references (verified by fetch, no invented standards): MITRE CWE-674 *Uncontrolled
Recursion*, <https://cwe.mitre.org/data/definitions/674.html>; MITRE CWE-754 *Improper Check for
Unusual or Exceptional Conditions*, <https://cwe.mitre.org/data/definitions/754.html>.

---

## 3. Which parser actually runs (observed)

`AuditExecutor._get_parser(vendor, platform)` (`executor.py:116-128`):

| vendor argument | selected parser |
|---|---|
| `cisco` | `CiscoIOSParser` |
| `juniper` | `JunosParser` |
| `fortinet` | `FortiOSParser` |
| anything else (`arista`, `f5`, `frr`, `a10`, `paloalto`, `unknown`, `""`) | **`CiscoIOSParser`** (explicit fallback, `executor.py:126-128`) |

- `platform` is declared by the signature and **never read** (`V04-36`): `_get_parser("cisco","junos")`
  and `_get_parser("cisco","ios_xe")` return the same class.
- A second, independent caller hard-codes the Cisco parser: `ai/adaptive.py:240-243`
  (`V04-40`) re-parses every vendor's content with `CiscoIOSParser`.
- Detected-vendor chain over the corpus: `match 315 / mismatch 8 / detected-unsupported-or-unknown 9`
  of 480. Restricted to Engine-01-ingestible files: **210/210 label-supported files are parsed by
  the label-matching parser**; the 46 ingestible *unsupported-vendor* files all reach
  **`CiscoIOSParser`** (detected `cisco` 33, `unknown` 8, `paloalto` 5).

---

## 4. Results by category

94 evidence rows: **PASS 55, FAIL 39, PARTIAL 0**.
Classifications: CONFIRMED BEHAVIOR 71, BUG 13, DESIGN LIMITATION 8, MISSING 2.

| Cat | Rows | Meaning | Status |
|---|---|---|---|
| A | 14 | functional - Cisco parser and section structure | PASS 9, FAIL 5 |
| B | 11 | functional - Junos parser | PASS 10, FAIL 1 |
| C | 10 | functional - FortiOS parser | PASS 10 |
| D | 9 | parser selection and pipeline integration | PASS 4, FAIL 5 |
| E | 10 | semantic fidelity (negation, banner, key selection, format sanity) | PASS 2, FAIL 8 |
| F | 7 | diagnostics required by spec 10.3 | PASS 1, FAIL 6 |
| G | 8 | **SEPARATE RECORD** - wrong-vendor input | PASS 2, FAIL 6 |
| H | 9 | hostile / boundary input | PASS 4, FAIL 5 |
| I | 5 | determinism and evidence fidelity | PASS 5 |
| J | 3 | performance (measurement only) | PASS 3 |
| K | 8 | cross-parser contract consistency | PASS 5, FAIL 3 |

Category G is deliberately separate: it records what happens when the *caller* supplies a wrong or
unsupported vendor. It is not used to judge "does the parser parse its own vendor correctly"
(categories A/B/C).

---

## 5. Expectations

1. **Spec 10.3** (`:473-484`): every parser must return a tree *and* errors *and* warnings *and*
   unknown/unsupported sections. Observed: `CiscoIOSParser.parse_errors` / `parse_warnings` are
   initialised (`cisco.py:156-157`) and **never appended to**; `cisco.py:252-258`
   (`unknown_sections`) is unreachable because `_parse_key_value` (`cisco.py:286-302`) accepts any
   non-empty line. `juniper.py:154` never assigns `unknown_sections`. Only `FortiOSParser`
   reports anything (`fortinet.py:259-278`).
2. **`ParsedConfiguration`** (`:744-753`): all three `ParseResult` classes lack `vendor`,
   `platform`, `id`, `ingested_config_id` (`V04-57`); the API re-adds `vendor`/`platform` at
   persistence time and hard-codes `parse_errors=[], parse_warnings=[]`
   (`audit_execution.py:325-326`, `V04-39`).
3. **Negation** (`:111`): `no ip http server` must differ from `ip http server`. In the tree they
   are the same node (`cisco.py:292-297`, `V04-41/42/44`).
4. **Three peer parsers** (`:1692-1694`): implemented, but they do not share a base class, a
   path convention or a search API (`K` category, `V04-85/86/87`).
5. **External**: `to_dict()` / `find_all()` recurse per child with no depth guard
   (`juniper.py:56`, `juniper.py:367-375`, `cisco.py:38`, `fortinet.py:50`) -> `RecursionError`
   at 1500 nesting levels (`V04-70/71`, CWE-674). Untrusted content is a `str` by the time it
   reaches the parser, so this is a robustness/availability issue rather than a traversal bug.

---

## 6. Hypotheses (19 CONFIRMED, 3 REJECTED, 0 unverifiable)

CONFIRMED: H04-01 IOS top-level sections nest under whatever section preceded them (5 tests) -
H04-02 the Cisco parser can never report an error/warning/unknown section - H04-03 the Junos
parser never flags an unknown/unsupported section - H04-04 `no ...` negation is lost - H04-05
foreign-syntax content accepted with 0 errors - H04-06 unsupported vendor routed to the Cisco
parser - H04-07 banner bodies parsed as commands - H04-08 JSON accepted as IOS - H04-09 the parse
tree is not an input to evaluation/normalization - H04-10 parse errors/warnings discarded at
persistence - H04-11 semantic re-analysis hard-codes the Cisco parser - H04-12 deep nesting
exhausts the stack - H04-13 Juniper style is one global switch - H04-14 the three parsers
disagree on path/value/API semantics - H04-15 `ParseResult` misses the contract fields - H04-16
non-`str` input raises untyped errors - H04-17 ACL sequence numbers / set-style values become
node keys - H04-18 `platform` argument never read - H04-19 the Juniper unclosed-brace warning is
a `ParseError`, not a `ParseWarning`.

REJECTED: H04-20 parsers lose or invent lines for their own vendor's content (0 unrepresented
meaningful lines across all 323 label-matched files; `V04-10`, `V04-79` PASS) - H04-21
repeated/interleaved parses differ (0 mismatches) - H04-22 hostile content crashes a parser (NUL,
C0 controls, lone surrogate, non-ASCII, whitespace, 1-2 MB: no exception).

---

## 7. Dataset sweep (480 real files, 11,282,991 bytes)

Label distribution: cisco 252, juniper 41, fortinet 30, arista 38, a10 3, f5 11, frr 63,
napalm 4, paloalto 38. Engine 01 recorded 256 files as ingestible.

### 7.1 Label-matched parsing (own-vendor correctness)

| Parser | Files (all / ingestible) | Nodes | errors | warnings | unknown | files with any diagnostic | unrepresented lines |
|---|---|---|---|---|---|---|---|
| CiscoIOS | 252 / 178 | 25,216 / 20,727 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| Junos | 41 / 15 | 160,244 / 80,231 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| FortiOS | 30 / 17 | 13,595 / 11,892 | 1 / 1 | 5 / 3 | 2,685 / 452 | 18 / 9 files | 0 / 0 |

Reading: all three parsers are **complete** for their own vendor (no lost/invented lines) and are
the *only* thing that never complains - Cisco/Junos produce **zero** diagnostics on 293 files,
including files that are deliberately malformed in the security probes.

### 7.2 Section structure (category A - the largest defect)

`cisco.py:180-196` keeps any differently-typed section open as the current parent, so each new
top-level IOS section attaches to the previous one instead of starting a sibling.

| Measure | value |
|---|---|
| ingestible Cisco files | 178 |
| section nodes total | 2,997 |
| **section nodes nested under another section** | **1,216** |
| **files affected** | **132 / 178 (74%)** |
| nested by type | acl 502, "nested" 464, router 190, interface 56, line 2, crypto 2 |
| all 252 Cisco-labelled files | 1,495 / 3,457 nested, 159 / 252 files |

Knock-on effects, all reproduced by tests:

- `get_section_value('router')` returns `None` although `('router','ospf 1')` is in the tree
  (`cisco.py:317-331` walks the root list only, `V04-92`).
- `audit_execution.py:309-313` serialises **roots only**, so the mis-nested sections never reach
  the persisted `ParsedConfiguration` (`V04-93`: stored section list contains only
  `interface`, while `acl` exists deeper in the tree).
- `ai/semantic.py` reads the same tree, so downstream rule matching sees an `interface` with an
  `ospf` router block inside it.

### 7.3 Wrong-vendor matrix (SEPARATE RECORD - category G, not a parser verdict)

How the parsers behave when handed another vendor's content (ingestible files only):

| Parser | foreign files | silent (nodes > 0, errors = 0) | empty tree | flagged |
|---|---|---|---|---|
| CiscoIOS on non-Cisco | 32 | **32** | 0 | 0 |
| Junos on non-Juniper | 195 | **195** | 0 | 0 |
| FortiOS on non-Fortinet | 193 | 5 | 136 | 52 |

And the chain effect: **all 46 ingestible unsupported-vendor files (Arista, F5, FRR, A10,
Palo Alto, ... ) are handed to `CiscoIOSParser`** and produce a Cisco-shaped tree with 0 errors.
This is recorded as *consequence of the detection/selection contract* (E03 F2) plus *absence of a
parser-level guard*, not as "the Cisco parser mis-parses Cisco".

### 7.4 Other corpus facts

- `no ...` lines: **1,220 across 153/178** ingestible Cisco files (1,376 across all 252) -
  none distinguishable from the affirmative form in the tree.
- `banner` configuration in 14 ingestible / 17 labelled Cisco files; body text is parsed as
  commands (`V04-46`: nodes `('Access','denied')`, `('Keep','out^')`, 0 errors).
- Three corpus files are **JSON** but labelled Cisco, detected `cisco` and ingestible:
  `Cisco/Routers/IOS-XE/csr1000v-running-config.txt` (250 nodes),
  `Cisco/Routers/IOS-XR/iosxr-running-config.txt` (77), `Cisco/Switches/Nexus/nxos-running-config.txt`
  (317) - each with **0 errors / 0 unknown** (`V04-48` reproduces it synthetically).
- Juniper style: 3 ingestible set-style vs 12 brace-style files (11 / 28 over all 41); mixed
  brace+set content is mis-detected as one style (`V04-65`).
- Maximum observed parse depth in the corpus: 18 (well below the 1,500-level crash point).
- Vendor chain agreement: 315 label matches, 8 mismatches, 9 detected-unsupported/unknown.

### 7.5 Determinism

Per-parser second pass over all label-matched files: **0 non-deterministic files**
(`files_nondeterministic = 0` for Cisco/Junos/FortiOS) and 0 `to_dict()` exceptions.
Pytest: 10 repeated parses, 2 instances, interleaved parses, line-number/`raw_text` fidelity - all
PASS (category I, 5/5).

---

## 8. Performance (measurement only - not a readiness score)

Corpus, label-matched files, single machine:

| Parser | n | p50 | p95 | max |
|---|---|---|---|---|
| CiscoIOS | 252 | 0.446 ms | 1.233 ms | 6.128 ms |
| Junos | 41 | 4.757 ms | 64.601 ms | 107.095 ms |
| FortiOS | 30 | 0.196 ms | 1.552 ms | 14.698 ms |

Synthetic (`V04-73`, all < 5000 ms): Cisco 2.02 MB / 618 ms / 90,000 nodes;
Junos 1.99 MB / 162 ms / 30,241 nodes; FortiOS 354 KB / 42 ms / 15,000 nodes.
Per-parser throughput probes (`V04-80/81/82`): 361.5 ms / 40,000 nodes (Cisco),
526.4 ms / 80,000 nodes (Junos), 57.6 ms / 30,000 nodes (FortiOS).
Offline end-to-end `AuditExecutor.execute(secure.txt)`: ~2.2 s for all 6 steps (`V04-37`).

---

## 9. Findings

### Blocking (must be fixed before this engine is ready)

**F1 - IOS section structure is wrong, and the API then drops what is left.**
`cisco.py:180-196` nests each new top-level section under the previous one: 1,216 of 2,997
section nodes in **132/178 ingestible Cisco files** are inside another section
(`V04-04/91/92/93/94`). Consequences: `get_section_value('router') -> None`
(`cisco.py:317-331`), and `audit_execution.py:309-313` persists roots only, so the stored
`ParsedConfiguration.section_list` is missing whole sections. A section lookup that silently
returns `None` is worse than a missing feature: consumers (`ai/semantic.py`) evaluate a
structurally false tree.

**F2 - the parsers have no diagnostics and the API throws away the ones that exist.**
Cisco: `parse_errors`/`parse_warnings` initialised and never written (`cisco.py:156-157`);
`unknown_sections` unreachable (`cisco.py:252-258`) - junk, unbalanced, binary and truncated
inputs all yield **0 errors** (`V04-51`), unrecognised commands become ordinary nodes
(`V04-53`). Juniper: `unknown_sections` never assigned (`juniper.py:154`, `V04-54`), and the one
warning it does emit is a `ParseError` instance placed in `warnings`
(`juniper.py:244-250`, `V04-19/90`). Only FortiOS reports. Then `audit_execution.py:325-326`
hard-codes `parse_errors=[], parse_warnings=[]`, so even FortiOS's diagnostics are discarded
(`V04-39`). Spec 10.3 responsibilities 2-4 are unmet end to end.

**F3 - wrong-vendor and unsupported-vendor content is parsed silently into a confident tree.**
Cross-vendor: 32/32 (Cisco) and 195/195 (Junos) foreign ingestible files parse with **0 errors**;
FortiOS flags only 5/193. Through the pipeline: `_get_parser` returns `CiscoIOSParser` for every
unknown/unsupported vendor (`executor.py:126-128`, `V04-35`) - **all 46 ingestible
unsupported-vendor files end up with a Cisco tree, 0 errors** (`V04-64`), and
`ai/adaptive.py:240-243` re-parses any vendor with the Cisco parser (`V04-40`). Combined with
E03 F2 (unsupported vendors *reported as* supported), the system never observes that it is
parsing content it does not understand. CWE-754 (Improper Check for Unusual or Exceptional
Conditions) applies to the missing "this is not my syntax" check.

**F4 - negation is lost, contrary to the spec's own example.**
`cisco.py:292-297` folds `no` into an identical `(key, value)` pair and `parse()` discards the
`kv_type`: `no ip http server` == `ip http server` (`V04-41`), `no shutdown` == `shutdown`
(`V04-42`), and `ConfigNode` has no negation field (`V04-44`, MISSING). This affects **1,220
negation lines in 153/178 ingestible Cisco files**. Spec `:111` explicitly requires these two
statements to be distinguishable; `raw_text` still contains the `no`, so the information is
recoverable only by re-parsing the raw line - which no consumer does.

### Secondary findings

- **F5** banner bodies become nodes (17 labelled / 14 ingestible files, `V04-46`).
- **F6** non-IOS formats are accepted: 3 JSON corpus files produce 250/77/317 nodes with 0
  errors (`V04-48`); CWE-754.
- **F7** `to_dict()`/`find_all()` raise `RecursionError` at 1,500 nesting levels (500 levels are
  fine); same unguarded recursion in `ai/semantic.py:130-139` (CWE-674, `V04-70/71`).
- **F8** `parse(None)`, `parse(b"...")`, `parse(5)` raise `AttributeError`/`TypeError` instead of
  a parser-level error (`V04-66/67/68`; root cause `.splitlines()` at `cisco.py:155`,
  `juniper.py:151`, `fortinet.py:140`).
- **F9** `_get_parser`'s `platform` parameter is never read (`V04-36`) - the ios vs ios_xe
  distinction that E03 F3 raised cannot be expressed at parser level either.
- **F10** `ai/adaptive.py:240-243` hard-codes `CiscoIOSParser` for every vendor (`V04-40`).
- **F11** the parse tree is not an input to evaluation or normalization: benchmark receives
  `raw_config`, normalizer receives `{'raw_lines': [...]}` (`executor.py:218-231`), the tree is
  stored only (`executor.py:203-204`) - `V04-38`, DESIGN LIMITATION (document it or wire it up).
- **F12** `ParseResult` lacks `vendor/platform/id/ingested_config_id` required by
  `ParsedConfiguration` (`V04-57`, MISSING; spec `:744-753`).
- **F13** cross-parser contract divergence: `ConfigNode.path` means "ancestor keys" (Junos),
  "key:value ancestors" (Cisco) and is unused (FortiOS); `find_all` is an instance method with
  `re.search` (Cisco), a staticmethod (Junos), absent (FortiOS); `get_section` vs
  `get_section_value`; `set`-style value-less statements differ (`V04-50/85/86/87`).
- **F14** ACL sequence numbers become node keys (`access-list 10 permit ...` -> key
  `access-list 10 permit ...`), and Junos set-style `set as-path 100 ...` keys the AS number
  (`V04-47/49`) - lookups by keyword fail.
- **F15** Juniper style detection is a single whole-file switch (`juniper.py:167-173`) with a
  blind 4-char strip (`juniper.py:276`): mixed content yields keys like `em`, `{`, `-name`
  (`V04-65`).
- **F16** two of this engine's own legacy test files fail (see section 10).

### What works

- **Completeness for the own vendor**: 0 unrepresented meaningful lines across 323 label-matched
  files; `line_number`/`raw_text` always point at the real source line (`V04-10/79/78`).
- **FortiOS parser** is the best of the three: 10/10 functional tests PASS, it is the only one
  that flags unknown sections and unclosed blocks, and `unset` keeps the negation in the key
  (`V04-30/45`).
- **Junos functional layer** 10/11: hierarchical and set-style paths, `##` show-configuration
  decoding, `;`-separated statements, unmatched `}` -> error, unclosed `{` -> warning
  (`V04-11..18`).
- **Determinism**: 0 mismatches on repeated/interleaved parses and across a full second sweep.
- **Robustness**: NUL, C0 controls, lone surrogate, non-ASCII, whitespace-only, 1-2 MB inputs -
  no exception (`V04-69/74/73`).
- **Performance**: p50 < 5 ms for all three parsers on real files; 2 MB in < 700 ms.
- **Shape compatibility**: all three return the same `ParseResult`/`ConfigNode` key set
  (`V04-83/84/89`), and the full offline pipeline completes with a populated `parse_result`
  (`V04-37`).

---

## 10. Cross-engine baseline (E01/E02/E03 artifacts, read-only)

- Engine 01 (PARTIAL): 480 files -> 256 ingestible; the same 480 files are swept here.
- Engine 02 (FAIL): validation passes/fails do not gate the parse step (all 6 steps complete in
  `V04-37` regardless).
- Engine 03 (FAIL, F1-F4): its F2 (unsupported vendors returned as supported) is the direct input
  to this engine's F3 - here the *consequence* is measured (46 files -> Cisco parser).
- Full suite before E04: 651 collected / 625 passed / 26 failed -> after: **745 / 719 / the same
  26 pre-existing failures** (94 new tests, byte-identical failure set verified against
  `_baseline_e04.txt`).
- Those 26 include **8 of this engine's own legacy tests** -
  `tests/test_juniper_benchmark.py` (7: Cisco regression + Juniper evaluation + sample configs)
  and `tests/test_vertical_slice.py::test_cisco_ios_full_pipeline` (1) - plus 2
  `test_detection.py` (E03's) and 16 benchmark/phase tests from Engines 07/11 territory.
  Pre-existing, unchanged by this work; the parser package has no `base.py` and no passing
  project-authored parser test suite to inherit expectations from.
- `git diff -- backend/app/` **empty**; `git status --porcelain -- backend/app/` **empty**.
- New files only: `tests/validation/test_v04_parsing.py`,
  `scripts/engine_validation/{sweep,report}_parsing.py`,
  `artifacts/engine_validation/04_parsing/*`, plus the conftest engine mapping for `04_parsing`.

---

## 11. NOT APPLICABLE / NOT VERIFIABLE

- Palo Alto / NX-OS / IOS-XR parsing: **no parser exists** (paloalto 38, and the JSON
  `iosxr`/`nxos` files are handled by the Cisco fallback) - NOT APPLICABLE to the three
  delivered parsers, recorded under F3/F6 instead.
- ML model quality - deferred by instruction (Engines are validated before ML).
- Authoritative per-file ground truth for vendor identity - directory labels are hints only;
  category G uses them to choose *content*, never to judge detection accuracy.
- Live HTTP API behaviour of the persisted `ParsedConfiguration` (source-level evidence only,
  `V04-39/93`).
- HTML/PDF escaping of `raw_text` that reaches reports - Engine 12.
- Effect of a wrong tree on individual control outcomes - Engines 07/11.

## Limitations of this validation

- Corpus labels are a hint; where a label and the content disagree, the row is reported as
  observed, not as an accuracy score.
- The mis-nesting count (F1) is computed with the same section-key set the parser uses
  (`interface, line, router, vlan, acl, crypto, key_chain, switch, nested`); a broader key set
  would only increase it.
- Security probes were run against the parser entry points directly; no fuzzing campaign was
  performed.
- Performance numbers are single-machine measurements.

---

## 12. Verdict

**FAIL / NOT READY** - 4 blocking findings: **F1** (wrong IOS section structure + roots-only
persistence), **F2** (no diagnostics anywhere in the chain), **F3** (wrong/unsupported-vendor
content parsed silently, including 46 ingestible files forced through the Cisco parser), **F4**
(negation lost, contradicting spec `:111`).

What is demonstrably working (own-vendor completeness, determinism, robustness, performance, the
FortiOS parser) does not offset the fact that a stored `ParsedConfiguration` can be structurally
wrong while reporting zero problems.

**Next:** Engine 05 - Universal Normalization/Model (pending user approval).
