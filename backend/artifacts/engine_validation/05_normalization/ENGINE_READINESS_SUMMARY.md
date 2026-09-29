# ENGINE_READINESS_SUMMARY - Engine 05 - Universal Security Model / Normalization

**Scope:** `backend/app/engines/normalization.py`, `backend/app/engines/universal_model.py` +
their contract with `docs/PROJECT_MASTER_SPEC.md` (§10.5, §11, §12.1) and the consumers
`app/benchmarks/execution.py:179`, `app/engines/compliance/executor.py:226,283-286`,
`app/api/v1/audit_execution.py:336-351`, `app/ai/validators.py:90,207`
**Evidence:** 100 pytest rows (100 passed, 0 failed) - 480-file corpus - 2 runtime probe
suites - 0 production files modified
**Overall verdict:** **FAIL** (comment/absence-driven results, broken FortiOS mapper,
dead model, unmet spec contract, unpersisted output - not robustness or speed)
**Date:** 2026-09-25

---

## Scoreboard

| Status | Count | % |
|---|---|---|
| PASS | 44 | 44% |
| PARTIAL | 0 | 0% |
| FAIL | 56 | 56% |
| **Total** | **100** | 100% |

| Classification | Count |
|---|---|
| CONFIRMED BEHAVIOR | 44 |
| BUG | 34 |
| MISSING | 13 |
| DESIGN LIMITATION | 9 |

| Category | Rows | Status |
|---|---|---|
| A model structure / spec §11 | 10 | PASS 7, FAIL 3 |
| B functional (Cisco mapper) | 13 | PASS 9, FAIL 4 |
| C functional (Junos mapper) | 10 | PASS 7, FAIL 3 |
| D functional (FortiOS mapper) | 9 | PASS 2, FAIL 7 |
| E result contract vs spec §12.1 | 10 | PASS 4, FAIL 6 |
| F model <-> mapper <-> controls drift | 8 | PASS 2, FAIL 6 |
| G SEPARATE RECORD - wrong/unsupported vendor | 6 | PASS 1, FAIL 5 |
| H semantic fidelity (state not in input) | 12 | PASS 0, FAIL 12 |
| I pipeline / persistence | 9 | PASS 1, FAIL 8 |
| J determinism | 3 | PASS 3 |
| K performance (measurement only) | 3 | PASS 3 |
| L hostile / boundary input | 7 | PASS 5, FAIL 2 |

---

## Hypotheses (24 CONFIRMED - 2 REJECTED - 0 unverifiable)

CONFIRMED: H05-01 model is a dead schema - H05-02 spec §11 concepts/version missing -
H05-03 FortiOS section checks never true - H05-04 FortiOS password/syslog values never
extracted - H05-05 https-only reports http enabled - H05-06 set-style NTP configured=False
- H05-07 Junos phantom conflicts - H05-08 multi-word keys never extract (any vendor) -
H05-09 `transport input ssh telnet` reports telnet disabled - H05-10 comments drive state
and control results - H05-11 absence materialized as definite state - H05-12 fabricated
values score controls (15 PASS on an empty file) - H05-13 data-type contract violated -
H05-14 hostname written outside the model - H05-15 descriptions counted as ACL rules -
H05-16 spec §12.1 fields absent / synthetic source_path / constant confidence - H05-17
result_type is exception-driven, not coverage-driven - H05-18 caller-trusted vendor gives
SUCCESS for foreign content - H05-19 FAILED normalization still evaluated (126 controls)
- H05-20 controls and AI validation disconnected from the model - H05-21 normalization
runs twice and the executor's copy is discarded - H05-22 output never persisted, §10.5
contract unmet - H05-23 payload without lines accepted as SUCCESS - H05-24 control
characters accepted into values.

REJECTED: H05-25 repeated/interleaved normalizations differ (5 repeats + 2 instances +
480-file second pass, 0 mismatches) - H05-26 hostile input crashes or hangs (NUL, C0,
surrogate, null entries, 1 MB line, 20k lines - no exception).

---

## Blocking findings (must be fixed before this engine is ready)

1. **F1 - Comments and absence produce the compliance result.** Every extraction helper
   substring-matches raw lines including comments and materializes absent settings as
   definite values: `! no ip http server` -> http disabled, `! access-list ... permit` ->
   `acl_applied=True` + 1 rule, `! ntp server` / `! logging host` likewise. Controls
   respond directly - empty file **15 PASS**, comment-only file **18 PASS** (gains
   `1.2.5`, `AC-4`, `SC-7` from one comment), and fabricated `snmp.version=2` /
   `http.enabled=True` cause false FAILs `1.5.3/4/5` and `2.1.10`. An empty file is a
   `success` with 37 mappings while **29 of 59 model leaves** stay missing.
2. **F2 - FortiOS mapper: 12 of 20 keys can never reflect input.** 8 keys are constant
   (7 single-keyword section checks whose marker list is empty, plus `complexity` with
   reversed marker/target arguments) and 4 never extract (`set min-length/expire-days/
   history/server` matched against single tokens); `set allowaccess https` alone reports
   http enabled. The 30 FortiOS corpus files therefore carry fabricated NTP/ACL/AAA/
   SNMP/logging/password-policy state - and **0 FortiOS controls are registered**, so none
   of it is evaluated.
3. **F3 - The Universal Security Model is dead and drifted.** No production code
   instantiates it; 12 mapper paths and 5 control paths are outside it; 10 model leaves
   no mapper can produce (including `device.hostname`, while the hostname is written to a
   root key `hostname`); 4 CIS + 1 NIST control path always evaluates an undefined path;
   the AI path validator accepts non-model paths and rejects in-model ones.
4. **F4 - Spec §10.5 / §11.3 / §12.1 unmet end to end.** Input is raw lines, not a
   `SemanticInterpretation`; no knowledge base; model unversioned while the API persists
   a hard-coded `"1.0"`; `NormalizationResult`/`NormalizationMapping` lack
   `id`/`universal_model_version`/`semantic_interpretation_id`/`vendor_specific_syntax`;
   `source_path` is a synthetic string instead of `string[]`; confidence is always `0.9`.
5. **F5 - The output never reaches storage, and the work is duplicated then discarded.**
   `executor.py:226` and `execution.py:179` both normalize; the executor's
   `normalization` parameter is never read (AST-verified); `audit_execution.py:346-351`
   persists `normalized_values=[]` / `unmapped_concepts=[]` and `:336-341` an empty
   `SemanticInterpretation`; the two calls disagree on the platform label (`ios` vs
   `ios_xe`).
6. **F6 - Failed or mismatched normalization is not a safety boundary.** Cross-vendor
   content returns SUCCESS (often byte-identical to an empty config); the lookup is
   case-sensitive; and when normalization returns `failed` the benchmark still evaluates
   **126 controls** and publishes `score=0.0` with 124 REVIEW rows.

Secondary: **F7** multi-word key/token bug (Cisco `ntp.servers` always `[]`,
Cisco/Junos `logging.remote_server` never present) - **F8** telnet transport substring -
**F9** Junos phantom conflicts - **F10** set-style NTP configured=False - **F11**
`host`/`host-name` substring enables remote syslog - **F12** descriptions counted as ACL
rules - **F13** string values for `integer` paths (and inconsistent across vendors) -
**F14** constant confidence - **F15** exception-driven result types - **F16** NUL kept in
values - **F17** payload without lines accepted as SUCCESS.

---

## What is solid

Determinism (**0 mismatches**: 5 repeats, 2 instances, full 480-file second pass) - speed
(**p50 0.250 ms / p95 2.496 ms** on the corpus, 20k lines 86.9 ms, 1 MB line 9.2 ms) -
robustness (NUL / C0 / surrogate / whitespace / null entries / non-string elements /
1 MB / 20k lines - **no exception anywhere**) - input never mutated - `to_dict()`
round-trip - `failed` correctly returned for unsupported vendor/platform - model
*structure* sound (82 concepts / 59 leaves, reciprocal parent/child, consistent data-type
vocabulary, secure defaults) - Cisco functional core (hostname, real negation, exec-timeout
300/630, per-block vty transport/timeouts, conflict detection with `conflict=False` for
matching values, AAA, logging severity/source, SNMPv3) - Juniper functional core
(hostname both syntaxes, time-zone, SSH version/root-login, password policy with correct
`integer` type, lockout minutes->seconds, hierarchical NTP excluding boot-server, syslog
and service flags) - offline end-to-end audit completes with a populated
`normalization_result` (51 mappings on `secure.txt`).

---

## Corpus measurements (480 files - 11,282,991 B)

| Measure | Value |
|---|---|
| outcomes | **323 success / 0 partial / 157 failed** (157 = unsupported labels: arista 38, frr 63, paloalto 38, f5 11, napalm 4, a10 3) |
| mappings | 11,128 total, min 15 / max 45 on supported files |
| unmapped | **0 on every file** (only exceptions populate it - see F15) |
| determinism | **0 non-deterministic files** |
| comment lines present | 382/480 files; **12 files** change output without them (cisco 2, juniper 8, fortinet 2) |
| per-label timing (sum / max) | cisco 137.0 / 3.63 ms - juniper 1,643.5 / 138.33 ms - fortinet 41.7 / 18.24 ms |
| unsupported-label timing | 157 files, ~0.2 ms total (returns `failed` immediately) |
| wrong-vendor (separate record) | Junos->Cisco SUCCESS 37 - Cisco->Junos SUCCESS 15 (= empty) - Cisco->FortiOS SUCCESS 15 (= empty) - arista -> `failed` then 126 controls still evaluated |
| FortiOS mapped keys that work | 7 of 20 (hostname, 4 enable flags, ntp.servers, rules_count); 12 broken, 1 hard-coded |

Directory labels are hints, not ground truth - no accuracy score is claimed; Engine 03
output was **not** used as normalization ground truth (methodology rule), wrong-vendor
behaviour is reported only in category G.

## Performance (measurement only)

Corpus: p50 **0.250 ms** / p95 **2.496 ms** / max **138.33 ms** / sum 1,822.8 ms
(supported labels: p50 0.543 / p95 53.0 ms). Synthetic: 20,000 lines **86.9 ms**;
1 MB single line **9.2 ms**; empty config < 1 ms. End-to-end offline
`AuditExecutor.execute` ~0.7 s warm / ~2.2 s cold.

## Regression / integrity

- Full suite before E05: 745 collected / 719 passed / 26 failed -> after: **845 / 819 /
  the same 26 pre-existing failures** (100 new tests). Failure composition unchanged from
  the Engine 04 record: 8 legacy parser/benchmark tests (`test_juniper_benchmark` 7 +
  `test_vertical_slice` 1), 2 of E03's `test_detection.py`, 16 benchmark/phase tests
  (`test_benchmark_execution` 6, `test_frontend_integration_support` 2,
  `test_phase5_integration` 2, `test_phase8_hardening` 6).
- `git diff -- backend/app/` **empty**; `git status --porcelain -- backend/app/` **empty**.
- New files only: `tests/validation/test_v05_normalization.py`,
  `scripts/engine_validation/{sweep,report}_normalization.py`,
  `artifacts/engine_validation/05_normalization/*`, plus the conftest engine mapping for
  `05_normalization`.

## NOT APPLICABLE / NOT VERIFIABLE

ML quality (deferred) - knowledge-base-driven mapping (no rules exist - MISSING, not
tested) - live behaviour of persisted normalized values (nothing is persisted - F5) -
per-control impact beyond the empty/comment probes (Engines 07/11 territory) -
per-file semantic ground truth (none exists; expectations come from the input text) -
comparison against another normalizer (none in this repository).

## Limitations of this validation

Corpus "comment sensitivity" measures output changes when comments are removed, not
whether a comment happens to agree with a real command - the V05-72 is_set count covers
the 4 in-model paths satisfied by an empty config while the runtime benchmark figure is
15 controls; category G uses labels only to choose content; performance numbers are
single-machine measurements, not a readiness score.

---

**Readiness:** NOT READY - 6 blocking findings (F1, F2, F3, F4, F5, F6).
**Next:** Engine 06 (pending user approval).
