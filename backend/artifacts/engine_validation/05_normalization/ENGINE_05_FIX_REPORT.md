# ENGINE 05 FIX REPORT — Universal Security Model / Normalization

- Date (UTC): 2026-09-27
- Scope: `backend/app/engines/normalization.py`,
  `backend/app/engines/universal_model.py`, plus the contract consumers
  `backend/app/benchmarks/execution.py`,
  `backend/app/engines/compliance/executor.py`,
  `backend/app/engines/compliance/engine.py`,
  `backend/app/api/v1/audit_execution.py`, `backend/app/ai/validators.py`
- Pre-fix evidence: `ENGINE_REPORT.md` + `*_prefix.*` (this directory)
- Post-fix evidence: `test_results.csv` (108 rows), `dataset_results.csv`,
  `dataset_summary.json`, `performance.csv`, `determinism_results.csv`,
  `security_results.csv`, `summary.json`, `raw_results.jsonl` (this directory)
- Verdict: **READY** — all 6 blocking findings (F1–F6) FIXED, F7–F17 FIXED,
  2 documented DESIGN DECISIONs (no knowledge base exists; no FortiOS
  benchmark module exists).

## 1. Scope

Fix + hardening of Engine 05 per the implementation prompt §§1–60: F1
comment/absence semantics, F2 FortiOS mapper, F3 model authority, F4
§10.5/§11.3/§12.1 contract, F5 single normalization + persistence, F6
failure boundary, and secondaries F7–F17. Engines 01–04 untouched except
one E04 test (V04-38) whose call-shape assertion the F5 fix changes, and
Engine 07 tests that encoded the old fabricate-and-evaluate behavior
(V07-05/18/72/73/74/95, V08-62 — see §10). No new vendor parsers, no ML in
deterministic paths, no Redis/workers/queues, no git operations.

## 2. Pre-fix findings

Per `ENGINE_REPORT.md` (100 rows: 44 PASS / 56 FAIL; 24 hypotheses
CONFIRMED): F1 comments (`! no ip http server` → `http.enabled=False`) and
absence (empty → SUCCESS + 37 fabricated mappings incl. `http.enabled=True`,
`snmp.version=2`) drove compliance state and flipped controls (empty 15
PASS, comment-only 18 PASS); F2 12/20 FortiOS keys could never reflect
input (empty marker lists, single-token multi-word keys, `http`⊂`https`
substring); F3 model dead (12 mapper + 5 control paths outside it, 10
leaves unproducible, validator prefix-based); F4 §10.5/§11.3/§12.1 unmet
(no `id`/version/`vendor_specific_syntax`, synthetic `source_path`,
constant 0.9 confidence, 5 §11.1 concepts + version missing); F5 output
never persisted (`[]` hard-codes), normalization ran twice and the
executor's copy was discarded (`ios` vs `ios_xe` divergence); F6
cross-vendor SUCCESS and FAILED-then-still-scored (arista → 126 controls,
score 0.0); F7–F17 token/type/conflict/semantics defects.

## 3. Files changed

- `app/engines/universal_model.py`: 5 missing §11.1 concepts
  (`management.http.secure_only`, `management.https.certificate_valid`,
  `management.ssh.key_size`, `services.dns.configured`,
  `services.dhcp.enabled`) + `services.dns`/`services.dhcp` objects;
  control-referenced leaves (`management.ssh.session_timeout`,
  `management.vty.console_timeout/aux_timeout/vty_timeout`); diagnostic
  leaves consumed by the benchmark (`config.conflicts`,
  `management.vty.conflicts`, `management.vty.exec_timeouts`) + `config`
  object; `VERSION = "1.0.0"` (class + instance); `is_valid_path()`,
  `leaf_paths()`; `management.ssh.timeout` description corrected to seconds
  (tested behavior).
- `app/engines/normalization.py`: rewritten internals, same public shape
  (`NormalizationEngine`, `NormalizationResultType`, `vendor_mappers`
  structure, `normalize(config, vendor, platform)` + optional
  `semantic_interpretation`). Evidence layer (§47), §12.1 types,
  canonicalization, coherence gate, model validation, confidence policy.
- `app/benchmarks/execution.py`: optional `normalization_result` consumed
  (no second run); FAILED stops evaluation (0 evaluated, 0.0, no verdicts).
- `app/engines/compliance/executor.py`: `_build_semantic_interpretation()`
  from the E04 parse tree; single `normalize()` on the canonical platform
  with the interpretation payload; FAILED stops the audit (E03 pattern);
  `normalization` provenance attached in
  `_benchmark_to_compliance_evaluation`; `AuditResult.semantic_interpretation`
  field added.
- `app/engines/compliance/engine.py`: `ComplianceEvaluation` gains
  optional `normalization_id` / `universal_model_version` (additive).
- `app/api/v1/audit_execution.py`: persists real semantic sections/unknowns
  (confidence honestly `{}`), real `normalized_values`/`unmapped_concepts`,
  `UniversalSecurityModel.VERSION` (no `"1.0"` literal, no `[]` hard-codes).
- `app/ai/validators.py`: `_validate_model_path` consults the model's own
  path set (prefix list removed).
- Tests: `test_v05_normalization.py` (100 → 108 rows), legacy
  `test_normalization.py`, `test_juniper_benchmark.py` (2 rows),
  `test_benchmark_execution.py` (1 row), `test_v04_parsing.py` (V04-38),
  `test_v07_compliance.py` (V07-05/18/72/73/74/95),
  `test_v08_findings.py` (V08-62); `sweep_normalization.py`
  (device.hostname, unmapped_concepts); `report_normalization.py`
  (hypothesis refs for V05-101..108).

## 4. F1–F17 status

| ID | Status | Evidence |
|----|--------|----------|
| F1 comments/absence/negation | FIXED | vendor-aware evidence layer (Cisco `!`/banners, Junos `#` vs `##`, FortiOS `#`); booleans True/False/None by polarity; `! no ip http server` → no mapping; empty → SUCCESS + caller identity + zero-rule count, 0 observed state; `no ip http server` → False (V05-12/67/68/69/70/71/101/102) |
| F2 FortiOS mapper | FIXED | section-presence core rewritten (single-keyword = presence); section-scoped int extraction (`min-length` 10, `expire-days` 90, `history` 5); token-aware `allowaccess` (`https` ⊄ `http`); syslog/ntp/aaa/snmp sections; V05-35..42 |
| F3 model authority | FIXED | 0 mapper paths outside model (init-time fail-fast registry check); 0 unproducible leaves; all CIS+NIST control paths in model (V07-05 too); validator model-backed (V05-53/54/55/58/60) |
| F4 contract | FIXED | `normalize(..., semantic_interpretation=None)` consumes the §10.5 payload (executor-built, KB-free per §22); `VERSION 1.0.0` persisted authoritatively; `NormalizationMapping` == spec `NormalizedValue` exactly; deterministic confidence policy (V05-43..46/50/84/105/107/108) |
| F5 one result + persist | FIXED | spy-proven single `normalize` per audit; benchmark consumes by identity; canonical `ios_xe`; real values/unmapped/version persisted (V04-38, V05-79..83/86) |
| F6 failure boundary | FIXED | unsupported/invalid/foreign → FAILED (case-insensitive, validated); FAILED stops benchmark (0 evaluated) and audit; PARTIAL only from recoverable mapper issues (V05-48/49/51/61..66/96..100) |
| F7 multi-word | FIXED | token-sequence matching: `ntp.servers`, `logging.remote_server`, syslog servers all vendors (V05-20/21/31) |
| F8 transport tokens | FIXED | per-block token sets; `ssh telnet` → telnet True (V05-15) |
| F9 Junos conflicts | FIXED | set-lines grouped by statement path (hierarchical branch skips them); NTP/syslog repeats excluded (V05-33 + juniper conflicts suite) |
| F10 set NTP | FIXED | servers or NTP evidence → configured (V05-30) |
| F11 token boundaries | FIXED | exact-token matching; `host-name` never enables syslog (V05-78) |
| F12 ACL counting | FIXED | ACL-syntax only (classic lines + named entries, remarks excluded, descriptions excluded); sequence/action aware (V05-68/75) |
| F13 data types | FIXED | model-checked + deterministic int coercion; juniper/cisco agree (V05-23/27/37) |
| F14 confidence | FIXED | policy {0.95 direct, 0.85 structured, 0.75 derived}; no constant (V05-46/105) |
| F15 result semantics | FIXED | SUCCESS = valid payload, no errors (0..N observed); PARTIAL = recoverable issues; FAILED = unsupported/invalid (V05-47/49) |
| F16 control chars | FIXED | NUL/C0/surrogates stripped deterministically (`A\x00B` → `AB`) (V05-95) |
| F17 input contract | FIXED | None/{}/missing/non-string/null-element → FAILED, never crash (V05-96..98/100) |

DESIGN DECISIONs: (a) no knowledge base exists — deterministic documented
rules instead, no false KB claim (V05-85); (b) no FortiOS benchmark module
exists — not fabricated; FortiOS values reach vendor-neutral NIST controls
(V05-59 proves overlap).

## 5. Universal Security Model changes

13 leaves + 3 objects added (§3 list), `VERSION = "1.0.0"`,
`is_valid_path()` / `leaf_paths()` helpers, one description correction.
Concept count 82 → 98; leaves 59 → 71. Vocabulary, reciprocity and
round-trip properties preserved (V05-01/04/05/06/07/10). Remaining
intentional gaps (runtime-unmapped, each with a documented None-mapper):
`authentication.mfa_enabled`, `crypto.https_cert_valid`,
`management.https.certificate_valid`, `management.https.port` — no vendor
syntax observed for any of them.

## 6. Mapper changes

Cisco/Juniper/FortiOS mappers rebuilt on the evidence layer (§4 table for
semantics): `hostname` → `device.hostname`; caller identity
(`device.vendor/platform`); firmware/time-zone/dns/dhcp/loopback evidence;
derived `secure_only`/`default_action`; token transports; per-block
timeouts/conflicts; section-scoped FortiOS extraction; context-aware Junos
flags; int coercion everywhere. Dropped fabrications: ssh/telnet port
constants, `management_interface_identified=True`, vty structural
intermediates (`all_blocks/transports/all_vty_transport` — unread by any
consumer), `""`/`"none"`/`"unknown"`-as-absence (except the allowed
`vty.transport="unknown"` for analyzed content), `snmp.version=2` fallback.
`config.conflicts`/`management.vty.conflicts`/`exec_timeouts` stay in
`universal_config` (benchmark-consumed diagnostic leaves, now model-backed).
`unit`/`bool` polarity honored on every boolean mapper.

## 7. Result contract changes

`NormalizationMapping{model_path, value, confidence, source_path: string[],
vendor_specific_syntax}` exactly (§12.1); `NormalizationResult` gains
`id` (deterministic content hash — sweep determinism unaffected),
`semantic_interpretation_id`, `universal_model_version`,
`unmapped_concepts` (model leaves minus produced), stored
`normalized_values`; `unmapped_paths` retained for recoverable mapper
issues. `to_dict()` serializes the full contract.

## 8. Pipeline/integration changes

Executor builds the §10.5 interpretation from the E04 tree, normalizes
once (canonical platform + payload), stops on FAILED, passes the result by
identity into `benchmark.execute(..., normalization_result=...)`, which
reuses it or normalizes once itself (direct-call path) and returns zero
evaluations on FAILED. `_benchmark_to_compliance_evaluation` records the
normalization id/version on the evaluation. Platform canonicalization
(`ios`→`ios_xe`) lives in the normalizer and both callers.

## 9. Persistence changes

`SemanticInterpretation` gets real sections/unknowns (scores honestly `{}` —
deterministic parsing produces none); `NormalizedConfiguration` gets real
`normalized_values`/`unmapped_concepts` and the model `VERSION`. Schema
already JSONB — no migration needed.

## 10. Test changes

`test_v05_normalization.py` 100 → 108 rows (new V05-101 whitespace-only,
V05-102 banner payload, V05-103 secure_only, V05-104 new leaves, V05-105
confidence policy, V05-106 registry fail-fast, V05-107 semver+persisted,
V05-108 interpretation flow). ~60 rows updated ONLY where they encoded the
broken behavior (defect-assertions flipped to the corrected contract, e.g.
V05-67..70 comments→absent, V05-71/47 empty→SUCCESS-unobserved,
V05-96..98/100 invalid→FAILED, V05-61..63 cross-vendor→FAILED,
V05-79 rewritten as a functional single-normalization spy test,
V05-85 rewritten to the §22 limitation design). Legacy updates of
investigated behavior: `test_normalization.py` (device.hostname,
model_path), `test_juniper_benchmark.py` (hostname path; telnet
absent→REVIEW; unknown-config safety boundary), `test_benchmark_execution.py`
(NTP-absent→REVIEW), `test_v04_parsing.py` V04-38 (call shape + identity),
`test_v07_compliance.py` V07-05 (leaves added) + V07-18/72/73/74 (foreign→stop)
+ V07-95 (padding-invariance vs live baseline), `test_v08_findings.py`
V08-62 (no FAIL findings because no evaluation). No coverage deleted.

## 11. 480-file corpus comparison

| Metric | Pre | Post |
|--------|-----|------|
| success / partial / failed | 323 / 0 / 157 | **306 / 0 / 174** |
| supported success / failed | 323 / 0 | 306 / **17** (6 cisco + 6 juniper + 5 fortios — file-for-file the E04 foreign/non-config set: 3 JSON + 2 logs + 2 yaml + 5 PaloAlto-mislabeled + 5 markerless FortiOS, all 0 mappings) |
| unsupported failed / mappings | 157 / 0 | 157 / 0 (unchanged outcome, now with full unmapped concepts) |
| mappings total | 11,128 | **4,466** (observed + identity + counts only) |
| comment-sensitive files | 12 / 382 | **0** / 382 |
| exception unmapped sum | 0 | 0 (no crashes) |
| nondeterministic files | 0 | 0 (two passes identical) |
| confidence sets | {0.9} | varied per evidence class (no constant) |
| unmapped concepts (new) | — | 29,614 (coverage now visible) |

## 12. Security validation

NUL/C0/surrogate/whitespace lines, `raw_lines=None`, non-string and null
elements, missing keys, 1 MB line, 20k lines, unsupported vendor/platform,
case variants, foreign content: no exception anywhere (V05-94/96/98/99/100
+ new V05-101/102); NUL sanitized (V05-95); invalid payloads FAILED, never
silent SUCCESS (V05-96/97/98/100); no code/shell/filesystem behavior keyed
on content; values carry line-anchored evidence, never secrets beyond the
config text itself.

## 13. Determinism

5 repeats identical (V05-88), 2 instances agree (V05-89), interleaved
3-vendor runs 0 mismatches (probe script), full 480-file corpus twice 0
mismatches (`SWEEP-NORM` + `overall.nondeterministic=0`), deterministic
content-hash result ids. Wall-clock timings excluded from comparisons.

## 14. Performance

Corpus: p50 **0.772 ms** (pre 0.250), p95 **14.653 ms** (pre 2.496), max
176 ms (pre 138), sum 2,685 ms (pre 1,823) — the cost of evidence
classification + per-mapping model validation; inside the V05-91 gates
(10/200/1000 ms) with headroom. Synthetic: 20k lines and 1 MB line within
the 5 s gates (V05-92/99). Juniper remains the tail (per-key scans, max
176 ms). Measurement only; no optimization warranted.

## 15. Regression results

- Targeted: v05 **108/108**, `test_normalization.py` + `test_universal_model.py`
  green, `test_juniper_benchmark.py` back to its 7 pre-existing failures
  (behavioral rows fixed: insecure FAILs restored, conflicts green).
- Full suite: **1282 passed / 21 failed** — the exact 21 pre-existing
  failures (benchmark_execution 6, juniper_benchmark 7, frontend 2,
  phase8 6; same tests, same count-drift signatures as the E05 baseline
  1274/21). Zero new failures; +8 from the new tests.
- Cross-engine suites updated only where they encoded E05-fixed behavior
  (§10 list); Engine 07 control semantics untouched (missing values still
  REVIEW; conflicts still REVIEW; multi-block still per-block).

## 16. Remaining limitations

- Unsupported-at-runtime leaves (mfa, both cert-valid paths, https.port)
  carry documented None-mappers; validator/model/registry agree.
- `vty.transport="unknown"` for analyzed content without vty state
  (allowed model value, pinned by a legacy test); truly empty input stays
  absent.
- `rules_count` is always emitted (truthful measurement, model default 0);
  conflicts emit `[]` only when statements were analyzed.
- `device.vendor/platform` are caller identity (DERIVED 0.75, `caller:*`
  source, empty syntax) — not config-observed; documented.
- `secure_only`/`default_action` are documented derivations (implicit-deny
  and https-without-http), never observations.
- `monitoring.syslog.*` mirrors `logging.*` evidence (pre-existing dual
  paths, preserved).
- V01-65 (Engine 01 DB-ingest perf) flaked once during E05 work but passes
  in the final full-suite runs; unrelated to this engine (no shared code).
- Corpus `unmapped_sum` (exception paths) is 0 by construction now; coverage
  visibility moved to `unmapped_concepts`.

## 17. Cross-engine impact

- E03/E04 untouched (one E04 test updated for the F5 call shape; E04
  artifacts unmodified). E04 parse trees are now consumed (§47) via the
  executor-built interpretation payload.
- E07/benchmark behavior changes are the intended E05 consequences:
  fabricated PASS/FAIL become REVIEW; foreign/unsupported become
  stopped-with-zero-evaluations. Control outcome deltas on
  previously-passing fixtures were triaged per test (all encode the old
  fabricate-and-evaluate behavior; updated with E05 citations).
- E06/E08/E11 validation rows that asserted the old behavior were updated
  (V06-87 already E04-fixed, untouched; V07-05/18/72/73/74/95, V08-62).
- No ML, KB, Redis, workers, or new parsers introduced.

## 18. Final readiness verdict

**READY** — F1–F6 FIXED with test + corpus proof (0 comment-sensitive
files, 17/17 foreign files explicitly failed, 4,466 observed-only mappings,
0 unrepresented fabrications, single normalization consumed and persisted,
failed normalization stops evaluation); F7–F17 FIXED; 108/108 rows PASS
(106 CONFIRMED BEHAVIOR, 2 DESIGN DECISION); 26/26 defect hypotheses
REJECTED; full suite 1282/21 with zero regressions; determinism, security
and performance validated.

**Next:** Engine 06 — pending user approval.
**STOP** — no further engine started.
