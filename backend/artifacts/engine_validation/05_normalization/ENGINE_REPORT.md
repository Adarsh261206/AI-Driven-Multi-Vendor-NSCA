# Engine 05 - Universal Security Model / Normalization

**Evidence:** 100 pytest rows (100 passed, 0 failed) + 480-file corpus sweep + 2 runtime
probe suites + report CSVs
**Date:** 2026-09-25
**Verdict:** **FAIL - NOT READY**

---

## 1. Method

Ground rules (user-mandated, unchanged from Engines 01-04):

- No production code was modified. Only `backend/tests/validation/**`,
  `backend/scripts/engine_validation/**` and `backend/artifacts/engine_validation/**`
  were written. `git diff -- backend/app/` is empty.
- Detector output (Engine 03) is **not** used as ground truth. Categories B/C/D feed each
  mapper only content that *is* of the vendor that mapper claims to handle.
- Category **G** is the separate, explicitly-labelled record of wrong/unsupported-vendor
  consequences, per the methodology rule.
- Every number in this report is recomputed from code, from the pytest evidence rows, or
  from the sweep/probe artifacts. Detector results and report prose are never treated as
  evidence.
- Statuses report whether the **requirement** is met: `FAIL` means the defect is present.
  Test rows therefore assert the defect (`assert defect`) for defect claims and
  `assert ok` for conformance claims.
- No numeric readiness score is produced. Verdicts are PASS / PARTIAL / FAIL /
  NOT VERIFIABLE / NOT APPLICABLE.
- Hypotheses are phrased as **defect claims**; `CONFIRMED` if any linked evidence row is
  FAIL/PARTIAL, otherwise `REJECTED`.

Pipeline order for this engine: INSPECT -> CONTRACT -> INDUSTRY EXPECTATIONS -> TEST ->
DATASET -> SECURITY -> REPORT -> STOP.

## 2. Contract under test

| Source | Clause used as the expectation |
|---|---|
| `docs/PROJECT_MASTER_SPEC.md:499-510` | **§10.5 Normalizer** - input `SemanticInterpretation`, output `NormalizedConfiguration`, "use knowledge base for mappings" |
| `docs/PROJECT_MASTER_SPEC.md:605-696` | **§11.1 Model Structure** - the enumerated concept tree (49 leaves in the spec list) |
| `docs/PROJECT_MASTER_SPEC.md:700-706` | **§11.3 Model Versioning** - "the model is versioned" (major/minor/patch) |
| `docs/PROJECT_MASTER_SPEC.md:788-803` | **§12.1** `NormalizedConfiguration {id, semantic_interpretation_id, universal_model_version, normalized_values, unmapped_concepts}` and `NormalizedValue {model_path, value, confidence, source_path: string[], vendor_specific_syntax}` |
| `app/benchmarks/*.py` | control `target_model_path` values must exist in the model; `is_set` means "the value is present" |
| `app/ai/validators.py:90,207-226` | AI output path validation must accept the model's own paths |
| Internal consistency | a value the input does not contain must not be reported as observed; normalized values must use the model's declared `data_type` and defaults |

Files in scope: `app/engines/normalization.py` (1,344 lines),
`app/engines/universal_model.py`, plus the consumers
`app/benchmarks/execution.py:134,179`, `app/engines/compliance/executor.py:113,226,283-286`,
`app/api/v1/audit_execution.py:336-351`, `app/ai/validators.py`.

## 3. What the normalizer actually does (observed)

- `NormalizationEngine.normalize(config, vendor, platform)` takes a **dict of raw lines**,
  looks up `vendor -> platform -> mapper dict` (case-sensitive), runs every mapper lambda
  inside a `try/except`, and materializes any value that is not `None`.
- Mappers: `cisco.ios`/`cisco.ios_xe` **54 keys**, `juniper.junos` **28**,
  `fortinet.fortios` **20** (61 distinct paths in total).
- `result_type`: `success` = >=1 mapping and 0 exceptions; `partial` = >=1 mapping and
  >=1 exception; `failed` = no mapper for that vendor/platform.
- Every mapping is stamped `confidence=0.9` and
  `source_path=f"{vendor}.{platform}.{universal_path}"` - a synthetic identifier, not a
  reference to the originating line (normalization.py:277-283).
- The `UniversalSecurityModel` is **not imported by any of this**; the mappers are plain
  dicts. The model class is referenced only by `tests/test_universal_model.py`.

## 4. Results by category

| Cat | Scope | Rows | PASS | FAIL | Headline |
|---|---|---|---|---|---|
| A | Model structure / spec §11 | 10 | 7 | 3 | 5 §11.1 concepts absent; no model version; model never instantiated in production |
| B | Cisco mapper (Cisco content) | 13 | 9 | 4 | `ntp.servers`, `logging.remote_server`, telnet transport, password-policy types |
| C | Juniper mapper (Junos content) | 10 | 7 | 3 | set-style `ntp.configured=False`, phantom conflicts, remote_server never extracted |
| D | FortiOS mapper (FortiOS content) | 9 | 2 | 7 | **12 of 20 mapper keys can never reflect input** |
| E | Result contract vs spec §12.1 | 10 | 4 | 6 | missing `id`/version/`vendor_specific_syntax`; synthetic source_path; constant confidence |
| F | Model <-> mapper <-> controls drift | 8 | 2 | 6 | 12 mapper paths outside the model, 10 unreachable leaves, 5 control paths outside, 0 FortiOS controls |
| G | SEPARATE RECORD - wrong/unsupported vendor | 6 | 1 | 5 | cross-vendor content -> SUCCESS; FAILED normalization still scored |
| H | Semantic fidelity (state not in input) | 12 | 0 | 12 | comments and absence drive the whole result |
| I | Pipeline / persistence | 9 | 1 | 8 | normalized values never persisted; normalization done twice, result discarded |
| J | Determinism | 3 | 3 | 0 | 0 mismatches everywhere |
| K | Performance (measurement only) | 3 | 3 | 0 | p50 0.25 ms, 20k lines 87 ms |
| L | Hostile / boundary input | 7 | 5 | 2 | no crashes; NUL kept in values; missing payload accepted as SUCCESS |
| | **Total** | **100** | **44** | **56** | 44 CONFIRMED BEHAVIOR, 34 BUG, 13 MISSING, 9 DESIGN LIMITATION |

## 5. Expectations (and where they come from)

No external "industry standard" is invoked. The expectations are:

1. **The project's own specification** (§10.5, §11.1, §11.3, §12.1) - a written contract
   this code claims to implement (`normalization.py:4` "Maps vendor-specific parsed
   configurations to the Universal Security Model").
2. **The project's own model**: its declared `data_type`, `default_value` and path set.
3. **The project's own control registry**: every `target_model_path` must be a path the
   model defines and a mapper can produce, otherwise the control evaluates `None`.
4. **Internal consistency**: `is_set` (benchmarks/execution.py) means "present in the
   normalized configuration"; a value fabricated from absent input therefore cannot mean
   "present in the device". Likewise `success`/`partial`/`failed` must distinguish
   content gaps from crashes, and a `FAILED` normalization must not be scored.
5. **Self-declared behaviour**: helper docstrings such as `_is_fortinet_enabled`
   ("First N-1 keywords are section markers, last keyword is the target") are checked
   against the call sites, which is how F2 below was found.

## 6. Hypotheses (24 CONFIRMED, 2 REJECTED, 0 unverifiable)

**CONFIRMED**

- **H05-01** the model is a dead schema: no production instantiation, 12 mapper paths and
  5 control paths outside it, 10 leaves no mapper can produce (V05-08/53/54).
- **H05-02** spec §11 unmet: `management.http.secure_only`,
  `management.https.certificate_valid`, `management.ssh.key_size`, `services.dns.configured`,
  `services.dhcp.enabled` absent; no version attribute (V05-02/03).
- **H05-03** FortiOS section checks never evaluate true - `config firewall policy`,
  `config system ntp`, `config user local/group`, `config log setting`,
  `config system snmp-community` all report False for content that contains them
  (V05-38/39/41/42).
- **H05-04** FortiOS password policy (`set min-length/expire-days/history`) and syslog
  target (`set server`) are never extracted (V05-37/40).
- **H05-05** `set allowaccess https` alone reports `management.http.enabled=True`
  (substring `http` matches `https`) (V05-35).
- **H05-06** Junos set-style NTP: servers listed, `ntp.configured=False` (V05-30).
- **H05-07** Junos flat statements grouped under the literal key `set` produce phantom
  conflicts for ordinary configurations (V05-33).
- **H05-08** multi-word keys matched against single tokens: Cisco `ntp.servers` stays
  `[]`, Cisco/Junos `logging.remote_server` never appears (V05-20/21/31).
- **H05-09** `transport input ssh telnet` -> `telnet.enabled=False` while the transport
  itself says telnet is permitted (V05-15).
- **H05-10** comment lines drive state: `! no ip http server` -> http False,
  `! access-list ... permit` -> acl_applied True + 1 rule, `! ntp server`, `! logging host`
  likewise; and **controls flip**: comment-only input passes 18 controls vs 15 for empty,
  gaining `1.2.5`, `AC-4`, `SC-7` from a single comment (V05-67/68/69/70/77).
- **H05-11** absent configuration is materialized as definite state: empty config ->
  SUCCESS with 37 mappings including `http.enabled=True`, `snmp.version=2`, ports 22/23,
  `management_interface_identified=True`, `vty.transport='unknown'`, while **29 of 59
  model leaves** stay missing and `unmapped_paths` stays empty (V05-47/71).
- **H05-12** those fabrications are scored: 15 controls PASS on an *empty* file
  (`is_set` on materialized `False`), and fabricated `snmp.version=2`/`http.enabled=True`
  cause the false FAILs `1.5.3`, `1.5.4`, `1.5.5`, `2.1.10` (V05-72/73/74).
- **H05-13** password-policy numbers emitted as `str` for an `integer` model path, and
  differently typed across vendors (`'15'` vs `12`) (V05-23).
- **H05-14** hostname written to root key `hostname`; `device.hostname` never populated
  (V05-76).
- **H05-15** `description deny the bad guys` counted as 1 ACL rule (V05-75).
- **H05-16** spec §12.1 unmet: no `id`/`semantic_interpretation_id`/
  `universal_model_version`; mapping lacks `vendor_specific_syntax`; `source_path` is a
  synthetic string, not `string[]`; confidence constant `0.9` (V05-43/44/45/46).
- **H05-17** result semantics are exception-driven: SUCCESS without coverage, PARTIAL only
  from crashes (V05-47/49).
- **H05-18** caller-trusted vendor/platform: Junos content through the Cisco mapper ->
  SUCCESS 37; Cisco through Junos/FortiOS -> SUCCESS identical to an empty config;
  `'Cisco'/'IOS'` -> FAILED (V05-61/62/63/66).
- **H05-19** `FAILED` normalization does not stop evaluation: arista -> normalization
  failed, **126 controls evaluated, score 0.0, 124 REVIEW** (V05-64/65).
- **H05-20** controls and AI validation disconnected from the model: 4 CIS paths and 1
  NIST path outside the model; 0 FortiOS controls; validator accepts
  `management.vty.console_timeout` (not in model) and rejects `monitoring.syslog.enabled`
  (in model) (V05-55/58/59/60).
- **H05-21** normalization runs twice per audit (executor.py:226 + execution.py:179) and
  the executor's copy is discarded - `_benchmark_to_compliance_evaluation`'s
  `normalization` parameter is never read; platform labels diverge (`ios` vs `ios_xe`)
  for identical output (V05-79/80/86).
- **H05-22** nothing reaches storage: `normalized_values=[]`, `unmapped_concepts=[]`,
  empty `SemanticInterpretation`, `universal_model_version="1.0"` hard-coded; §10.5 input
  type and knowledge base unused (V05-81/82/83/84/85).
- **H05-23** a payload with no lines at all is accepted as a full SUCCESS (V05-97).
- **H05-24** control characters accepted into normalized values (`hostname A\x00B`)
  (V05-95).

**REJECTED**

- **H05-25** repeated/interleaved normalizations differ - 5 repeats identical, 2 instances
  identical, 0 non-deterministic files in the corpus (V05-88/89/90).
- **H05-26** hostile input crashes or hangs - NUL/C0/surrogate/whitespace lines,
  `raw_lines=None`, non-string elements, a 1 MB line and 20k lines all complete without
  an exception (V05-94/96/98/99/100).

## 7. Dataset sweep (480 real files, 11,282,991 bytes)

### 7.1 Outcomes

| Group | Files | success | partial | failed | mappings |
|---|---|---|---|---|---|
| all | 480 | 323 | **0** | 157 | 11,128 |
| supported labels (cisco 252, juniper 41, fortinet 30) | 323 | 323 | 0 | 0 | min 15 / max 45 |
| unsupported labels (arista 38, frr 63, paloalto 38, f5 11, napalm 4, a10 3) | 157 | 0 | 0 | 157 | 0 |

- `unmapped_sum = 0` on every file (unmapped paths are only produced by exceptions, so
  this measures crashes, not coverage - see H05-17).
- **0 non-deterministic files** (second pass identical everywhere).
- 382/480 files contain comment lines; **12 files** change normalized output if comments
  are removed (2 cisco, 8 juniper, 2 fortinet) - the measurable subset of H05-10; the
  remaining files are "comment-insensitive" only because their comments happen not to
  contain matching substrings.
- FortiOS corpus files normalize to **15-16 mappings**, of which only **7 of the 20**
  FortiOS keys can reflect input at all (hostname, http/https/ssh/telnet enable flags,
  ntp.servers, rules_count): 12 are broken as described in F2 and the last one
  (`management.ssh.port`) is a hard-coded 22. The remaining values are fabricated
  defaults (H05-03/04/05).

### 7.2 Wrong/unsupported-vendor (SEPARATE RECORD - category G)

- Cross-fed content (probes): Junos through Cisco -> `success` 37 mappings;
  Cisco through Junos -> `success` 15, byte-identical to an empty configuration;
  Cisco through FortiOS -> `success` 15, also identical to empty.
- Unsupported label through the pipeline: normalization `failed`, then the benchmark
  engine still evaluates **126 NIST controls** (0 PASS / 2 FAIL / 124 REVIEW, score 0.0).
- These are consequences recorded under G; no claim is made about which vendor a file
  "really" is (directory labels remain hints).

### 7.3 Determinism

`SWEEP-NORM`: 480 files normalized twice -> 0 differences; plus V05-88 (5 repeats) and
V05-89 (2 instances).

## 8. Performance (measurement only - not a readiness score)

Corpus (480 files): p50 **0.250 ms**, p95 **2.496 ms**, max **138.33 ms**, sum 1,822.8 ms.
Supported labels only: p50 0.543 ms, p95 53.0 ms.

| Label | Files | sum ms | max ms |
|---|---|---|---|
| cisco | 252 | 137.0 | 3.63 |
| juniper | 41 | **1,643.5** | 138.33 |
| fortinet | 30 | 41.7 | 18.24 |

Synthetic: 20,000-line config **86.9 ms**; 1 MB single line **9.2 ms**; empty config
< 1 ms. End-to-end offline `AuditExecutor.execute` on `tests/sample_configs/secure.txt`
completes in ~0.7 s warm (~2.2 s cold) with `normalization_result` attached.

The Junos mapper is ~40 ms/file (vs ~0.5 ms/file for Cisco) because the conflict
extractor and the per-key scans re-walk every line for each of the 28 keys.

## 9. Findings

### Blocking (must be fixed before this engine is ready)

**F1 - Comments and absence produce the compliance result (H05-10, H05-11, H05-12).**
Every extraction helper (`_is_enabled`, `_is_negated`, `_has_section`, `_count_acls`)
substring-matches raw lines *including comments*, and every absent setting is materialized
as a definite value instead of `None`. Observed consequences:

- `! no ip http server` -> `management.http.enabled=False`; `! access-list 10 permit host
  1.2.3.4` -> `acl_applied=True`, `rules_count=1`; `! ntp server` -> `ntp.configured=True`;
  `! logging host` -> `logging.remote_enabled=True`.
- Control evaluation responds directly: empty file **15 PASS**, comment-only file
  **18 PASS** (gains `1.2.5`, `AC-4`, `SC-7`), `! no ip http server` -> 17 PASS.
- An empty file is a `success` with 37 mappings, 29 model leaves missing, and fabricated
  `http.enabled=True` / `snmp.version=2` that contradict the model defaults and produce
  false FAILs `1.5.3`, `1.5.4`, `1.5.5`, `2.1.10`.
- 12 corpus files measurably change normalized output when comment lines are removed.

**F2 - The FortiOS mapper is systematically broken: 12 of its 20 keys can never reflect
input (H05-03/04/05).**
- 8 keys are constant: `aaa.authentication_enabled`, `aaa.authorization_enabled`,
  `logging.enabled`, `logging.remote_enabled`, `ntp.configured`, `acl_applied`,
  `services.snmp.enabled` are single-keyword `_is_fortinet_enabled` calls whose marker
  list is empty (normalization.py:741-775), so `in_section` can never become true;
  `password_policy.complexity` passes the enable statement and the section header in
  reversed roles.
- 4 keys never extract: `min_length`, `expiration`, `history`, `logging.remote_server`
  use multi-word keys tested against single whitespace tokens (normalization.py:777-785).
- `set allowaccess https` alone flips `management.http.enabled=True` (substring).
- Net: for the 30 FortiOS corpus files, NTP/ACL/AAA/SNMP/logging/password-policy state in
  the normalized output is fabricated. Additionally **no FortiOS controls are registered**
  (0 controls), so none of it is even evaluated today.

**F3 - The Universal Security Model is dead and the three sides have drifted (H05-01,
H05-14, H05-20).**
- No production code instantiates `UniversalSecurityModel` (only the model module itself,
  its unit test, and validation probes reference it).
- 12 mapper keys are outside the model (`hostname`, `config.conflicts`,
  `management.ssh.session_timeout`, `management.telnet.port`, and 8 `management.vty.*`
  keys); 10 model leaves no mapper can produce (`device.hostname/vendor/platform`,
  `access_control.default_action`, `authentication.mfa_enabled`, `crypto.https_cert_valid`,
  `device.firmware_version`, `management.http.port`, `management.https.port`,
  `management.ssh.max_retries`).
- 4 CIS control paths (`management.ssh.session_timeout`, `management.vty.{aux,console,
  vty}_timeout`) and 1 NIST path (`management.vty.vty_timeout`) are outside the model, so
  those controls always evaluate an undefined path; FortiOS has **0 controls**.
- `OutputValidator._validate_model_path` is prefix-based: it accepts
  `management.vty.console_timeout` (not in the model) and rejects
  `monitoring.syslog.enabled` (in the model) because `monitoring` is not in
  `VALID_PATH_PREFIXES`.

**F4 - The written contract (§10.5 / §11.3 / §12.1) is unmet end to end (H05-02,
H05-16, H05-22).**
- §10.5 says the normalizer takes a `SemanticInterpretation` and uses the knowledge base;
  the engine takes `{'raw_lines': [...]}` and has no knowledge-base import at all.
- §11.3 says the model is versioned; the model has no version, the API persists a
  hard-coded `"1.0"`, and `NormalizationResult` has no `id` /
  `universal_model_version` / `semantic_interpretation_id`.
- §12.1 `NormalizedValue` requires `model_path`, `source_path: string[]` and
  `vendor_specific_syntax`; the runtime mapping uses `universal_path`, a single synthetic
  `source_path` string, and has no `vendor_specific_syntax`; confidence is the constant
  `0.9` regardless of evidence.

**F5 - The engine's output never reaches storage, and the work it does is duplicated and
then thrown away (H05-21, H05-22).**
- `executor.py:226` and `benchmarks/execution.py:179` both run `NormalizationEngine` on
  the same content (probe: both `success`, 51 mappings, identical `universal_config`).
- `_benchmark_to_compliance_evaluation(benchmark_result, normalization)` never loads its
  `normalization` parameter (AST-verified), so the executor's result is discarded.
- `audit_execution.py:346-351` persists `normalized_values=[]` and
  `unmapped_concepts=[]` regardless of the engine result, and `:336-341` persists an
  empty `SemanticInterpretation` - so no normalized value, no unmapped concept and no
  semantic section ever reaches the database.
- The two normalization calls even disagree on the platform label (`ios` vs `ios_xe`).

**F6 - A failed or mismatched normalization is not a safety boundary (H05-18, H05-19).**
- Cross-vendor content normalizes to `success` (often byte-identical to an empty config),
  and the lookup is case-sensitive (`'Cisco'/'IOS'` -> `failed`).
- When normalization does return `failed` (unsupported vendor/platform), the benchmark
  engine still evaluates 126 controls and publishes `score=0.0` with 124 REVIEW rows -
  the failure is visible only inside `normalization_result`, which is never persisted
  (F5).

### Secondary findings

- **F7** multi-word key/token bug beyond FortiOS: Cisco `ntp.servers` is always `[]` and
  Cisco/Junos `logging.remote_server` never appears, so `6.7.1` (junos `ntp.servers
  is_set`) and any remote-logging check can never be satisfied by real evidence
  (V05-20/21/31).
- **F8** `_has_line_transport` matches the literal substring `transport input telnet`, so
  `transport input ssh telnet` reports `telnet.enabled=False` - understating a telnet
  exposure (V05-15).
- **F9** Junos `_extract_juniper_conflicts` groups every flat `set` line under the key
  `set`, so two ordinary statements (or two NTP servers) are reported as conflicting
  configuration (V05-33).
- **F10** Junos `_is_juniper_section_present` only matches `ntp {`, so set-style NTP is
  `configured=False` with servers listed (V05-30).
- **F11** Junos `_is_juniper_enabled(..., 'host')` matches `host` inside `host-name`, so
  `system { host-name R2; }` reports `logging.remote_enabled=True` (V05-78).
- **F12** `_count_acls` counts any line containing `permit `/`deny `, including interface
  descriptions (V05-75).
- **F13** data-type contract violated for `integer` paths (`'15'`, `'5'` for min_length and
  history; juniper emits `12` for the same path) (V05-23).
- **F14** confidence is a constant `0.9`, so consumers cannot distinguish a documented
  mapping from a guess (V05-46).
- **F15** `success`/`partial` distinguish crashes from content gaps, never coverage
  (V05-47/49).
- **F16** control characters (NUL) pass straight into normalized values (CWE-158 class of
  problem) (V05-95).
- **F17** a payload without `raw_lines` at all is accepted as a full `success` (V05-97).

### What works

- **Determinism:** 5 repeats identical, 2 instances identical, 0 non-deterministic files
  across all 480 corpus files (V05-88/89/90, `SWEEP-NORM`).
- **Performance:** p50 0.250 ms / p95 2.496 ms on the corpus; 20k lines in 86.9 ms;
  1 MB line in 9.2 ms; empty config < 1 ms (V05-91/92/93).
- **Robustness:** NUL/C0/surrogate/whitespace lines, `raw_lines=None`, integer elements,
  a `None` element, a 1 MB line and 20k lines - no exception anywhere (V05-94/96/98/99/100).
- **Model structure itself:** 82 concepts / 59 leaves load, parent/child relations fully
  reciprocal, no dangling children, a consistent data-type vocabulary, names and
  descriptions everywhere, secure-by-default values (`http.enabled=False`,
  `snmp.version=3`) (V05-01/04/05/06/07/09/10).
- **Cisco functional layer:** hostname, negation of a *real* command, exec-timeout
  conversion (300/630 s), vty transport and per-block timeouts, conflict detection
  (including non-conflicts staying `conflict=False`), AAA flags, logging level/severity/
  source-interface, SNMPv3 group + community (V05-11..14, 16..19, 22).
- **Juniper functional layer:** hostname in both syntaxes, time-zone, SSH protocol-version
  and root-login, password min-length/format in both syntaxes (correct `integer` type),
  lockout minutes->seconds, hierarchical NTP (servers excluding boot-server, authentication),
  syslog flags, service flags (V05-24..29, 32).
- **FortiOS fragments that do work:** quoted hostname, interface `allowaccess` flags,
  firewall policy rule count, NTP server list (V05-34/36, plus `rules_count` in V05-38).
- **Contract fragments that do work:** `failed` for unsupported vendor/platform, `unmapped`
  reporting on exceptions, `to_dict()` round-trip, input never mutated, engine-level
  `failed` signal present (V05-48/50/51/52/64).
- **Integration:** an offline end-to-end audit completes with a populated
  `normalization_result` (V05-87, 51 mappings on `secure.txt`).

## 10. Cross-engine baseline (E01-E04 artifacts, read-only)

- Engine 01 (PARTIAL): 480 files -> 256 ingestible; the same 480 files are swept here.
- Engine 02 (FAIL): validation does not gate later stages - likewise here nothing gates
  normalization or evaluation.
- Engine 03 (FAIL): its F2 (unsupported returned as supported) feeds category G here -
  unsupported vendors are normalized as `failed` and then still evaluated (F6).
- Engine 04 (FAIL): its parsers produce the `raw_lines` this engine consumes; E04 F2
  (no diagnostics) and F4 (negation lost in the tree) are upstream of, but independent
  from, the comment/absence handling measured in F1 - this engine re-reads raw text, so
  fixing the parser would not fix F1.
- Full suite before E05: 745 collected / 719 passed / 26 failed -> after:
  **845 / 819 / the same 26 pre-existing failures** (100 new tests). The failure set is
  unchanged in composition: 7 `tests/test_juniper_benchmark.py`, 1
  `test_vertical_slice.py::test_cisco_ios_full_pipeline`, 2 `test_detection.py`, and 16
  benchmark/phase tests (`test_benchmark_execution` 6, `test_frontend_integration_support`
  2, `test_phase5_integration` 2, `test_phase8_hardening` 6) - the same 8+2+16 split
  recorded in the Engine 04 report.
- `git diff -- backend/app/` **empty**; `git status --porcelain -- backend/app/` **empty**.
- New files only: `tests/validation/test_v05_normalization.py`,
  `scripts/engine_validation/{sweep,report}_normalization.py`,
  `artifacts/engine_validation/05_normalization/*`, plus the conftest engine mapping for
  `05_normalization`.

## 11. NOT APPLICABLE / NOT VERIFIABLE

- **ML model quality** - deferred by instruction (engines validated before ML).
- **Knowledge-base-driven mapping** - the knowledge base has no normalization rules to
  test against; recorded as MISSING under H05-22 rather than tested.
- **Live HTTP behaviour of persisted normalized values** - nothing is persisted (F5), so
  there is no live path to observe; source-level only.
- **Effect of normalization bugs on individual control outcomes beyond the probes run
  here** - Engines 07/11 own per-control validation; only the empty/comment consequences
  were measured (V05-72/77).
- **Per-file semantic ground truth** ("what this device is really configured to do") -
  no authoritative source exists; expectations are drawn from the input text itself
  (comment vs command, present vs absent).
- **A/B comparison against another normalizer** - none exists in this repository.

## Limitations of this validation

- Category G uses directory labels only to choose *content* for wrong-vendor probes; no
  detection accuracy is claimed.
- Corpus "comment sensitivity" measures whether removing comment lines changes the output;
  it cannot detect comments that merely agree with real commands.
- The is_set coverage count in V05-72 is computed over control paths that exist in the
  model (4 of 6 such paths are satisfied by an empty config); the runtime figure from the
  benchmark probe is 15 controls passing on an empty file, which includes paths outside
  the model's is_set set - both are reported as observed.
- Performance numbers are single-machine measurements, not a readiness score.
- Hypothesis conclusions are derived only from the recorded evidence rows; no claim goes
  beyond them.

---

## 12. Verdict

**FAIL - NOT READY.** Six blocking findings:

| | Finding | Evidence |
|---|---|---|
| F1 | Comments and absence produce the compliance result | V05-67..77, H05-10/11/12 |
| F2 | FortiOS mapper: 12 of 20 keys can never reflect input; 0 FortiOS controls | V05-35..42, V05-59, H05-03/04/05 |
| F3 | Universal Security Model is dead and three-sided drifted | V05-08/53/54/55/58/60/76, H05-01/20 |
| F4 | Spec §10.5 / §11.3 / §12.1 contract unmet | V05-02/03/43..46/82..85, H05-02/16/22 |
| F5 | Normalized output never persisted; normalization duplicated then discarded | V05-79..86, H05-21/22 |
| F6 | Failed or mismatched normalization is not a safety boundary | V05-61..66, H05-18/19 |

Secondary: F7-F17 (multi-word token bugs, telnet transport substring, Junos phantom
conflicts, set-style NTP flag, `host`/`host-name` substring, ACL counting, data types,
constant confidence, result semantics, NUL acceptance, missing payload accepted).

This engine's **own** outputs are deterministic, fast and crash-resistant; the blocking
problems are semantic fidelity, contract conformance and integration - not robustness or
speed.
