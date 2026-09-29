# Engine 07 - Control Selection / Compliance (spec 10.7)

**Evidence:** 95 pytest rows (95 passed, 0 failed) + 480-file corpus sweep + 3 runtime
probe suites + report CSVs
**Date:** 2026-09-25
**Verdict:** **FAIL - NOT READY**

---

## 1. Method

Ground rules (user-mandated, unchanged from Engines 01-06):

- No production code was modified. Only `backend/tests/validation/**`,
  `backend/scripts/engine_validation/**` and `backend/artifacts/engine_validation/**`
  were written. `git diff -- backend/app/` is empty.
- Detector output is **not** used as ground truth. Category G is the separate,
  explicitly-labelled record of wrong/unsupported-vendor consequences, per the
  methodology rule.
- Every number in this report is recomputed from code, from the pytest evidence rows, or
  from the sweep/probe artifacts. Report prose is never treated as evidence.
- Statuses report whether the **requirement** is met: `FAIL` means the defect is present.
  Test rows therefore assert the defect (`assert defect`) for defect claims and
  `assert ok` for conformance claims.
- No numeric readiness score is produced. Verdicts are PASS / PARTIAL / FAIL /
  NOT VERIFIABLE / NOT APPLICABLE.
- Hypotheses are phrased as **defect claims**; `CONFIRMED` if any linked evidence row is
  FAIL/PARTIAL, otherwise `REJECTED`.

Pipeline order for this engine: INSPECT -> CONTRACT -> INDUSTRY EXPECTATIONS -> TEST ->
DATASET -> SECURITY -> REPORT -> STOP.

**Explicit user directive for this engine:** Engine 05 findings are carried as *upstream
context only*. They are cited where they touch a section 10.7 duty (e.g. normalization
output that the evaluator consumes) and are **never assumed fixed**; nothing in this
report claims an Engine 05 result as this engine's evidence, and Engine 05's own defects
are not re-litigated here.

## 2. Contract under test

| Source | Clause used as the expectation |
|---|---|
| `docs/PROJECT_MASTER_SPEC.md:361-363` | **§9.1 step 6** - "Apply CIS/NIST rules against the universal model" after vendor detection |
| `docs/PROJECT_MASTER_SPEC.md:525-536` | **§10.7 Control Selection & Compliance** - load framework rules (CIS, NIST), extract values, evaluate, produce evidence chains |
| `docs/PROJECT_MASTER_SPEC.md:908-916` | **§13.1** dual baseline: CIS vendor controls + NIST SP 800-53 baseline both loaded |
| `docs/PROJECT_MASTER_SPEC.md:918-958` | **§13.2** control structure: `id`, `framework`, `version`, title/description/category/severity, `rule.target.model_path`, `rule.operator` |
| `docs/PROJECT_MASTER_SPEC.md:960-1005` | **§13.3** evaluation logic: extract value -> compare with operator (equals, not_equals, greater_than, less_than, contains, **in**) -> `calculate_confidence(normalization_confidence, rule_confidence)` -> emit evidence chain |
| `docs/PROJECT_MASTER_SPEC.md:1007-1013` | **§13.4** insufficient evidence -> REVIEW; **confidence <70% -> REVIEW** |
| `docs/PROJECT_MASTER_SPEC.md:831-838` | **§12 EvidenceChain** - `raw_config, parsed_value, normalized_value, security_control, expected_value, actual_value, result, reasoning` |
| `docs/PROJECT_MASTER_SPEC.md:806-824` | **§12 ComplianceResult / ControlResult** - single `overall_score`, `framework`, `framework_version`, result enum PASS/FAIL/REVIEW |
| `docs/PROJECT_MASTER_SPEC.md:~1426-1436` | **§15 DDL** `compliance_results` - `configuration_id` link column, `confidence DECIMAL(5,2)` |
| Internal consistency | one logical contract must behave the same in every implementation that exposes it; a framework request must change which rules run |

Files in scope: `app/benchmarks/{registry,execution,models,cisco_ios_xe_controls,
juniper_junos_controls,nist_sp800_53_controls,framework_mappings}.py` (canonical path,
196 controls), `app/engines/compliance/{models,loader,engine,evidence,executor,findings,
cisco_controls}.py` (legacy/dead path, 10 controls), `app/api/v1/{compliance,
audit_execution,reports}.py`, `app/models/__init__.py:243-264` (`ComplianceResult`).

## 3. What the compliance engine actually does (observed)

- **Two control systems, one production path.** The canonical path is
  `AuditExecutor.execute` -> `BenchmarkExecutionEngine.execute`
  (`executor.py:218`, `execution.py:152-215`): detection supplies vendor/platform,
  the registry selects vendor CIS controls + the 126 NIST universal controls (dual
  baseline, `execution.py:181-193`), each control is evaluated against the normalized
  config, and findings are generated from the same evaluation
  (`executor.py` -> `findings.py`). The legacy path (`ControlLoader` reads 10 CIS-only
  controls; `RuleEngine` evaluates with its own operator set) is imported by the
  executor (`executor.py:19-20`) but never instantiated - the module docstring at
  `executor.py:8-9` documents it as not used.
- **Selection is exact-case.** Registry keys are `f"{vendor}:{platform}"`
  (`registry.py:41/63`); the only normalization is the `ios -> ios_xe` alias, gated on
  `vendor_lower == "cisco"` (`execution.py:171-175`). A caller-supplied `"Cisco"` or
  `"JUNOS"` therefore selects the NIST-only set (V07-14/16).
- **`framework`/`framework_version` are inert.** `AuditExecutor.execute` declares both
  (`executor.py:134-135`) and never reads either; the API passes the request's
  framework through (`audit_execution.py:241-246`) but every run evaluates the same
  dual baseline - probe: CIS / NIST / BOGUS all return the identical 179 results
  (V07-17).
- **Verdicts come from two different mechanisms.** 106 of 196 controls are unmapped in
  the Universal Security Model and are decided by `audit_regex` against **raw text**
  (match -> PASS conf 0.8, miss -> FAIL conf 0.8, `execution.py:292-321`); the mapped
  remainder are decided by normalized values through the §13.3 operator set
  (`execution.py:620-668`). Normalization confidence reaches the evidence as a constant
  `0.0` on every one of 179 evaluations (probe).
- **Framework labels are inferred at write time, not stored with the control.** Controls
  have no `framework` field (`models.py:32-76`); persistence assigns
  `is_nist = control_id starts with a letter and contains "-"`, otherwise the
  **user-selected** framework is stamped on the row (`audit_execution.py:359-362`), and
  `reports.py:54` hardcodes `framework="CIS"` in the list response while `:35-38`
  filters on the persisted column.
- **Two scores per run.** `AuditResult.overall_score = passed/evaluated` (`execution.py:206`,
  persisted at `audit_execution.py:446`) = **46.9** on the sample secure config, while
  `ComplianceEvaluation.overall_score = passed/(passed+failed)` (`executor.py:370`) =
  **95.5** for the same run (84 P / 4 F / 91 R).
- **Persistence schema** (`models/__init__.py:243-264`): `normalized_configuration_id`
  (spec DDL says `configuration_id`, spec §12 interface says `normalized_config_id` -
  the spec disagrees with itself), lowercase result values
  (`ComplianceResultType.PASS = "pass"`), `Float` confidence, no `framework_version`
  column written anywhere.

## 4. Results by category

| Cat | Scope | Rows | PASS | FAIL | Headline |
|---|---|---|---|---|---|
| A | Spec structure (§13.1/§13.2) | 10 | 5 | 5 | no `framework` attribute; 6 controls target non-existent model paths; spec `in` operator unimplemented; three operator vocabularies; duplicate id overwrites the index |
| B | Control selection (§10.7, §9.1 step 6) | 17 | 8 | 9 | `framework=` argument is a no-op; casing drops 53/17 controls; API drops vendor/platform filter arguments; advertised versions don't exist; benchmark_id from controls[0] |
| C | Evaluation logic (§13.3/§13.4) | 18 | 11 | 7 | `*_or_equal` falls through to equality in the registry; unknown operator silently equals; regex PASS/FAIL with no normalized value; dual score; confidence model absent |
| D | Evidence chains (§13.3 step 3, §12) | 9 | 5 | 4 | spec keys `raw_config`/`parsed_value`/`security_control`/`reasoning` missing; `parsed_value` never populated; 2 decisive results without raw evidence; multi-block PASS with null normalized_value |
| E | Framework attribution + persistence | 8 | 2 | 6 | NIST request relabels CIS rows; report list hardcodes `CIS`; lowercase result enum; no framework_version; DDL column drift |
| F | Drift: legacy vs canonical | 9 | 1 | 8 | 10 vs 196 controls; legacy has no NIST; ios vs ios_xe excludes legacy rules; is_set/regex_match/applicability semantics differ; dead module + dead imports |
| G | SEPARATE RECORD - wrong/unsupported vendor | 4 | 0 | 4 | engine trusts caller; cross-vendor PASSes; unsupported vendor raw-regex verdicts; empty config -> 2 decisive FAILs |
| H | Semantic fidelity invariants | 3 | 3 | 0 | no fabricated PASS; empty file never PASSes; manual always REVIEW |
| I | Pipeline integration (§9.1) | 6 | 5 | 1 | offline pipeline runs end to end, findings wired; unknown vendor parsed with `CiscoIOSParser` |
| J | Determinism | 3 | 3 | 0 | repeat runs identical verdicts/scores/inventory |
| K | Performance (measurement only) | 3 | 3 | 0 | startup ms; 179 controls in 6-9 ms warm; near-linear scaling |
| L | Hostile / boundary input | 5 | 2 | 3 | None -> raw `AttributeError` message; failure reason not recorded on any step; invalid regex -> confident FAIL everywhere |
| | **Total** | **95** | **48** | **47** | 48 CONFIRMED BEHAVIOR, 18 BUG, 16 DESIGN LIMITATION, 8 MISSING, 5 RECOMMENDATION |

## 5. Expectations (and where they come from)

No external "industry standard" is invoked. The expectations are:

1. **The project's own specification** (§9.1 step 6, §10.7, §13.1-13.4, §12, DDL) -
   a written contract this code claims to implement (`executor.py:1` "canonical
   evaluation path", `audit_execution.py` "per SPEC section 9").
2. **The spec's own cross-references**: §13.3 step 4 names
   `calculate_confidence(normalization_confidence, rule_confidence)` as a function to
   implement; §13.4 sets the 70% REVIEW threshold; §12 fixes the evidence-key list and
   the PASS/FAIL/REVIEW enum.
3. **Internal consistency**: two evaluators answering "does control X pass?" for the
   same input must agree, otherwise the verdict depends on which code path ran;
   one run must expose one score (§12 `ComplianceResult.overall_score` is singular).
4. **Self-declared behaviour**: `execution.py`'s own docstrings and the
   `we trust the caller` comment (`execution.py:164-165`) are checked against what the
   spec says selection must be based on (detection, §9.1 step 4).
5. **Consequences, not just clauses**: a defect counts only when it changes an observable
   outcome - controls silently dropped, rows mislabelled, a wrong verdict, a score a
   downstream consumer can misread.

## 6. Hypotheses (16 CONFIRMED, 15 REJECTED, 0 unverifiable)

**CONFIRMED**

- **H07-01** framework selection is a no-op: `framework`/`framework_version` are declared
  but never read, so the API's framework request cannot select rules and
  framework_version is never persisted (V07-17/55; probe: CIS=NIST=BOGUS = 179 identical
  results).
- **H07-02** control selection depends on caller casing: registry keys are exact-case, so
  `vendor="Cisco"` silently drops all 53 CIS controls (126 instead of 179) and
  `platform="JUNOS"` drops all 17 juniper controls; only cisco's `ios->ios_xe` alias is
  normalized (V07-14/15/16).
- **H07-03** the controls API cannot filter: a vendor-only request ignores vendor and
  returns all 70 CIS controls, `platform=ios` returns 0 (alias missing), and the
  registry's platform-only filter ignores platform (106 instead of 51)
  (V07-19/20/21).
- **H07-04** three operator vocabularies drift (spec/enum vs engine vs registry): the
  spec's `in` is unimplemented, the registry has no `*_or_equal` branch and falls
  through to equality (wrong verdicts for 3 juniper controls), unknown operators
  silently evaluate as equals (V07-07/08/33/34).
- **H07-05** six controls (1.2.6/1.2.7/1.2.8/2.1.3/AC-2(3)/SC-10) target model paths
  that do not exist in the Universal Security Model, so they are permanently REVIEW, and
  a duplicate `control_id` silently overwrites the lookup index while both per-vendor
  lists keep their rows (V07-05/10).
- **H07-06** framework attribution is derived, not stored: controls carry no framework
  field, persistence infers it from the control-id shape, a user who requests NIST gets
  CIS rows labelled NIST (and `reports.py` filters on that label), the API advertises
  versions no control carries, and the report list hardcodes `CIS`
  (V07-03/25/57/58/62).
- **H07-07** the §13.3 step 4 confidence model is unimplemented: no rule-confidence
  field, normalization confidence never propagated (constant 0.0), result confidence is
  a hardcoded constant, and the §13.4 <70% REVIEW trigger exists only in the dead legacy
  path (V07-43/44).
- **H07-08** evidence chains deviate from §12/§13.3: `raw_config`/`parsed_value`/
  `security_control`/`reasoning` missing from the canonical evidence, persisted
  `parsed_value` is None on all rows, a multi-block decisive result leaves
  `normalized_value` null, two decisive controls carry no raw evidence lines, and
  regex-only controls PASS/FAIL with no normalized value (V07-37/38/46/47/48/49).
- **H07-09** one audit run exposes two overall scores - 46.9 (passed/evaluated, persisted)
  vs 95.5 (passed/(passed+failed), evaluation object) - REVIEW counted in one,
  excluded from the other (V07-42; probe 84/4/91).
- **H07-10** SEPARATE RECORD (category G): wrong/unsupported inputs produce verdicts -
  the engine trusts its caller over detection, unsupported vendors get NIST verdicts
  from raw text (including decisive FAILs), and an empty configuration yields two
  decisive FAILs instead of REVIEW (V07-72/73/74/75; corpus section 7).
- **H07-11** two control systems coexist with drift: legacy loader (10 CIS-only controls,
  no NIST) vs canonical 196; `ios` vs `ios_xe` platform labels make legacy rules
  inapplicable; applicability contracts differ (case-insensitive vs exact); `is_set`
  and `regex_match` semantics disagree (V07-63/65/66/67/69/70).
- **H07-12** persistence drifts from the spec: stored results are lowercase
  (`"pass"` vs §12 PASS), and the link column/precision differ from the spec DDL -
  which itself disagrees with the spec-12 interface (V07-59/60).
- **H07-13** unknown vendors are silently parsed with `CiscoIOSParser`
  (`executor.py:116-128`), so detection, parsing and normalization disagree about the
  device (V07-83).
- **H07-14** hostile inputs lose their error signal: None surfaces a raw
  `AttributeError` string, an invalid config fails with the validation step marked
  `completed` and no recorded reason, and an invalid `audit_regex` yields a confident
  FAIL for every input (`execution.py:677-678` swallows `re.error`) (V07-91/92/93).
- **H07-15** dead rule data remains in the tree: `framework_mappings.py` has zero
  referencing modules and the executor still imports the retired
  `ControlLoader`/`RuleEngine` without using them (V07-68/71).
- **H07-16** result metadata understates the dual baseline: `benchmark_id` comes from
  `controls[0]`, so a run that evaluated 126 NIST controls alongside CIS is labelled as
  a single CIS benchmark (V07-26).

**REJECTED**

- **H07-17** "selection loses or duplicates controls under normal inputs" - rejected:
  cisco -> 179 (53+126), juniper -> 143 (17+126), alias works, no duplicate evaluations
  (V07-11/12/13/27).
- **H07-18** "supported operators' truth tables are wrong" - rejected: equals,
  not_equals, contains, numeric comparisons and `*_or_equal` (in the canonical engine)
  all implement §13.3 semantics (V07-28/29/30/31/32).
- **H07-19** "verdicts are fabricated from missing/manual input" - rejected: absent
  values -> REVIEW, manual controls always REVIEW, no PASS on an empty file
  (V07-35/36/39/76/77/78).
- **H07-20** "evaluation is non-deterministic" - rejected: identical verdicts, scores
  and registry statistics across repeat runs and engine instances (V07-85/86/87).
- **H07-21** "the offline pipeline does not run end to end / findings are not wired" -
  rejected: INGEST->...->FINDINGS runs with no external service, findings derive from
  the same evaluation, one row persisted per configuration (V07-79/80/81/82).
- **H07-22** "performance is unusable or super-quadratic" - rejected: ms-level warm
  evaluation, near-linear scaling (factor 1.38 for 2.4x input), unicode-safe
  (V07-88/89/90/95).
- **H07-23** "the API inventory or framework inference is wrong" - rejected: 70 CIS / 126
  NIST served correctly, labels correct for the current inventory, framework filter
  works against the persisted column (V07-22/23/24/56/84).
- **H07-24** "the retired legacy pipeline still executes" - rejected: `RuleEngine`/
  `ControlLoader` are imported but never instantiated (V07-64).
- **H07-25** "confidence or remediation disagree across layers" - rejected: evaluation
  confidence equals persisted evidence confidence; remediation null for PASS, present
  for FAIL (V07-52/53).
- **H07-26** "the loaded inventory misses §13.2 structure/severity/operators/ids" -
  rejected: all structure fields present except framework, severity vocabulary matches,
  operators unique, ids unique (V07-01/02/04/06/09).
- **H07-27** "alias and unsupported-vendor fallback are broken" - rejected: `cisco/ios`
  selects the same 179 as `ios_xe`, unknown vendors fall back to the 126-control NIST
  baseline as §10.7 prescribes (V07-12/18).
- **H07-28** "conflicts/negations produce unsafe verdicts" - rejected: duplicate
  conflicting settings resolve to REVIEW; negated controls invert correctly
  (V07-40/41).
- **H07-29** "persisted score/counts are inconsistent with the evaluation" - rejected:
  persisted audit score equals the engine's `passed/total*100`; counts recomputed from
  rows (V07-45/61).
- **H07-30** "per-row evidence lacks operator/reasoning or is not persisted" - rejected:
  expected/actual/operator recorded, reasoning on every evaluation, JSONB evidence +
  remediation wired through `run_audit_pipeline` (V07-50/51/54).
- **H07-31** "unicode content breaks evaluation" - rejected: CJK comments evaluate
  normally (V07-94).

## 7. Dataset sweep (480 real files, 480 processed, 0 errors)

`scripts/engine_validation/sweep_compliance.py` - detection -> control selection ->
evaluation for every file, per-file CSV plus aggregate summary; 58.4 s total.

### 7.1 Selection and verdicts

| Measure | Value |
|---|---|
| Files | 480 (0 errors, 0 empty, 0 with zero evaluated controls) |
| Selection | CIS+NIST 364, NIST-only 116 |
| Controls evaluated | 179 x 320 files, 143 x 44, 126 x 116 (78,188 verdicts) |
| Verdicts | 6,952 PASS / 15,266 FAIL / 55,970 REVIEW |
| mapped (value-based) | 6,579 PASS / 11,667 FAIL / 12,566 REVIEW (30,812) |
| regex-driven (raw text) | 373 PASS / 3,599 FAIL / 43,404 REVIEW (47,376) |
| Detected vendors | cisco 323, juniper 44, unknown 73, fortinet 29, paloalto 11 |

77% of all verdicts (60,480 of 78,188 = 480 x 126) come from the NIST universal controls
(REVIEW-heavy); of the 22,218 decisive
verdicts (PASS+FAIL), **3,972 (17.9%)** were produced by raw-regex decisions - 373 PASS +
3,599 FAIL, none of which saw a normalized value.

### 7.2 Category-G consequences on the corpus

| Flag | Files | Meaning |
|---|---|---|
| `label_detection_mismatch` | **158** | directory label disagrees with the detector - selection therefore follows detection, not the label (5 Juniper-labelled files detected cisco; 33 FRR files detected cisco, ...) |
| `unsupported_vendor_evaluated` | **113** | fortinet (29) / paloalto (11) / unknown (73) files still got NIST verdicts |
| `regex_verdicts_on_unsupported_vendor` | **113** | those verdicts were produced from raw text of a vendor with no mapper |

Unsupported-vendor outcomes: unknown - 73 files, 9,198 evaluations, **146 FAIL (all
regex)**; fortinet - 29 files, 3,654 evaluations, **406 FAIL (58 regex)**; paloalto - 11
files, 1,386 evaluations, **22 FAIL (all regex)**. Zero PASSes: raw-regex controls cannot
verify what they cannot understand, so unsupported vendors accumulate FAILs they cannot
act on. By label: Fortinet 30 and PaloAlto 38 files are NIST-only by construction; FRR 63
(34 CIS+NIST because 33 were detected as cisco, 29 NIST-only); Juniper 41 all CIS+NIST
with 5 detected as cisco; Arista 38 (37 CIS+NIST, detected cisco).

Directory labels are used only to choose content; no detection accuracy is claimed
(Engine 02 owns detection).

## 8. Performance (measurement only - not a readiness score)

| Measurement | Result |
|---|---|
| Engine construction (registry build) | 2.8 ms in-process (probe), 1,688 ms first run cold including imports |
| 179-control evaluation (warm) | 5.4-9.1 ms per config (probe, all vendors) |
| Full executor run (validate+normalize+evaluate+findings) | ~595-600 ms cold, faster warm |
| Scaling with config size | 100 KB = 731 ms; 239 KB = 14.2 s -> factor 1.38 for 2.4x size (super-linear but within the <=2x-per-x bound of V07-90) |
| Corpus sweep | 480 files in 58.4 s (avg ~121 ms/file, incl. detection and interpreter start) |

Evaluation is comfortably synchronous for interactive audits; the sweep cost is dominated
by per-file interpreter/detection overhead.

## 9. Findings

### Blocking (must be fixed before this engine is ready)

**F1 - The framework selection of §9.1 step 6 / §10.7 does not exist: the executor
ignores its `framework`/`framework_version` arguments (H07-01, H07-16).**
- `executor.py:134-135` declares both parameters; neither appears anywhere in the
  `execute()` body (V07-17). The API faithfully forwards the user's choice
  (`audit_execution.py:241-246`) into an argument that cannot affect anything.
- Probe: identical 179 results (same ids, same 84/4/91) for `framework="CIS"`,
  `"NIST"` and even `"BOGUS"` - an invalid framework is not rejected.
- Every run evaluates the hardcoded dual baseline (§13.1 is implemented - as an
  unconditional constant, not as a selection).
- `framework_version` is never read and never written: no persisted row carries it
  (V07-55), so §12 `ComplianceResult.framework_version` is absent end to end.
- Consequence: the product cannot honour a CIS-only or NIST-only audit request, and a
  versioned framework claim in the UI would have nothing to bind to.

**F2 - Control selection and filtering depend on caller casing and on which code path is
used: controls are silently dropped (H07-02, H07-03).**
- Registry lookups join exact-case dict keys (`registry.py:41/63`). Probe: `vendor="Cisco"`
  -> 126 controls (53 CIS gone, score 46.9 -> 1.6); `platform="JUNOS"` -> 126 (17 juniper
  gone); wrong-case registry key -> 0 controls (V07-14/15/16).
- The `ios -> ios_xe` alias exists only in `execution.py:174` and only for
  `vendor_lower == "cisco"`, so no other vendor's platform casing is normalized.
- The API compounds it: `compliance.py:96-103` drops the `vendor` argument entirely on
  vendor-only requests (`GET /frameworks/CIS/controls?vendor=fortinet` returns all 70
  cisco+juniper controls, V07-20), the registry's platform-only filter ignores platform
  (106 instead of 51, V07-19), and the API never applies the alias
  (`platform=ios` -> 0 items, V07-21).
- Consequence: "how many controls ran" is a function of string casing and call site.
  A silent drop produces a low score that looks like a compliance result.

**F3 - Framework labels on persisted rows are inferred from control-id shape and from the
user's request, not from the control - and reports read those labels (H07-06).**
- Controls carry no `framework` field (V07-03); `audit_execution.py:359-362` computes
  `is_nist = id starts with a letter and contains "-"`, else stamps the **audit's**
  requested framework on the row.
- Probe: `is_nist("SEC-5") = True` (any letter-prefixed id becomes NIST), and with the
  audit's framework set to NIST every CIS control 1.1.1... is stored as `framework='NIST'`
  (V07-58) - on a dual-baseline run where §14.3.2 expects both labels side by side.
- `reports.py:54` hardcodes `framework="CIS"` in the list response while `:35-38`
  filters on the persisted column - the list *view* and the list *filter* can disagree
  (V07-62). The API also advertises framework versions (`2024.1/2023.1`) that no loaded
  control carries (`v2.2.1/v2.1.0`, V07-25).
- Consequence: a report filtered by framework answers from mislabelled rows; "CIS" in a
  response body is a literal, not data.

**F4 - Evidence chains do not implement §12 / §13.3 step 3 (H07-08).**
- The canonical `BenchmarkEvidence` carries `raw_config_lines`/`raw_evidence_snippet`/
  `result_reasoning`/`control_id` instead of §12's `raw_config`/`reasoning`/
  `security_control`, and has no `parsed_value` key at all (V07-46).
- The legacy `EvidenceChain` form that is actually persisted does have `parsed_value` -
  always `None` (the executor never sets it, V07-47) - and lacks `security_control`;
  `reasoning` appears as `result_reasoning`.
- 2 of 77 decisive value-based results (AC-4, SC-7) carry neither line numbers nor a
  snippet: `_find_matching_lines` keyword fallback found nothing (V07-48).
- Control 1.2.8's multi-block PASS records `actual_value` but leaves
  `evidence.normalized_value = None` (the single-path branch writes it,
  `_evaluate_multi_block` does not, V07-49).
- 106 regex-driven controls PASS/FAIL with `normalized_value=None` (V07-37/38) -
  §13.3 step 1 says verdicts derive from extracted values; §13.4 says insufficient
  evidence yields REVIEW, yet a regex miss is a decisive FAIL at conf 0.8.
- Consequence: an evidence chain cannot reconstruct "what value was judged" for a
  substantial share of verdicts - the audit trail §10.7 promises is partial.

**F5 - One audit run carries two different overall scores (H07-09).**
- Probe on the sample secure config: 84 PASS / 4 FAIL / 91 REVIEW yields
  **46.9** (`passed/evaluated`, `execution.py:206` - the value persisted at
  `audit_execution.py:446`) and **95.5** (`passed/(passed+failed)`, `executor.py:370`)
  for the same run (V07-42).
- §12 defines a single `ComplianceResult.overall_score`. REVIEW-heavy runs make the gap
  enormous (91 of 179 controls sit out of the second formula): a product showing 95.5
  while the database holds 46.9 is a materially different compliance claim.

**F6 - Wrong/unsupported-vendor inputs produce decisive verdicts (H07-10; category G,
SEPARATE RECORD).**
- The benchmark engine documents "we trust the caller" (`execution.py:164-165`):
  detection exists but is informational - the caller's vendor/platform select the rules
  (V07-72). In production the executor re-detects, so this is reachable when detection
  itself errs: **158 of 480 corpus files** disagree with their directory label
  (section 7.2).
- Cross-vendor PASSes are real: juniper content declared cisco gets 15 PASS including
  2.1.13-2.2.4 (V07-73); cisco content declared juniper gets 7 decisive juniper verdicts
  (probe, V07-72).
- Unsupported vendors (fortinet/paloalto/unknown = 113 corpus files) receive 14,238 NIST
  evaluations from **raw regex on foreign text**, including 574 decisive FAILs they can
  neither fix nor verify (V07-74, section 7.2).
- An empty configuration completes with 126 evaluations and **2 decisive FAILs**
  (CM-7, CM-7(1) - their regex is absent from an empty file) where §13.4 requires
  REVIEW (V07-75).

**F7 - The §13.3 step 4 confidence model and the §13.4 <70% trigger are unimplemented
(H07-07).**
- `BenchmarkControl` has no rule-confidence field; `BenchmarkEvidence.
  normalization_confidence` stays at its 0.0 default on all 179 evaluations; result
  confidences are hardcoded constants (0.95/0.9/0.85/0.8/0.7/0.5) (V07-43).
- The <70% -> REVIEW demotion exists only in `evidence.py:166` of the legacy path, which
  never executes (V07-44/64).
- Consequence: confidence numbers shown on results cannot be composed from their stated
  inputs, and low-confidence normalization can never demote a verdict.

### Secondary findings

- **F8** operator vocabulary drift: three vocabularies (enum, engine, registry) with the
  spec's `in` unimplemented, registry `*_or_equal` silently equals-falling-through
  (probe: `less_than_or_equal` with a present value returns engine PASS vs registry
  REVIEW/FAIL semantics - wrong verdicts for juniper 6.6.1.1/6.6.1.5/6.6.11), and unknown
  operators evaluating as equals in **both** evaluators - probe `T-1` with operator
  `banana` returns FAIL conf 0.95 (V07-07/08/33/34).
- **F9** structure defects: 6 controls target `management.vty.*_timeout` /
  `management.ssh.session_timeout`, which are not model leaves -> permanent REVIEW
  (cross-ref E05 V05-55, upstream context); a duplicate `control_id` overwrites the
  lookup index while both vendor lists keep their rows, so `get_control()` answers with
  the wrong vendor's control (V07-05/10).
- **F10** two control inventories persist (196 canonical vs 10 legacy, legacy has no
  NIST), with platform labels `ios_xe` vs `ios` that make legacy rules inapplicable to
  the detector's own `ios` output, case-insensitive vs exact applicability contracts,
  `is_set('')` True vs False, `regex_match` search vs match, plus a zero-reference
  `framework_mappings.py` and two dead imports (V07-63/65/66/67/68/69/70/71). Impact
  contained today: the legacy path never runs (V07-64) - but it is the path that *has*
  the §13.4 threshold (F7).
- **F11** persistence drift: stored results are lowercase `pass/fail/review` where §12
  mandates PASS/FAIL/REVIEW (counters re-normalize with `.upper()` at
  `audit_execution.py:382-386`); the table's link column is
  `normalized_configuration_id` where the spec DDL says `configuration_id` (the spec's
  §12 interface itself says `normalized_config_id` - an upstream spec conflict recorded
  as-is, not resolved) (V07-59/60).
- **F12** unknown vendors fall through to `CiscoIOSParser` (`executor.py:116-128`):
  arista/paloalto/etc. are parsed as IOS before evaluation ever runs (V07-83); upstream
  normalization context is Engine 05's, cited not re-tested.
- **F13** failure handling: `None` input fails with `'NoneType' object has no attribute
  'strip'` as the user-visible reason; an invalid (NUL) config returns `status=failed`
  with **zero failed steps** - validation is marked `completed` before the early return
  (`executor.py:171-179`), so §9.1 step 1's "report validation errors" never surfaces;
  an invalid `audit_regex` swallows `re.error` and returns FAIL conf 0.8 for every input
  (V07-91/92/93).

### What works

- **Selection under canonical inputs** (H07-17 rejected): cisco -> 53+126 = 179,
  juniper -> 17+126 = 143, `cisco/ios` alias identical to `ios_xe`, NIST fallback for
  vendors with no benchmark (§10.7), vendor+NIST appended without duplicates.
- **Evaluation semantics** (H07-18/19/28 rejected): the supported operator truth tables
  match §13.3; missing values and manual controls always REVIEW; no PASS is fabricated
  (every mapped PASS shows an observed actual); empty files never PASS at the control
  layer; conflicting duplicates -> REVIEW; negated controls invert correctly.
- **Evidence where values exist** (partial): expected/actual/operator/reasoning on every
  mapped evaluation, confidence consistent between evaluation and persisted evidence,
  remediation null for PASS and populated for FAIL, JSONB evidence+remediation persisted
  per control (V07-50/51/52/53/54).
- **Pipeline integration** (H07-21 rejected): the offline audit pipeline runs
  INGEST->...->FINDINGS with no external service, findings derive from the same
  evaluation, one compliance row per configuration, the report framework filter queries
  the real column, the API serves the full 70 CIS / 126 NIST inventory (V07-79..82/84).
- **Determinism** (H07-20 rejected): identical verdicts, scores and registry statistics
  across repeat runs and fresh engine instances.
- **Performance** (H07-22 rejected): 2.8 ms engine build, 5-9 ms warm evaluation of 179
  controls, near-linear scaling, unicode-safe, comment-padding invariant.
- **The retired legacy pipeline is truly retired** (H07-24 rejected): imported but never
  instantiated (V07-64).
- **Persisted score/counts are self-consistent** (H07-29 rejected): audit score equals
  `passed/total*100`, counts recomputed from rows (V07-45/61).

## 10. Cross-engine baseline (E01-E06 artifacts, read-only)

- Engine 01 (PARTIAL), 02 (FAIL), 03 (FAIL), 04 (FAIL), 05 (FAIL), 06 (FAIL): E07's
  category G cites detection only as *upstream context* where selection follows it
  (158 label mismatches) - detection accuracy is Engine 02's claim, not re-tested here;
  Engine 05's normalization gaps are cited where an unmapped path forces regex verdicts
  (V07-74) - never assumed fixed, never re-tested.
- Full suite before E06: 845 collected / 819 passed / 26 failed -> after E06:
  950 / 924 / 26 -> after E07: **1045 / 1019 / the same 26 pre-existing failures**
  (95 new tests). Failure composition unchanged: 6 `test_benchmark_execution.py`, 2
  `test_detection.py`, 2 `test_frontend_integration_support.py`, 7
  `test_juniper_benchmark.py`, 2 `test_phase5_integration.py`, 6
  `test_phase8_hardening.py`, 1 `test_vertical_slice.py::test_cisco_ios_full_pipeline`.
- `git diff -- backend/app/` **empty**; `git status --porcelain -- backend/app/`
  **empty**. Working tree matches the recorded pre-existing baseline (requirements.txt,
  frontend package files, plus the untracked validation/artifacts/scripts directories).
- New files only: `tests/validation/test_v07_compliance.py`,
  `scripts/engine_validation/{sweep,report}_compliance.py`,
  `artifacts/engine_validation/07_compliance/*`, plus the conftest engine mapping for
  `07_compliance`.

## 11. NOT APPLICABLE / NOT VERIFIABLE

- **ML model quality** - deferred by instruction (engines validated before ML).
- **Detection accuracy** - Engine 02 owns it; this engine records only that selection
  follows detection (category G, section 7.2).
- **Normalization correctness for mapped paths** - Engine 05 owns it; cited as upstream
  context where the absence of a mapper forces raw-regex verdicts.
- **The "correct" overall_score formula** - the repo deliberately implements two (the
  spec says "a single number" but not which denominator); recorded as a dual-value defect
  (V07-42), not resolved to one formula.
- **Whether `configuration_id` or `normalized_configuration_id` is the intended link
  column** - the spec contradicts itself (§12 interface vs §15 DDL); recorded as drift,
  not adjudicated.
- **Registry `evaluate_control` production reachability** - the vocabulary/semantics
  defects (V07-33/34) are established against the API-facing registry; the sweep uses
  the canonical engine path. No live API request-log evidence was collected.
- **Concurrency, locking, transactional behaviour** - all probes single-threaded.
- **Authentication/authorization testing** - not in this engine's contract.
- **Postgres write performance at audit volume** - persistence was verified for
  correctness on small runs; no bulk-insert benchmark was run.

## Limitations of this validation

- Corpus sweep uses detection output as *input*, not as truth; `label_detection_mismatch`
  compares directory labels with the detector and does not decide who is right.
- Category G probes exercise the benchmark engine's public contract with a declared
  vendor; production reachability through the executor (which re-detects) is noted per
  finding (F6).
- Confidence measurements reflect the code's constants; there is no ground truth for
  what confidence *should* be, only whether the spec's formula was implementable (it is
  not - no inputs exist).
- Performance numbers are single-machine measurements, not a readiness score.
- Hypothesis conclusions derive only from the recorded evidence rows; no claim goes
  beyond them.

---

## 12. Verdict

**FAIL - NOT READY.** Seven blocking findings:

| | Finding | Evidence |
|---|---|---|
| F1 | Framework selection does not exist - `framework`/`framework_version` ignored, no version persisted, CIS=NIST=BOGUS identical | V07-17/55, H07-01 |
| F2 | Selection/filters depend on caller casing and call path - 53/17 controls silently dropped, API drops filter arguments | V07-14/15/16/19/20/21, H07-02/03 |
| F3 | Framework labels inferred from id shape + user request; report list hardcodes `CIS`; advertised versions don't exist | V07-03/25/57/58/62, H07-06 |
| F4 | Evidence chains deviate from §12/§13.3 - missing keys, parsed_value never set, decisive results without raw evidence or normalized_value, regex PASS/FAIL | V07-37/38/46/47/48/49, H07-08 |
| F5 | Two overall scores per run: 46.9 persisted vs 95.5 in the evaluation object | V07-42, H07-09 |
| F6 | Wrong/unsupported-vendor inputs yield decisive verdicts - caller-trust, 574 corpus FAILs on unsupported vendors, empty config -> 2 FAILs | V07-72/73/74/75 + corpus 7.2, H07-10 |
| F7 | Confidence model unimplemented: no rule confidence, normalization confidence constant 0.0, <70% trigger only in dead path | V07-43/44, H07-07 |

Secondary: F8 operator vocabulary drift with silent equals-fallback, F9 broken model paths
+ duplicate-id overwrite, F10 dual control inventories with semantic drift, F11
persistence/schema drift (lowercase enums, DDL column), F12 Cisco-parser fallback for
unknown vendors, F13 hostile-input error signals lost.

What is solid: deterministic verdicts and scores, correct operator truth tables,
no fabricated verdicts (missing/manual/empty -> REVIEW), an end-to-end offline pipeline
with findings wired, correct inventory for the canonical paths, ms-level warm performance
with near-linear scaling, and a genuinely retired legacy execution path. The blocking
problems are selection reliability, framework attribution, evidence completeness, score
single-ness, wrong-vendor consequences, and the missing confidence model - not speed or
determinism.
