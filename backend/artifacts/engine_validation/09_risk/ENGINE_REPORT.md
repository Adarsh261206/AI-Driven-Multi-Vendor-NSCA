# Engine 09 — Risk Engine (spec §10.9) — ENGINE REPORT

**Verdict: FAIL / NOT READY**
Validation date: 2026-09-26 · Evidence rows: 87 (48 FAIL / 39 PASS) · Hypotheses: 19 (14 CONFIRMED / 5 REJECTED, 0 unreferenced rows) · Corpus sweep: 480/480 files, 71,236 findings, 0 errors
Artifacts: `backend/artifacts/engine_validation/09_risk/` (raw_results.jsonl, test_results.csv, dataset_results.csv, dataset_summary.json, performance.csv, determinism_results.csv, security_results.csv, summary.json)
Production code changes: **none** (`git diff -- backend/app/` empty)

---

## 1. Method

One engine per approval cycle, methodology unchanged since Engine 01 (spec §5 "Testing Strategy"):

- **Ground rules held**: no edits under `backend/app/**`; detector output never treated as ground truth; wrong/unsupported-vendor consequences recorded only in category **G** as a separate, explicitly labelled record; classification vocabulary restricted to `CONFIRMED BEHAVIOR | BUG | MISSING | DESIGN LIMITATION | RECOMMENDATION`; statuses restricted to PASS/FAIL; no numeric readiness score invented; no fabricated "industry standard" claims (§5 below names the source of every expectation).
- **Assertion convention**: conformance claims assert `ok`; defect claims compute conformance and assert `not ok` — the pytest run passes either way, while the recorded row carries PASS/FAIL truthfully.
- **Evidence chain**: every row in `test_results.csv` carries requirement, input, expected, actual, status, classification, evidence and recommendation, produced by `tests/validation/test_v09_risk.py` (87 tests) via the shared recorder; the dataset sweep (`scripts/engine_validation/sweep_risk.py`) re-runs the production path (`AuditExecutor.execute`, exactly as the audit API wires it) over the whole corpus; `scripts/engine_validation/report_risk.py` assembles the CSVs and `summary.json`, and **fails the build if any non-PASS row is not referenced by a hypothesis** (0 unreferenced).
- **Upstream engines (01–08)**: their findings are cited as *upstream context only* (e.g. E07 V07-42 dual score, E08 G attribution flags); none were re-tested here.
- **Environment**: `backend/venv` Python 3.13.5, corpus `C:\Users\priye\Downloads\SIH Config\final-dataset` (480 files, 9 vendor directories), ML risk model available in this environment (`risk_model.joblib` loads; `get_risk_predictor() → available=True`).

## 2. Contract under test

Primary: **spec §10.9 Risk Engine** (spec:551–562):

| Element | Spec text |
|---|---|
| Purpose | "Calculate risk scores for findings" |
| Responsibilities | "Apply risk calculation formula" (:556) · "Consider severity, impact, confidence" (:557) · "Generate priority rankings" (:558) · "Calculate overall compliance score" (:559) |
| Input | `Findings` (:561) |
| Output | `RiskAssessment` (:562) |

Supporting contract points: §4.2 table assigns **"Risk score calculation" to the Deterministic Engine** (:158); §8 pipeline step "10. Risk Engine calculates risk scores" (:328); §18.2 file tree expects `compliance/risk.py` (:1322); §18.3 background sequence "# 8. Calculate risk scores" (:1361); §20.2 endpoint list (:1510–1556); §20.7 UI routes (:1183–1191); §30.3 Phase 3 deliverable "- [ ] Risk calculation" (:1968); §4.3 principle 2 "Deterministic Compliance: No black-box security decisions" (:160).

**Important**: the spec never defines the risk formula (the only "formula" occurrence is the responsibility bullet itself), never defines the priority vocabulary (P1–P4 appear in the spec only as *feature* priorities at :1689–1704), and never defines the `RiskAssessment` interface beyond naming it as the output.

## 3. Observed behavior (code reality)

1. **There is no Risk Engine module.** Risk lives in `app/engines/compliance/findings.py::SeverityCalculator` (:67–150) — inside the Finding Engine, contradicting §10.9/§18.2. No `RiskEngine` class, no `risk.py`, no `RiskAssessment` type anywhere in `app/`.
2. **Two scoring vocabularies run in one function.** `calculate_risk_score(severity, vendor, category, confidence)` (:103) tries the RandomForest first (`get_risk_predictor()`, 4 features `[severity_num, vendor_mult, category_mult, confidence]`, clamp [0,100], round 1dp) and only falls back to the documented deterministic formula `base × vendor × category × max(conf, 0.5) / 15.6 × 100` (:133–143) on exception. The model is trained (`app/ml/train_all_engines.py::train_risk`) on **2,000 synthetic rows generated from a *different* formula** (`conf_factor = 0.8 + 0.4c`, 13-key title-case category vocab, 5-key vendor vocab) plus gaussian noise, seed 42; `risk_meta.json` reports r²=0.992 against that synthetic holdout.
3. **Priority** = `calculate_priority(risk_score)` (:145–150) with coded thresholds P1≥80, P2≥60, P3≥40, P4 otherwise (catch-all, never empty). Nothing in the spec defines these bands.
4. **`_create_finding`** (:198–247) computes risk from `ControlEvaluation` fields (:209) **before** the `Finding` is constructed (:230), attaches `risk_score`/`priority` to the in-memory dataclass — and the values are then dropped by every downstream layer: no `findings.risk_score`/`priority` column (model + alembic 001), no `FindingResponse` field, no persistence write, no summary aggregate, no report rendering, **zero** references across `app/api/**`.
5. **Overall compliance score** (§10.9 responsibility 4) is computed as `passed/total×100` in `engine.py:54/146/148` and `executor.py:69/248` (and `audit_execution.py`), never by any risk component.
6. **Integration surfaces claim ML risk**: pipeline step desc "ML risk scoring (RandomForest)" (audit_execution.py:434) and PDF footer "Risk Scoring: RandomForest (R² …)" (reporting.py:464) — the footer is gated on `ml_info.get("available")`, which is the **vendor detector's** flag, not the risk model's.

## 4. Results by category

| Cat | Area | Rows | PASS | FAIL | Main signal |
|---|---|---|---|---|---|
| A | spec structure (§10.9/4.2/8/18.2/18.3/30.3) | 12 | 2 | 10 | No risk module/stage/class/RiskAssessment; spec formula & priority vocabulary undefined; §4.2 deterministic vs ML-first |
| B | formula & ML behavior | 14 | 12 | 2 | Formula arithmetic correct on its own terms; **ML diverges up to 29.9 pts**; confidence non-monotonic on ML path |
| C | priority rankings | 7 | 7 | 0 | Boundaries exact, never empty, consistent — **and E08 F10 corrected** |
| D | impact considerations | 5 | 3 | 2 | Multipliers work mechanically, but **category impact is inert for 100% of production categories** (case + vocab mismatch) |
| E | persistence/exposure of 10.9 output | 10 | 1 | 9 | Computed then discarded at every layer (model, migration, schema, summary, reports, API) |
| F | training/serving drift | 8 | 2 | 6 | Different confidence transform (20% gap), different vocabularies, synthetic labels, r² measured on synthetic holdout |
| G | SEPARATE RECORD: wrong/unsupported vendor | 5 | 0 | 5 | Attribution-keyed multipliers distort risk ±10–20% and can shift priority bands |
| H | fidelity guarantees | 5 | 5 | 0 | Range/band/rounding/typing guarantees hold — including on hostile values |
| I | pipeline/report/spec integration | 7 | 1 | 6 | No risk stage; overall-score responsibility unowned; input contract violated; PDF claim wrong guard |
| J | determinism | 3 | 3 | 0 | Repeatable across ML grid, formula, and full generation |
| K | performance | 3 | 3 | 0 | ML predict p50 8.79 ms (sanity bound 25 ms), formula 0.0015 ms |
| L | hostile/boundary input | 7 | 0 | 7 | Crashes (None) and silent corruption (NaN→100.0→P1, string severity −33%) |
| M | user-facing exposure | 1 | 0 | 1 | Frontend never renders risk_score/priority |
| **Total** | | **87** | **39** | **48** | classifications: 39 CONFIRMED BEHAVIOR · 22 MISSING · 15 DESIGN LIMITATION · 11 BUG |

## 5. Expectations (and where each comes from)

No industry-standard claims are invented below. Each expectation names its source: **[S]** = explicit spec text, **[C]** = internal-consistency requirement derived from the spec's own principles, **[P]** = general software-engineering practice (labelled as such, not as a standard).

- **E1 [S]**: the component, file and output type named by §10.9/§18.2 exist (`risk.py`, a risk calculation stage, `RiskAssessment`).
- **E2 [S]**: all four §10.9 responsibilities are implemented: formula, severity/impact/confidence, priority rankings, overall compliance score.
- **E3 [S]**: scoring follows §4.2's assignment (deterministic engine handles risk calculation) and §4.3's "no black-box security decisions".
- **E4 [C]**: a score shown with a priority band has **one** meaning — the value and its band must agree regardless of code path (derived from §4.3 determinism and from §10.9 listing score and rankings as one output).
- **E5 [S]**: the §10.9 output reaches its consumers — storage (§14), API (§20.2), UI (§20.7, CISO "risk summary" :130) — since §10.9 names Input/Output like every other engine.
- **E6 [S/C]**: "impact" applies to the vendors and categories the system actually audits (§1 multi-vendor scope; §10.9 "consider … impact").
- **E7 [P]**: invalid inputs are rejected with a clear error, never crashing with an internal exception type and never silently producing a wrong value.
- **E8 [P]**: a model's training inputs, label transform and vocabularies match its serving inputs; accuracy metrics state what they were measured against.
- **E9 [S/C]**: identical inputs produce identical outputs (§4.3 deterministic compliance spirit).
- **E10 [P]**: per-finding scoring cost stays negligible relative to the pipeline (sanity bound used since E08: <25 ms/finding; **no spec latency requirement exists** — this is a sanity check, not a conformance claim).

## 6. Hypotheses (19)

Full statements and evidence lists in `summary.json`. Conclusion rule: CONFIRMED if ≥1 linked row FAIL, else REJECTED.

| ID | Claim (abridged) | Conclusion | Evidence |
|---|---|---|---|
| H09-01 | The §10.9 Risk Engine does not exist as a component: no `risk.py` (spec:1322), no class, no pipeline stage (spec:328/1361); logic embedded in Finding Engine | **CONFIRMED** | V09-01, 04, 08*, 09*, 10, 11, 12 |
| H09-02 | `RiskAssessment` undefined in spec (single mention :562) and absent from code | **CONFIRMED** | V09-02, 03 |
| H09-03 | Spec mandates a formula and priority rankings but defines neither | **CONFIRMED** | V09-06, 07 |
| H09-04 | §4.2 says deterministic; production is ML-first with the model available and the step text advertises ML | **CONFIRMED** | V09-05, 68* |
| H09-05 | Two scoring vocabularies: ML vs formula differ on 100% of 71,236 corpus findings (>1 pt), 65.2% band mismatch; unit max 29.9/mean 13.2 | **CONFIRMED** | V09-19, 25* |
| H09-06 | ML confidence ordering broken (severity ordering holds) | **CONFIRMED** | V09-20*, 21*, 22 |
| H09-07 | Category impact inert: 28 production categories, 0 overlap with impact keys; case-sensitive lookup | **CONFIRMED** | V09-34, 35 |
| H09-08 | 10.9 output computed then discarded at model/migration/schema/persistence/summary/report/API | **CONFIRMED** | V09-39…47, 48* |
| H09-09 | Training/serving drift: transforms differ (20% gap at conf=1.0), vocabularies differ, synthetic labels, synthetic-holdout r² | **CONFIRMED** | V09-49…54, 55*, 56* |
| H09-10 | **(G)** vendor attribution distorts risk: +9.1% wrong-vendor inflation, −16.7% unsupported understatement, 4/9 vendor coverage, P2↔P3 band shifts, sweep delta up to +20.0% on 158 files | **CONFIRMED** | V09-57…61 |
| H09-11 | Hostile inputs crash (None vendor/confidence) or silently corrupt (NaN→100.0, −1/1000 accepted, string severity 32.1 vs 48.1) | **CONFIRMED** | V09-80…86 |
| H09-12 | No exposure surface: no stage, no §20.2 endpoint, no §20.7 route, frontend 0 hits, PDF claim guarded by vendor-model flag | **CONFIRMED** | V09-67, 69, 70, 71, 87 |
| H09-13 | "Calculate overall compliance score" has no risk-component owner (computed in engine/executor/API; E07 V07-42 upstream context) | **CONFIRMED** | V09-72 |
| H09-14 | Input contract violated: risk computed from `ControlEvaluation` before the Finding exists | **CONFIRMED** | V09-73 |
| H09-15 | Banding itself defective (boundaries, empty priorities, consistency, reachability) | **REJECTED** | V09-27…33 all PASS |
| H09-16 | Fidelity guarantees violated (range/band/rounding/typing) | **REJECTED** | V09-62…66 all PASS |
| H09-17 | Scoring non-deterministic | **REJECTED** | V09-74…76 all PASS |
| H09-18 | Performance beyond sanity bounds | **REJECTED** | V09-77…79 all PASS |
| H09-19 | Severity/impact/confidence considerations missing entirely | **REJECTED** | V09-13…18, 23, 24, 26, 36–38 all PASS |

\* PASS rows inside confirmed hypotheses (context/evidence).

**Totals: 14 CONFIRMED, 5 REJECTED.** All 48 FAIL rows referenced; all 87 rows referenced by ≥1 hypothesis (0 unreferenced).

## 7. Dataset sweep (production path, 480/480 files, 0 errors, 884.3 s)

**Risk & priority distribution (71,236 findings — identical count to E08's sweep):**

| Metric | Value |
|---|---|
| risk range observed | **17.2 – 68.7** (0 out-of-range, 0 scored zero) |
| P1 | **0** (0.0%) |
| P2 | 19,396 (27.2%) |
| P3 | 27,201 (38.2%) |
| P4 | 24,639 (34.6%) |
| empty priority | **0** |

- **E08 F10 correction (recorded in `summary.json.e08_correction`)**: E08 reported "24,639 empty priorities". `calculate_priority` never returns an empty string (P4 catch-all), and this sweep counts **exactly 24,639 P4 and 0 empty** — the E08 "other/empty" bucket was P4. E08's priority numbers are otherwise confirmed unchanged (P2/P3 match E08's 19,396/27,201).
- Corpus risk never reaches the P1 threshold (max 68.7): production category impact never applies (all multipliers 1.0) and confidences <1.0 cap the achievable score — the top band exists only in unit grids (V09-32: max 98.6 reachable in principle).

**ML vs deterministic formula (per finding, formula recomputed from the same evaluation inputs):**

| Metric | Value |
|---|---|
| findings compared | 71,236 |
| differing by >1 point | **71,236 (100%)** |
| max of per-file maxima | 29.4 pts (mean of file maxima 28.32) |
| priority band mismatches (ML band ≠ formula band) | **46,451 (65.21%)** |
| files with ≥1 band mismatch | **480/480** |

**Category G (separate record):**

| Flag | Files |
|---|---|
| `wrong_vendor_attributed` | 158 (matches E08's 158 exactly) |
| `risk_vendor_unsupported` (detected vendor outside `VENDOR_IMPACT`) | 73 |
| `priority_band_shift_between_vocabularies` | 480 |
| label-vendor re-score delta | up to **+20.0%** (158 files) |

Per-vendor (findings, P2/P3/P4): Cisco 39,369 (12,061/15,334/11,974) · FRR 9,176 · Arista 6,056 · Juniper 5,532 · PaloAlto 4,788 · Fortinet 3,780 · F5 1,511 · NAPALM 583 · A10 441. Every vendor directory produced P1=0, empty=0.

## 8. Performance (measurement only)

| Source | Measurement | Result |
|---|---|---|
| V09-77 | ML `calculate_risk_score` per call (200 warm calls) | p50 **8.79 ms**, p95 11.92 ms, max 36.00 ms — within the <25 ms/finding sanity bound |
| V09-78 | Formula path (1,000 calls, ML off) | p50 **0.0015 ms** |
| V09-79 | `generate_findings` on 100 evaluations (ML path) | 914 ms (~9.1 ms/finding incl. evidence assembly) |
| Sweep | full executor, 480 files | p50 1816.2 ms / p95 2196.1 ms / max 5637.4 ms, total 884.3 s |
| Sweep | risk formula re-probe over all findings | p50 0.5 ms / p95 0.9 ms per file |

Note: E08's sweep of the same corpus measured p50 878.2 ms / total 451.8 s. The identical pipeline with an added ~0.5 ms/file arithmetic probe measured ~2× slower in this session; the difference is environmental (session load), not attributable to risk code — risk-specific cost is isolated in the rows above.

## 9. Findings

### Blocking (any one keeps the engine NOT READY)

**F1 — The §10.9 output is computed and discarded (H09-08).** `risk_score`/`priority` exist only on the in-memory dataclass: no DB column (V09-39/40), no migration (41), no `FindingResponse` field (42/43), no persistence write (44), no summary aggregate (45), no report rendering (46), zero API references (47). A risk assessment that never reaches storage or any consumer cannot satisfy "Output: RiskAssessment". *Classifications: MISSING ×9. Recommendation: add columns + migration + schema fields, or amend §10.9.*

**F2 — Two scoring vocabularies: the model and the documented formula disagree everywhere (H09-05).** Unit grid: max 29.9 / mean 13.2 points (e.g. CRITICAL/cisco: ML 94.3 vs formula 76.9); corpus: **100% of 71,236 findings differ >1 pt** and **65.2% would change priority band** depending on which path serves them. Any user seeing "risk 67" has no way to know it is not the spec-formula's 48. *BUG. Recommendation: pick one normative scorer and derive/delete the other.*

**F3 — The Risk Engine component does not exist, and the spec itself is incomplete (H09-01/02/03).** No `risk.py` (spec:1322), no `RiskEngine`, no risk stage (spec:328/1361), no `RiskAssessment` type in spec or code, no formula and no priority vocabulary anywhere in the spec. The implementation invented thresholds 80/60/40 and a formula the spec never states. *MISSING ×7. Recommendation: deliver §10.9 as specified or rewrite the section to match reality (including defining the formula, bands and output).*

**F4 — §4.2/§4.3 conflict: deterministic assignment vs ML-first production (H09-04).** Spec :158 puts risk calculation in the deterministic column and §4.3 forbids black-box security decisions, yet the code tries RandomForest first (model available here) and the pipeline text advertises "ML risk scoring (RandomForest)". *DESIGN LIMITATION. Recommendation: align spec and code — either direction is defensible, silently doing both is not.*

**F5 — Category impact is inert for every production finding (H09-07).** The 28 categories the system emits (`AAA`, `SSH`, `Logging`, `Access Control`, …) never overlap the six lowercase keys (`ssh`, `logging`, `access_control`, …); even same-word capitalisation misses (`ssh`→83.0 vs `SSH`→67.0). Every finding is scored as categoryless — a whole impact dimension is dead code. *BUG. Recommendation: normalise/extend the key mapping and add a corpus-level assertion of nonzero category effect.*

**F6 — Risk model training/serving drift (H09-09).** Labels come from a different confidence transform (training `0.8+0.4c` vs serving `max(c,0.5)` = 20% gap at c=1.0), different category (13 title-case vs 6 lowercase keys) and vendor vocabularies, on 2,000 **synthetic formula+noise rows**; r²=0.992 is measured against that synthetic holdout, so it evidences formula-regression fit, not risk-prediction quality. *DESIGN LIMITATION. Recommendation: generate labels from the exact serving formula and vocabulary, or present the model honestly as formula emulation.*

**F7 — Hostile inputs crash or silently corrupt the score (H09-11).** `vendor=None` → AttributeError (findings.py:134, outside the ML try/except); `confidence=None` → TypeError; **`confidence=NaN` → 100.0 → P1** (`min(100.0, NaN)` returns 100.0); −1 accepted (58.2); 1000 accepted (67.0); string `"HIGH"` on the formula path scores 32.1 instead of 48.1 (−33%, masked when ML is up, so behaviour differs by path); `severity=None` silently defaulted. *BUG ×7. Recommendation: validate severity/vendor/category/confidence up front (enum + finiteness + range).*

**F8 — (G, separate record) Vendor attribution distorts risk and rankings (H09-10).** Multipliers key on `evaluation.vendor`: same finding scores cisco 76.9 vs juniper 70.5 (**+9.1% inflation** when Juniper content is detected as cisco — E08 measured 158 such files / 22,820 findings); unsupported vendors fall silently to 1.0 (−16.7% vs cisco; only 4 of 9 dataset vendors covered; `unknown` detection = 73 files); the gap crosses band thresholds (HIGH/access_control: cisco 63.5→P2 vs arista 52.9→P3); sweep shows label-vendor re-scoring deltas up to **+20.0%**. *DESIGN LIMITATION ×5. Recommendation: derive vendor impact from verified content evidence and document the neutral default.*

**F9 — No exposure surface for risk anywhere (H09-12).** No §20.2 risk endpoint (and zero `risk_score` in `app/api`), no §20.7 UI route (CISO persona expects a "risk summary", spec:130), frontend renders neither field (`scoreRisk()` labels the *compliance* score — a different quantity), and the PDF's "Risk Scoring: RandomForest" claim is gated on the **vendor detector's** availability flag. *MISSING/DESIGN LIMITATION. Recommendation: expose the fields and gate each claim per model.*

**F10 — Ownership and input-contract gaps (H09-13/14).** Responsibility 4 "Calculate overall compliance score" has no risk-component implementation (scores computed in `engine.py:54/146/148`, `executor.py:69/248`; upstream context: E07 V07-42 dual score 46.9 vs 95.5 — not re-tested); §10.9's Input=`Findings` is violated because risk runs on `ControlEvaluation` at findings.py:209 before the Finding exists at :230. *MISSING/DESIGN LIMITATION.*

### Secondary

**S1 — ML confidence non-monotonicity (H09-06, BUG).** MEDIUM: 47.0 (conf 0.9) → **45.5** (conf 1.0); LOW: 20.8 (0.7) → **20.5** (0.8). Higher confidence can lower risk; the formula path guarantees ordering, the ML path does not — same family as F2's vocabulary split. (Severity ordering itself: 0/48 violations — holds.)

### What works (evidence-backed)

- **Priority banding is correct on its own terms (H09-15 rejected)**: exact boundary behaviour at 80/60/40, out-of-range scores clamped to P1/P4, **never empty** (1,001-value sweep + 71,236 corpus findings), every band equals the band of its own score, P1 reachable in principle (98.6). **This closes E08 F10 with a correction**: the "24,639 empty priorities" were P4.
- **Fidelity guarantees hold (H09-16 rejected)**: all 96-grid scores and all hostile-value scores within [0,100], priorities always in P1–P4, 1-decimal rounding, native floats.
- **Deterministic (H09-17 rejected)**: ML grid ×3, formula ×2, full generation ×2 all identical (finding ids aside).
- **Performance sane (H09-18 rejected)**: ML p50 8.79 ms/finding, formula 0.0015 ms, 100-finding generation 914 ms.
- **Considerations exist and work mechanically (H09-19 rejected)**: severity bases 64.1/48.1/32.1/16.0 correct; vendor multipliers apply (ratios 1.2/1.1 exact); confidence factor + 0.5 floor + 15.6-normalisation cap all behave as coded; ML path honours vendor (67.0 vs 61.4) and category (83.0 vs 67.0) inputs; feature order and training seeds aligned; the in-memory `Finding` does carry both fields; the pipeline step honestly discloses ML risk scoring (true while the model is available).

## 10. Cross-engine baseline

| Engine | Area | Verdict |
|---|---|---|
| 01 | Configuration Ingestion | PARTIAL |
| 02–08 | Validation → Findings | FAIL |
| **09** | **Risk (§10.9)** | **FAIL / NOT READY** (this report) |
| 10–12 | Remediation, audit execution, reporting | pending approval |

Full suite after E09: **1223 collected, 1197 passed, 26 failed** (3:23) — the same 26 pre-existing failures as the E08 baseline (test_benchmark_execution 6, test_detection 2, test_frontend_integration_support 2, test_juniper_benchmark 7, test_phase5_integration 2, test_phase8_hardening 6, test_vertical_slice 1); delta vs E08: +87 collected, +87 passed, failures unchanged. `git diff -- backend/app/` remains empty; artifact set matches the E01–E08 file contract.

## 11. Not applicable / not verifiable

- **NOT APPLICABLE**: DB-backed tests (none of §10.9's behaviour requires the throwaway DB — risk is computed pre-persistence and never stored, which *is* finding E/F); spec §20.2 risk endpoint conformance (the endpoint does not exist in spec — tested as MISSING, not NV).
- **NOT VERIFIABLE**: real-world risk-prediction accuracy (no labelled outcomes exist anywhere in the repo or dataset — the model's r² measures agreement with its own synthetic generator, F6); end-user perception of rankings (no UI renders them, F9); whether the vendor-detection attribution errors themselves are wrong is E03/E07 territory — category G here only records their *risk-score consequences*.

## Limitations

1. ML-path numbers depend on the shipped `risk_model.joblib` (sha of this environment); if artifacts are retrained, B/F rows should be re-run (seeds are fixed at 42, so regeneration should be reproducible).
2. Formula re-computation in the sweep zips non-PASS evaluations with findings by order (verified per file: `zip_mismatch` would have been flagged; 0 occurred); category is taken from the evaluation, matching `_create_finding`'s own input.
3. The sweep measures whole-executor time; risk-specific cost is isolated only by the separate recalc probe and unit timings.
4. Expectations E7/E8/E10 are labelled engineering practice [P], not standards; E3/E5 rely on spec text that this project could legitimately amend — the conflict itself (F3/F4) is the reportable fact.
5. Upstream defects (E07 dual score, E08 attribution/evidence gaps) are cited as context only and were not re-tested.

## 12. Verdict

**FAIL / NOT READY.** 14 of 19 hypotheses confirmed, 48 of 87 evidence rows failing across every dimension the spec's §10.9 names: the component does not exist (F3), the output is discarded before storage or display (F1), two scoring vocabularies disagree on every finding in the corpus (F2), a whole impact dimension is inert (F5), the model trains on drifted synthetic labels (F6), hostile inputs crash or manufacture maximum risk (F7), vendor attribution distorts rankings (F8), no consumer can see any of it (F9), and two spec responsibilities have no owner (F10). What works — banding correctness, fidelity, determinism, performance, mechanical impact handling — is real and now evidence-backed, and E08's "empty priority" claim is formally corrected to P4. The engine cannot be marked ready until at least F1–F3 are resolved and the spec/implementation conflict in F4 is decided.

*Next in sequence after approval: Engine 10 — Remediation Engine (§10.10).*
