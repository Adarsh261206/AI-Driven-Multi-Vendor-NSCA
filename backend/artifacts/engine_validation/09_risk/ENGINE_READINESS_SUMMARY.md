# Engine 09 Readiness Summary — Risk Engine (spec §10.9)

**Verdict: FAIL / NOT READY** · 87 evidence rows (48 FAIL / 39 PASS) · 19 hypotheses (14 CONFIRMED / 5 REJECTED, 0 unreferenced) · sweep 480/480 files, 71,236 findings, 0 errors · full suite 1223/1197/26 · `backend/app/` untouched

---

## TL;DR

The spec's Risk Engine doesn't exist as a component — risk scoring hides inside the Finding Engine, the `RiskAssessment` output is neither specified nor produced, and the score it does compute is thrown away before storage, API, report or UI. Worse, two different scoring vocabularies run in the same function: the RandomForest and the documented formula disagree on **100% of 71,236 corpus findings**, flipping **65.2% of priority bands**. On top of that the category-impact multiplier matches **0 of 28** production categories (dead code), the model trains on synthetic labels from a *different* confidence transform, and hostile inputs can manufacture a P1 out of a NaN. What is solid: priority banding itself (boundaries, consistency, never-empty — which **formally corrects E08 F10**), fidelity guarantees, determinism and performance.

## The contract (§10.9, spec:551–562)

- Purpose "Calculate risk scores for findings"; responsibilities: apply risk calculation formula · consider severity/impact/confidence · generate priority rankings · calculate overall compliance score; Input `Findings`; Output `RiskAssessment`.
- Supporting: §4.2 puts risk calculation in the **deterministic** column (:158); §8 step 10 (:328); §18.2 expects `compliance/risk.py` (:1322); §18.3 step 8 (:1361); §30.3 deliverable (:1968).
- **The spec never states the formula, never defines P1–P4, never defines `RiskAssessment`.** The implementation invented thresholds 80/60/40 and a formula of its own.

## Where risk actually lives

`findings.py::SeverityCalculator` (:67–150), inside the Finding Engine:
`calculate_risk_score` → **ML-first** (RandomForestRegressor, 4 features, clamp [0,100]) with deterministic fallback `base×vendor×category×max(conf,0.5)/15.6×100`; `calculate_priority` → 80/60/40 bands, P4 catch-all. `_create_finding` (:209–216) computes both from `ControlEvaluation` fields **before** the Finding object exists — then every downstream layer drops them.

## Blocking findings

| # | Finding | Hypothesis | Class | Key evidence |
|---|---|---|---|---|
| F1 | 10.9 output computed then **discarded** | H09-08 | MISSING ×9 | no model column, no migration field, no `FindingResponse` field, no persistence write, no summary aggregate, no report render, **0** `risk_score` refs in `app/api` |
| F2 | **Two scoring vocabularies** | H09-05 | BUG | unit grid max 29.9 / mean 13.2 (CRITICAL/cisco: ML 94.3 vs formula 76.9); corpus **71,236/71,236 findings differ >1 pt**; **46,451 (65.2%) band mismatches**, all 480 files |
| F3 | Risk Engine component **missing** + spec incomplete | H09-01/02/03 | MISSING ×7 | no `risk.py`/`RiskEngine`/risk stage; `RiskAssessment` undefined anywhere; formula & priority vocabulary absent from spec |
| F4 | §4.2 deterministic vs **ML-first** production | H09-04 | DESIGN LIMITATION | findings.py:117 ML branch, model available=True; pipeline text "ML risk scoring (RandomForest)" |
| F5 | **Category impact inert** for 100% of findings | H09-07 | BUG | 28 production categories (`AAA`,`SSH`,`Logging`,…) vs 6 lowercase keys: overlap ∅; `ssh`→83.0 vs `SSH`→67.0 (case-sensitive) |
| F6 | Training/serving **drift**, synthetic labels | H09-09 | DESIGN LIMITATION ×6 | train `0.8+0.4c` vs serve `max(c,0.5)` (20% gap @c=1.0); 13-key vs 6-key category vocab; 2,000 formula+noise rows; r²=0.992 vs synthetic holdout |
| F7 | **Hostile inputs crash/corrupt** | H09-11 | BUG ×7 | `vendor=None`→AttributeError, `conf=None`→TypeError, **NaN→100.0→P1**, −1→58.2 & 1000→67.0 accepted, `"HIGH"`→32.1 vs 48.1 (−33%, path-dependent), `severity=None` defaulted |
| F8 | **(G)** vendor attribution distorts risk | H09-10 | DESIGN LIMITATION ×5 | cisco 76.9 vs juniper 70.5 (**+9.1%**), unsupported −16.7%, coverage 4/9 dataset vendors, band shift cisco 63.5→P2 vs arista 52.9→P3; sweep: 158 wrong-attrib files, 73 unsupported, label re-score delta up to **+20.0%** |
| F9 | **No exposure surface** | H09-12 | MISSING/DESIGN | no §20.2 endpoint, no §20.7 route, frontend renders neither field (dashboard `scoreRisk()` = compliance score, different thing), PDF claim gated on **vendor** model flag |
| F10 | Ownership + input contract gaps | H09-13/14 | MISSING/DESIGN | overall score computed in engine/executor, never by a risk component (E07 V07-42 upstream context); Input=`Findings` violated (evaluations are scored first) |

**Secondary:** S1 — ML confidence **non-monotonic** (MEDIUM 47.0→45.5 from conf 0.9→1.0; LOW 20.8→20.5 at 0.7→0.8) while severity ordering holds (0/48 violations).

## Results by category

| Cat | Area | PASS | FAIL |
|---|---|---|---|
| A | spec structure | 2 | **10** |
| B | formula & ML behavior | 12 | 2 |
| C | priority rankings | **7** | 0 |
| D | impact considerations | 3 | 2 |
| E | persistence/exposure | 1 | **9** |
| F | training/serving drift | 2 | **6** |
| G | wrong/unsupported vendor (separate record) | 0 | **5** |
| H | fidelity guarantees | **5** | 0 |
| I | pipeline/report/spec integration | 1 | **6** |
| J | determinism | **3** | 0 |
| K | performance | **3** | 0 |
| L | hostile input | 0 | **7** |
| M | user-facing exposure | 0 | 1 |
| **Σ** | | **39** | **48** |

Classifications: 39 CONFIRMED BEHAVIOR · 22 MISSING · 15 DESIGN LIMITATION · 11 BUG.

## Sweep highlights (71,236 findings over 480 files)

- **Priority: P1 0 · P2 19,396 · P3 27,201 · P4 24,639 · empty 0.**
- **E08 F10 correction**: E08's "24,639 empty priorities" were **P4** — `calculate_priority` never returns empty. P2/P3 match E08 exactly; the correction is recorded in `summary.json.e08_correction`.
- **Risk range 17.2–68.7** → corpus never reaches P1 (threshold 80 unreachable while category impact is inert and confidence <1).
- ML vs formula: 100% of findings differ >1 pt (file-max mean 28.32, max 29.4); band mismatch 65.2%; `priority_band_shift_between_vocabularies` on 480/480 files.
- G flags: `wrong_vendor_attributed` 158 (matches E08), `risk_vendor_unsupported` 73.
- Timing: executor p50 1816.2 / p95 2196.1 / max 5637.4 ms, total 884.3 s (~2× E08's session — environmental; risk-specific cost isolated: formula re-probe p50 0.5 ms/file).

## What works (hypotheses rejected — evidence-backed)

- **H09-15 banding**: boundaries exact (79.9→P2 / 80.0→P1 etc.), out-of-range clamped, **never empty** (0/71,236), each band == band of its own score, P1 reachable in unit grids (98.6).
- **H09-16 fidelity**: all scores ∈ [0,100] (incl. hostile inputs), priorities ∈ P1–P4, 1-decimal, native floats.
- **H09-17 determinism**: ML ×3, formula ×2, generation ×2 identical.
- **H09-18 performance**: ML p50 **8.79 ms**/call (<25 ms sanity), formula 0.0015 ms, 100 findings = 914 ms.
- **H09-19 considerations present**: severity bases 64.1/48.1/32.1/16.0 exact; vendor ratios 1.2/1.1 exact; confidence floor + cap behave as coded; ML honours vendor (67.0>61.4) and category (83.0>67.0); feature order & seeds aligned; in-memory Finding carries both fields; pipeline discloses ML risk while the model is available.

## Hypothesis ledger

**CONFIRMED (14):** H09-01 no component · H09-02 RiskAssessment undefined · H09-03 formula/vocab unspecified · H09-04 deterministic-vs-ML conflict · H09-05 two vocabularies · H09-06 confidence non-monotonic · H09-07 category impact inert · H09-08 computed-then-discarded · H09-09 training/serving drift · H09-10 (G) vendor distortion · H09-11 hostile inputs · H09-12 no exposure · H09-13 overall-score unowned · H09-14 input contract violated.
**REJECTED (5):** H09-15 banding defective · H09-16 fidelity violated · H09-17 non-determinism · H09-18 performance · H09-19 considerations missing.

## Cross-engine baseline

01 PARTIAL · 02–08 FAIL · **09 FAIL** (this) · 10–12 pending.
Full suite: **1223 collected / 1197 passed / 26 failed** — same 26 pre-existing failures as E08 (+87/+87/±0). Artifact set `09_risk/` follows the established contract (raw_results.jsonl, test_results.csv, dataset_results.csv, dataset_summary.json, performance.csv, determinism_results.csv, security_results.csv, summary.json, ENGINE_REPORT.md, this file). No production code modified.

## Readiness

**Not ready.** Minimum to reconsider: F1 (persist/expose the 10.9 output), F2 (one scoring vocabulary), F3 (deliver or rewrite §10.9 — including specifying formula, bands and `RiskAssessment`), F4 (decide deterministic vs ML). F5–F10 are required for the engine to be *correct* rather than merely present. Positive foundation to build on: banding, fidelity, determinism and performance all verified.

**Next after approval: Engine 10 — Remediation Engine (§10.10).**
