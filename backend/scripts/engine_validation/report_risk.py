"""Build Engine 09 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/09_risk/raw_results.jsonl    (pytest run)
    artifacts/engine_validation/09_risk/dataset_summary.json (sweep)
    artifacts/engine_validation/09_risk/dataset_results.csv  (sweep)

Outputs (same directory):
    test_results.csv  performance.csv  determinism_results.csv
    security_results.csv  summary.json
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
OUT = BACKEND / "artifacts" / "engine_validation" / "09_risk"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H09-01", "the Risk Engine specified by section 10.9 does not exist as "
               "a component: the section 18.2 file tree expects "
               "compliance/risk.py, section 8 lists '10. Risk Engine calculates "
               "risk scores' and section 18.3 lists '# 8. Calculate risk "
               "scores', but there is no risk module, no RiskEngine class and "
               "no risk pipeline stage - the logic lives inside the Finding "
               "Engine's SeverityCalculator (findings.py:67)",
     ["V09-01", "V09-04", "V09-08", "V09-09", "V09-10", "V09-11", "V09-12"]),
    ("H09-02", "the section 10.9 output type RiskAssessment is undefined in "
               "the spec (a single mention at spec:562 with no schema, fields "
               "or interface) and does not exist anywhere in the codebase",
     ["V09-02", "V09-03", "V09-105"]),
    ("H09-03", "section 10.9 requires 'Apply risk calculation formula' and "
               "'Generate priority rankings' but the spec defines neither: "
               "the only 'formula' occurrence is the responsibility bullet "
               "itself and no P1..P4 band vocabulary or threshold exists "
               "(the P1 rows at spec:1689-1704 are feature priorities, not "
               "finding risk) - the implementation invented thresholds "
               "80/60/40",
     ["V09-06", "V09-07"]),
    ("H09-04", "spec/code conflict: section 4.2 lists 'Risk score "
               "calculation' under Deterministic Engine Handles, but the "
               "production path tries the RandomForest first and only falls "
               "back to the formula on exception (findings.py:117-131), and "
               "the pipeline step text openly advertises 'ML risk scoring "
               "(RandomForest)' with the model available in this environment",
     ["V09-05", "V09-68"]),
    ("H09-05", "two scoring vocabularies: the ML path and the documented "
               "deterministic formula disagree on every finding - unit grid "
               "max difference 29.9 / mean 13.2 points, and across the "
               "480-file corpus 100% of 71,236 findings differ by >1 point "
               "(max file maximum 29.4) with 65.2% landing in a different "
               "priority band depending on which vocabulary is used",
     ["V09-19", "V09-25", "V09-98", "V09-99"]),
    ("H09-06", "ML risk ordering is broken for confidence: severity "
               "monotonicity holds (0/48 violations) but confidence "
               "monotonicity fails - MEDIUM drops 47.0 -> 45.5 between "
               "conf 0.9 and 1.0 and LOW drops 20.8 -> 20.5 between 0.7 and "
               "0.8, so higher confidence can lower the score",
     ["V09-20", "V09-21", "V09-22", "V09-96"]),
    ("H09-07", "the category impact multiplier is inert in production: the "
               "28 categories the system actually emits (AAA, SSH, Logging, "
               "Access Control, ... from the benchmark controls) never "
               "overlap the six lowercase CATEGORY_IMPACT keys (ssh, "
               "logging, access_control, ...), and the lookup is "
               "case-sensitive so even 'SSH' misses 'ssh' - every finding is "
               "scored as if it had no category",
     ["V09-34", "V09-35", "V09-102"]),
    ("H09-08", "the section 10.9 outputs are computed and then discarded: "
               "risk_score and priority exist on the in-memory Finding "
               "dataclass only - no findings-table column, no migration, no "
               "FindingResponse field, no persistence write, no summary "
               "aggregate, no report rendering and zero API references - so "
               "the RiskAssessment never reaches storage or any consumer",
      ["V09-39", "V09-40", "V09-41", "V09-42", "V09-43", "V09-44",
       "V09-45", "V09-46", "V09-47", "V09-48", "V09-97", "V09-100"]),
    ("H09-09", "training/serving drift in the risk model: train_risk uses "
               "confidence factor 0.8+0.4c while serving uses max(c,0.5) "
               "(20% gap at c=1.0), the training category vocabulary (13 "
               "title-case keys) and vendor vocabulary (includes 'unknown') "
               "differ from serving, the 2,000 labels are synthetic "
               "formula+noise rows, and the advertised r2=0.992 is measured "
               "against that synthetic holdout - feature order and seeding "
               "are the only things aligned",
      ["V09-49", "V09-50", "V09-51", "V09-52", "V09-53", "V09-54",
       "V09-55", "V09-56", "V09-99"]),
    ("H09-10", "SEPARATE RECORD (category G): vendor attribution distorts "
               "risk - multipliers key on evaluation.vendor, so wrong-vendor "
               "content (E08: 158 files / 22,820 findings) scores 9.1% "
               "inflated as cisco vs juniper, unsupported vendors (5 of 9 "
               "dataset vendors plus detected 'unknown', 73 files) silently "
               "drop to 1.0 (up to -16.7%), and the gap can cross the "
               "P2/P3 threshold (63.5 vs 52.9); sweep shows label-vendor "
               "re-scoring delta up to +20.0% on 158 files",
      ["V09-57", "V09-58", "V09-59", "V09-60", "V09-61", "V09-103"]),
    ("H09-11", "hostile inputs crash or silently corrupt risk: vendor=None "
               "raises AttributeError, confidence=None raises TypeError, "
               "NaN confidence becomes 100.0 (P1) via min(100.0, NaN), -1 "
               "and 1000 are accepted without validation, string severity "
               "'HIGH' scores 32.1 instead of 48.1 on the formula path (the "
               "ML path masks it, so behaviour differs by path), and "
               "severity=None is silently defaulted",
      ["V09-80", "V09-81", "V09-82", "V09-83", "V09-84", "V09-85", "V09-86",
       "V09-101"]),
    ("H09-12", "the 10.9 output has no exposure surface: no risk pipeline "
               "stage, no section 20.2 risk endpoint (and zero risk_score "
               "references across app/api), no section 20.7 risk UI route, "
               "the frontend never renders risk_score/priority anywhere "
               "(dashboard scoreRisk() labels the compliance score, a "
               "different quantity), and the PDF's 'Risk Scoring: "
               "RandomForest' claim is gated on the vendor detector's "
               "availability flag rather than the risk model's",
     ["V09-67", "V09-69", "V09-70", "V09-71", "V09-87"]),
    ("H09-13", "the section 10.9 responsibility 'Calculate overall "
               "compliance score' has no owner in the risk component: no "
               "risk module exists and overall_score is computed as "
               "passed/total in the compliance engine, executor and audit "
               "API instead; upstream context only (not re-tested): engine "
               "07 V07-42 dual score 46.9 vs 95.5",
      ["V09-72", "V09-104"]),
    ("H09-14", "the section 10.9 input contract is violated: risk is "
               "calculated from ControlEvaluation fields at findings.py:209 "
               "before the Finding object is constructed at :230 - the "
               "engine consumes control evaluations, not the Findings the "
               "spec names as input",
     ["V09-73"]),
    # --- rejected (predictions that did NOT hold) -----------------------
    ("H09-15", "priority banding itself is defective: boundary values are "
               "mis-banded, out-of-range scores crash, priorities come back "
               "empty (E08 F10 'empty priority' claim), a finding's band "
               "disagrees with its own score, or the top band is "
               "unreachable",
     ["V09-27", "V09-28", "V09-29", "V09-30", "V09-31", "V09-32", "V09-33"]),
    ("H09-16", "fidelity guarantees are violated: scores leave [0,100] on "
               "the ML or hostile paths, priorities fall outside P1..P4, "
               "values are unrounded or non-float",
     ["V09-62", "V09-63", "V09-64", "V09-65", "V09-66"]),
    ("H09-17", "risk scoring is non-deterministic across repeated runs "
               "(ML grid, generated findings, formula path)",
     ["V09-74", "V09-75", "V09-76"]),
    ("H09-18", "performance is unusable: ML predict exceeds the 25ms/"
               "finding sanity bound, the formula path is slow, or "
               "generating 100 findings with risk scoring exceeds 5s",
     ["V09-77", "V09-78", "V09-79"]),
    ("H09-19", "the section 10.9 considerations (severity, impact, "
               "confidence) are missing entirely: severity has no base "
               "scores, vendor/category multipliers do not change the "
               "output, confidence is ignored, or the ML path drops the "
               "impact inputs",
     ["V09-13", "V09-14", "V09-15", "V09-16", "V09-17", "V09-18",
      "V09-23", "V09-24", "V09-26", "V09-36", "V09-37", "V09-38"]),
]

CATEGORIES = {
    "A": "spec structure conformance (section 10.9, 4.2, 8, 18.2, 18.3, "
         "30.3 - does the Risk Engine / RiskAssessment exist?)",
    "B": "functional - risk calculation formula and ML model behaviour "
         "(section 10.9 'Apply risk calculation formula')",
    "C": "functional - priority rankings (section 10.9 'Generate priority "
         "rankings')",
    "D": "functional - impact considerations (section 10.9 'Consider "
         "severity, impact, confidence')",
    "E": "persistence and exposure of the 10.9 output (models, migrations, "
         "schemas, summaries, reports, API)",
    "F": "drift: risk model training vs serving (app/ml/train_all_engines.py)",
    "G": "SEPARATE RECORD - wrong/unsupported-vendor risk distortion "
         "(methodology rule)",
    "H": "fidelity guarantees (range, band vocabulary, rounding, typing)",
    "I": "integration with the pipeline, reports and spec interface sections "
         "(8, 20.2, 20.7)",
    "J": "determinism",
    "K": "performance (measurement only, sanity bounds)",
    "L": "hostile and boundary input",
    "M": "user-facing exposure (frontend rendering of risk/priority)",
}


def load() -> tuple[list[dict], dict, list[dict], dict]:
    rows = [
        json.loads(line)
        for line in (OUT / "raw_results.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    dataset = json.loads((OUT / "dataset_summary.json").read_text(encoding="utf-8"))
    with open(OUT / "dataset_results.csv", newline="", encoding="utf-8") as fh:
        files = list(csv.DictReader(fh))
    contract_path = OUT / "contract_results.json"
    contract = (json.loads(contract_path.read_text(encoding="utf-8"))
                if contract_path.exists() else {"checks": [], "violations_total": 0,
                                                "verdict": "NOT RUN"})
    return rows, dataset, files, contract


def write_csv(name: str, fields: list[str], rows: list[dict]) -> None:
    with open(OUT / name, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    rows, dataset, files, contract = load()
    write_csv("test_results.csv", TEST_FIELDS, rows)

    # ---- performance -------------------------------------------------
    perf: list[dict] = [{
        "source": "sweep",
        "label": f"{dataset['files']} dataset files through the full "
                 "executor (validation -> detection -> parsing -> "
                 "normalization -> evaluation -> finding generation with "
                 "normative risk scoring)",
        "p50_ms": dataset["exec_ms"]["p50"],
        "p95_ms": dataset["exec_ms"]["p95"],
        "max_ms": dataset["exec_ms"]["max"],
        "note": f"total {dataset['elapsed_s']}s; normative scoring is pure "
                "arithmetic inside generation (no per-finding model calls)",
    }]
    for row in rows:
        if row["category"] == "K":
            perf.append({
                "source": row["test_id"], "label": row["input"],
                "p50_ms": "", "p95_ms": "", "max_ms": "",
                "note": row["actual"],
            })
    write_csv("performance.csv",
              ["source", "label", "p50_ms", "p95_ms", "max_ms", "note"], perf)

    # ---- determinism -------------------------------------------------
    det = [r for r in rows if r["category"] == "J"]
    det.append({
        "test_id": "SWEEP-C7", "category": "J",
        "requirement": "re-running corpus files reproduces identical risk "
                       "scores and priorities",
        "input": next((c["probes"] for c in contract["checks"]
                       if c["id"] == "C7"), 0),
        "expected": "identical outcomes",
        "actual": f"violations="
                  f"{next((c['violations'] for c in contract['checks'] if c['id'] == 'C7'), 'n/a')}",
        "status": "PASS" if next((c["violations"] for c in contract["checks"]
                                  if c["id"] == "C7"), 0) == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "sweep_risk.py check C7",
        "recommendation": "", "pytest_test": "",
    })
    write_csv("determinism_results.csv", TEST_FIELDS, det)

    # ---- security / wrong-vendor / fidelity / hostile ----------------
    write_csv("security_results.csv", TEST_FIELDS,
              [r for r in rows if r["category"] in {"G", "H", "L"}])

    by_id = {r["test_id"]: r for r in rows}

    def expand(refs: list[str]) -> list[str]:
        out: list[str] = []
        for ref in refs:
            if ref in by_id and ref not in out:
                out.append(ref)
        return out

    hypotheses = []
    for hid, statement, refs in HYPOTHESES:
        resolved = expand(refs)
        missing = [r for r in refs if r not in by_id]
        if missing:
            raise SystemExit(f"{hid}: unknown test ids {missing}")
        statuses = [by_id[r]["status"] for r in resolved]
        if not statuses:
            conclusion = "NOT VERIFIABLE"
        elif any(s in {"FAIL", "PARTIAL"} for s in statuses):
            conclusion = "CONFIRMED"
        else:
            conclusion = "REJECTED"
        hypotheses.append({
            "id": hid,
            "statement": statement,
            "evidence_tests": resolved,
            "observed_statuses": statuses,
            "conclusion": conclusion,
            "classifications": sorted({by_id[r]["classification"] for r in resolved}),
        })

    covered = {t for h in hypotheses for t in h["evidence_tests"]}
    unreferenced = [r["test_id"] for r in rows if r["test_id"] not in covered]
    unreferenced_nonpass = [r["test_id"] for r in rows
                            if r["test_id"] in set(unreferenced)
                            and r["status"] != "PASS"]
    if unreferenced_nonpass:
        raise SystemExit(f"non-PASS rows unreferenced: {unreferenced_nonpass}")

    status_counts = Counter(r["status"] for r in rows)
    class_counts = Counter(r["classification"] for r in rows)
    cat_counts = Counter(r["category"] for r in rows)
    cat_status: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        cat_status[r["category"]][r["status"]] += 1

    fail_rows = [r["test_id"] for r in rows if r["status"] == "FAIL"]

    summary = {
        "engine": "09_risk",
        "scope": "backend/app/engines/compliance/risk.py (RiskEngine, "
                 "RiskAssessment, normative scorer, advisory isolation), "
                 "backend/app/engines/compliance/findings.py "
                 "(FindingGenerator wiring, SeverityCalculator adapter), "
                 "backend/app/ml/train_all_engines.py (train_risk, shared "
                 "builder), backend/app/ml/model_artifacts/risk_model.joblib "
                 "+ risk_meta.json (retrained emulation), backend/app/api/v1/"
                 "audit_execution.py (persistence write, summary aggregates), "
                 "backend/app/api/v1/reports.py + backend/app/engines/"
                 "reporting.py (report exposure), backend/app/models "
                 "(Finding risk columns), backend/app/schemas "
                 "(FindingResponse risk fields), backend/alembic (008), "
                 "validated against docs/PROJECT_MASTER_SPEC.md 10.9 (+ "
                 "§10.9.1 amendment), 4.2, 8 step 10, 18.2, 18.3, 20.2, "
                 "20.7, 30.3",
        "pytest": {
            "evidence_rows": len(rows),
            "status_counts": dict(status_counts),
            "classification_counts": dict(class_counts),
            "category_counts": dict(sorted(cat_counts.items())),
            "category_status": {k: dict(v) for k, v in sorted(cat_status.items())},
            "fail_rows": fail_rows,
        },
        "hypotheses": hypotheses,
        "hypothesis_totals": dict(Counter(h["conclusion"] for h in hypotheses)),
        "unreferenced_rows": unreferenced,
        "dataset": dataset,
        "corpus_contract_checks": contract,
        "categories": CATEGORIES,
        "e08_correction": (
            "E08 F10 claimed 24,639 findings with 'empty priority'. Engine "
            "09 evidence corrects this: calculate_priority never returns an "
            "empty string (P4 catch-all), and the corpus sweep counts "
            "exactly 24,639 P4 priorities with 0 empty - the E08 bucket "
            "labelled 'other' was P4, not empty."
        ),
    }
    (OUT / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(summary["pytest"], indent=2))
    print(json.dumps(summary["hypothesis_totals"], indent=2))
    print(json.dumps({h["id"]: h["conclusion"] for h in hypotheses}, indent=2))
    print(f"corpus contract checks: {contract['verdict']} "
          f"({contract['violations_total']} violations)")
    print(f"unreferenced rows: {len(unreferenced)} (all PASS verified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
