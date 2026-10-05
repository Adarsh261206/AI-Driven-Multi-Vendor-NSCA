"""Build Engine 11 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/11_reporting/raw_results.jsonl    (pytest run)
    artifacts/engine_validation/11_reporting/dataset_summary.json (sweep)
    artifacts/engine_validation/11_reporting/dataset_results.csv  (sweep)
    artifacts/engine_validation/11_reporting/contract_results.json (sweep)

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
OUT = BACKEND / "artifacts" / "engine_validation" / "11_reporting"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H11-01", "no Reporting Engine boundary exists (spec §10.11 names an "
               "engine; reporting is an unvalidated function with no input "
               "contract or format gate)",
     ["V11-01", "V11-02", "V11-04", "V11-05"]),
    ("H11-02", "generation produces malformed, incomplete, or "
               "mis-sequenced documents",
     ["V11-03", "V11-06", "V11-07", "V11-10"]),
    ("H11-03", "partial stored data (None scores, string scores, missing "
               "keys) crashes report generation",
     ["V11-08", "V11-09"]),
    ("H11-04", "attacker-controlled config text breaks the document or "
               "injects formatting",
     ["V11-11", "V11-12", "V11-13", "V11-14"]),
    ("H11-05", "per-device counts are fabricated when grouping does not "
               "match",
     ["V11-15", "V11-16", "V11-17", "V11-18"]),
    ("H11-06", "reports carry false model/framework claims",
     ["V11-19", "V11-20", "V11-21"]),
    ("H11-07", "report content is non-deterministic",
     ["V11-22", "V11-23", "V11-24"]),
    ("H11-08", "wrong/unsupported vendors break or mislabel reports",
     ["V11-25", "V11-26", "V11-27"]),
    ("H11-09", "hostile and boundary inputs crash generation",
     ["V11-28", "V11-29", "V11-30", "V11-31"]),
    ("H11-10", "pipeline content (remediation, risk, compliance rows, "
               "executor output) is dropped on the way to the page",
     ["V11-32", "V11-33", "V11-34", "V11-35"]),
    ("H11-11", "report generation exceeds the roadmap budget",
     ["V11-36", "V11-37"]),
    ("H11-12", "rendered content is internally inconsistent",
     ["V11-38", "V11-39", "V11-40"]),
]

CATEGORIES = {
    "A": "spec structure conformance (section 10.11, 9.1 step 9, 30.7)",
    "B": "functional - generation contract",
    "C": "hostile markup (attacker-controlled evidence text, V03-44)",
    "D": "per-device attribution honesty",
    "E": "claims honesty (ML, framework)",
    "F": "determinism",
    "G": "SEPARATE RECORD - wrong/unsupported-vendor consequences "
         "(methodology rule)",
    "H": "hostile and boundary input",
    "I": "integration with the rest of the pipeline (section 9.1)",
    "J": "performance (measurement only)",
    "K": "content consistency spot checks",
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
        "label": f"{dataset['files']} dataset files x 2 report variants "
                 "(matched + unmatched attribution)",
        "p50_ms": dataset["gen_ms"]["p50"],
        "p95_ms": dataset["gen_ms"]["p95"],
        "max_ms": dataset["gen_ms"]["max"],
        "note": f"roadmap budget 30000ms per report; "
                f"{dataset['pdf_bytes_total']} bytes total",
    }]
    for row in rows:
        if row["category"] == "J":
            perf.append({
                "source": row["test_id"], "label": row["input"],
                "p50_ms": "", "p95_ms": "", "max_ms": "",
                "note": row["actual"],
            })
    write_csv("performance.csv",
              ["source", "label", "p50_ms", "p95_ms", "max_ms", "note"], perf)

    # ---- determinism -------------------------------------------------
    det = [r for r in rows if r["category"] == "F"]
    det.append({
        "test_id": "SWEEP-C6", "category": "F",
        "requirement": "re-running corpus files reproduces identical "
                       "report content",
        "input": next((c["probes"] for c in contract["checks"]
                       if c["id"] == "C6"), 0),
        "expected": "identical normalized content",
        "actual": f"violations="
                  f"{next((c['violations'] for c in contract['checks'] if c['id'] == 'C6'), 'n/a')}",
        "status": "PASS" if next((c["violations"] for c in contract["checks"]
                                  if c["id"] == "C6"), 0) == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "sweep_reporting.py check C6",
        "recommendation": "", "pytest_test": "",
    })
    write_csv("determinism_results.csv", TEST_FIELDS, det)

    # ---- security / wrong-vendor / hostile ---------------------------
    write_csv("security_results.csv", TEST_FIELDS,
              [r for r in rows if r["category"] in {"G", "H", "C"}])

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
        "engine": "11_reporting",
        "scope": "backend/app/engines/reporting.py "
                 "(generate_audit_report, ReportEngineError, "
                 "validate_report_inputs, safe display helpers, "
                 "matched-only attribution, neutral cover, conditional "
                 "breaks), backend/app/api/v1/reports.py "
                 "(resolve_report_format), validated against "
                 "docs/PROJECT_MASTER_SPEC.md 10.11, 9.1 step 9, 30.7",
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
