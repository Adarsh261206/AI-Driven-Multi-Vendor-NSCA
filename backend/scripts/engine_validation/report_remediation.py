"""Build Engine 10 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/10_remediation/raw_results.jsonl    (pytest run)
    artifacts/engine_validation/10_remediation/dataset_summary.json (sweep)
    artifacts/engine_validation/10_remediation/dataset_results.csv  (sweep)
    artifacts/engine_validation/10_remediation/contract_results.json (sweep)

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
OUT = BACKEND / "artifacts" / "engine_validation" / "10_remediation"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H10-01", "no Remediation Engine component exists (spec §10.10 names "
               "an engine; remediation is built inline or not at all)",
     ["V10-01", "V10-03"]),
    ("H10-02", "remediation content does not follow the §12 interface",
     ["V10-02", "V10-04", "V10-05", "V10-10", "V10-32"]),
    ("H10-03", "control-authored commands are ignored or overwritten",
     ["V10-06", "V10-19"]),
    ("H10-04", "missing commands are fabricated instead of honestly empty "
               "or conservatively derived",
     ["V10-07", "V10-08", "V10-09", "V10-18", "V10-40"]),
    ("H10-05", "vendor-specific syntax is wrong (cross-family commands, "
               "unsafe negation, derivation for unknown vendors)",
     ["V10-11", "V10-12", "V10-13", "V10-14", "V10-38"]),
    ("H10-06", "verification/rollback steps are missing or wrong",
     ["V10-15", "V10-16", "V10-17", "V10-18", "V10-39"]),
    ("H10-07", "references/linkage are missing or mismatched",
     ["V10-19", "V10-20", "V10-21", "V10-33"]),
    ("H10-08", "remediation generation is non-deterministic",
     ["V10-22", "V10-23", "V10-24"]),
    ("H10-09", "wrong/unsupported vendors receive fabricated remediations",
     ["V10-25", "V10-26", "V10-27"]),
    ("H10-10", "hostile inputs crash or corrupt remediation",
     ["V10-28", "V10-29", "V10-30", "V10-31"]),
    ("H10-11", "pipeline/API/reports drop or diverge remediation content",
     ["V10-32", "V10-33", "V10-34", "V10-35"]),
    ("H10-12", "remediation makes audits unacceptably slow",
     ["V10-36", "V10-37"]),
]

CATEGORIES = {
    "A": "spec structure conformance (section 10.10, section 12 Remediation)",
    "B": "functional - remediation generation contract",
    "C": "functional - vendor-specific syntax",
    "D": "functional - verification and rollback",
    "E": "references and finding linkage",
    "F": "determinism",
    "G": "SEPARATE RECORD - wrong/unsupported-vendor consequences "
         "(methodology rule)",
    "H": "hostile and boundary input",
    "I": "integration with the rest of the pipeline (section 9.1)",
    "J": "performance (measurement only)",
    "K": "content quality spot checks",
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
                 "canonical remediation)",
        "p50_ms": dataset["exec_ms"]["p50"],
        "p95_ms": dataset["exec_ms"]["p95"],
        "max_ms": dataset["exec_ms"]["max"],
        "note": f"total {dataset['elapsed_s']}s; remediation is pure "
                "string work inside generation (no per-finding I/O)",
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
        "test_id": "SWEEP-C7", "category": "F",
        "requirement": "re-running corpus files reproduces identical "
                       "remediations",
        "input": next((c["probes"] for c in contract["checks"]
                       if c["id"] == "C7"), 0),
        "expected": "identical outcomes",
        "actual": f"violations="
                  f"{next((c['violations'] for c in contract['checks'] if c['id'] == 'C7'), 'n/a')}",
        "status": "PASS" if next((c["violations"] for c in contract["checks"]
                                  if c["id"] == "C7"), 0) == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "sweep_remediation.py check C7",
        "recommendation": "", "pytest_test": "",
    })
    write_csv("determinism_results.csv", TEST_FIELDS, det)

    # ---- security / wrong-vendor / hostile ---------------------------
    write_csv("security_results.csv", TEST_FIELDS,
              [r for r in rows if r["category"] in {"G", "H"}])

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
        "engine": "10_remediation",
        "scope": "backend/app/engines/compliance/remediation.py "
                 "(RemediationEngine, Remediation, negate/invert, "
                 "validate_remediation), backend/app/engines/compliance/"
                 "executor.py (delegation), backend/app/benchmarks/"
                 "execution.py (control-authored content on evidence), "
                 "backend/app/engines/reporting.py (§12 rendering), "
                 "backend/app/schemas (Remediation), validated against "
                 "docs/PROJECT_MASTER_SPEC.md 10.10, 9.1, 12 Remediation",
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
