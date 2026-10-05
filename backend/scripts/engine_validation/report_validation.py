"""Build Engine 02 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/02_validation/raw_results.jsonl    (pytest run)
    artifacts/engine_validation/02_validation/dataset_summary.json (sweep)

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
OUT = BACKEND / "artifacts" / "engine_validation" / "02_validation"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H02-01", "the NULL_BYTE error code is unreachable because the binary "
               "check short-circuits first", ["V02-06"]),
    ("H02-02", "is_valid can only ever become False because of BINARY_CONTENT",
     ["V02-07"]),
    ("H02-03", "empty and whitespace-only content does not fail validation",
     ["V02-13-*"]),
    ("H02-04", "comment-only content validates with zero issues",
     ["V02-14-*"]),
    ("H02-05", "syntax validation is claimed in the docstring but not implemented",
     ["V02-15", "V02-34"]),
    ("H02-06", "vendor_hint is inert and no mixed-vendor recognition exists",
     ["V02-16", "V02-23"]),
    ("H02-07", "unknown / unsupported content is never recognised as such",
     ["V02-17"]),
    ("H02-08", "credential detection misses space-separated and non-Cisco "
               "password forms", ["V02-19-*"]),
    ("H02-09", "insecure-setting detection false-positives on negated commands",
     ["V02-20-*"]),
    ("H02-10", "comment suppression covers only '!' and '#'",
     ["V02-22-*"]),
    ("H02-11", "binary detection is a dilutable strict >10% ratio",
     ["V02-09-*", "V02-24"]),
    ("H02-12", "ValidationResult.warnings and .info are never populated",
     ["V02-27"]),
    ("H02-13", "non-str input raises an untyped exception",
     ["V02-08"]),
    ("H02-14", "warnings and info issues can stop the audit pipeline",
     ["V02-32"]),
    ("H02-15", "a routine key-generation command is reported as a credential",
     ["V02-21"]),
]


def load() -> tuple[list[dict], dict]:
    rows = [
        json.loads(line)
        for line in (OUT / "raw_results.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    dataset = json.loads((OUT / "dataset_summary.json").read_text(encoding="utf-8"))
    return rows, dataset


def write_csv(name: str, fields: list[str], rows: list[dict]) -> None:
    with open(OUT / name, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    rows, dataset = load()
    write_csv("test_results.csv", TEST_FIELDS, rows)

    perf: list[dict] = []
    for row in rows:
        for r in row.get("performance", []):
            perf.append({
                "source": "pytest synthetic sizes",
                "label": f"{r['chars']} chars",
                "p50_ms": r["p50_ms"], "p95_ms": r["p95_ms"],
                "p99_ms": r["p99_ms"], "throughput_mb_s": "",
            })
    t = dataset["timing_ms"]
    perf.append({
        "source": "real dataset sweep",
        "label": f"validate() over {dataset['files_total']} files",
        "p50_ms": t["validate_p50"], "p95_ms": t["validate_p95"],
        "p99_ms": t["validate_p99"], "throughput_mb_s": "",
    })
    write_csv("performance.csv",
              ["source", "label", "p50_ms", "p95_ms", "p99_ms", "throughput_mb_s"],
              perf)

    det = [r for r in rows if r["test_id"] in {"V02-28", "V02-29"}]
    det.append({
        "test_id": "SWEEP-DET", "category": "H",
        "requirement": "second full pass over 480 dataset files reproduces "
                       "is_valid and the issue-code multiset",
        "input": f"{dataset['files_total']} files, {dataset['bytes_total']} bytes",
        "expected": "0 mismatches",
        "actual": f"{dataset['determinism_mismatches']} mismatches",
        "status": "PASS" if dataset["determinism_mismatches"] == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "scripts/engine_validation/sweep_validation.py determinism pass",
        "recommendation": "", "pytest_test": "",
    })
    write_csv("determinism_results.csv", TEST_FIELDS, det)

    write_csv("security_results.csv", TEST_FIELDS,
              [r for r in rows if r["category"] == "F"])

    by_id = {r["test_id"]: r for r in rows}

    def expand(refs: list[str]) -> list[str]:
        out: list[str] = []
        for ref in refs:
            hits = ([k for k in by_id if k.startswith(ref[:-1])]
                    if ref.endswith("*")
                    else ([ref] if ref in by_id else []))
            for hit in hits:
                if hit not in out:
                    out.append(hit)
        return out

    hypotheses = []
    for hid, statement, refs in HYPOTHESES:
        resolved = expand(refs)
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

    status_counts = Counter(r["status"] for r in rows)
    class_counts = Counter(r["classification"] for r in rows)
    cat_counts = Counter(r["category"] for r in rows)
    cat_status: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        cat_status[r["category"]][r["status"]] += 1

    summary = {
        "engine": "02_configuration_validation",
        "scope": "backend/app/engines/validation.py only",
        "pytest": {
            "evidence_rows": len(rows),
            "status_counts": dict(status_counts),
            "classification_counts": dict(class_counts),
            "category_counts": dict(sorted(cat_counts.items())),
            "category_status": {k: dict(v) for k, v in sorted(cat_status.items())},
        },
        "hypotheses": hypotheses,
        "dataset": dataset,
        "categories": {
            "A": "functional/positive",
            "B": "functional/positive (gate + caller contract)",
            "C": "negative",
            "D": "boundary",
            "E": "malformed / requested content classes",
            "F": "security",
            "G": "reliability",
            "H": "determinism",
            "I": "error handling",
            "J": "performance",
            "K": "integration contract",
        },
    }
    (OUT / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(summary["pytest"], indent=2))
    print(json.dumps({h["id"]: h["conclusion"] for h in hypotheses}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
