"""Build Engine 01 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/01_ingestion/raw_results.jsonl   (pytest run)
    artifacts/engine_validation/01_ingestion/dataset_summary.json (sweep)

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
OUT = BACKEND / "artifacts" / "engine_validation" / "01_ingestion"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H1", "FileDecodeError is unreachable because latin-1 always succeeds",
     ["V01-24", "V01-12"]),
    ("H2", ".zip is allow-listed but archives are never extracted",
     ["V01-15", "V01-16"]),
    ("H3", "no binary/magic-byte detection before persistence",
     ["V01-34", "V01-08"]),
    ("H4", "path-traversal shaped filenames are accepted and stored verbatim",
     ["V01-17-*", "V01-35"]),
    ("H5", "filename longer than String(255) raises an untyped database error",
     ["V01-30"]),
    ("H6", "upload endpoint duplicates engine logic and returns instead of raising",
     ["V01-37"]),
    ("H7", "upload endpoint decodes with a different fallback chain (no cp-1252)",
     ["V01-37"]),
    ("H8", "upload endpoint handles extensionless filenames differently",
     ["V01-37"]),
    ("H9", "upload endpoint buffers the whole body before the size check",
     ["V01-37"]),
    ("H10", "NUL bytes in content fail at the database as an untyped driver error",
     ["V01-40"]),
    ("H11", "IngestionEngine is imported by nothing (orphaned module)",
     ["V01-37"]),
    ("H12", "zero-byte configurations are accepted with line_count=0",
     ["V01-31"]),
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
                "label": f"{r['bytes']} bytes",
                "p50_ms": r["p50_ms"], "p95_ms": r["p95_ms"],
                "p99_ms": r["p99_ms"], "throughput_mb_s": r["mb_per_s"],
            })
    t = dataset["timing_ms"]
    for label, p50, p95, p99 in [
        ("dataset decode (480 files)", t["decode_p50"], t["decode_p95"], t["decode_p99"]),
        ("dataset sha256 (480 files)", t["hash_p50"], t["hash_p95"], t["hash_p99"]),
    ]:
        perf.append({
            "source": "real dataset sweep",
            "label": label,
            "p50_ms": p50, "p95_ms": p95, "p99_ms": p99,
            "throughput_mb_s": "",
        })
    write_csv(
        "performance.csv",
        ["source", "label", "p50_ms", "p95_ms", "p99_ms", "throughput_mb_s"],
        perf,
    )

    det = [
        r for r in rows
        if r["test_id"] in {"V01-21", "V01-22", "V01-36"}
        or r["test_id"].startswith("V01-11-")
    ]
    det.append({
        "test_id": "SWEEP-DET",
        "category": "H",
        "requirement": "second full pass over 480 dataset files reproduces every "
                       "hash and encoding",
        "input": f"{dataset['files_total']} files, {dataset['bytes_total']} bytes",
        "expected": "0 mismatches",
        "actual": f"{dataset['determinism_mismatches']} mismatches",
        "status": "PASS" if dataset["determinism_mismatches"] == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "scripts/engine_validation/sweep_ingestion.py determinism pass",
        "recommendation": "", "pytest_test": "",
    })
    write_csv("determinism_results.csv", TEST_FIELDS, det)

    write_csv("security_results.csv", TEST_FIELDS, [r for r in rows if r["category"] == "F"])

    by_id = {r["test_id"]: r for r in rows}

    def expand(refs: list[str]) -> list[str]:
        out: list[str] = []
        for ref in refs:
            hits = (
                [k for k in by_id if k.startswith(ref[:-1])]
                if ref.endswith("*")
                else ([ref] if ref in by_id else [])
            )
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
            "classifications": sorted(
                {by_id[r]["classification"] for r in resolved}
            ),
        })

    status_counts = Counter(r["status"] for r in rows)
    class_counts = Counter(r["classification"] for r in rows)
    cat_counts = Counter(r["category"] for r in rows)
    cat_status: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        cat_status[r["category"]][r["status"]] += 1

    summary = {
        "engine": "01_configuration_ingestion",
        "scope": "backend/app/engines/ingestion.py only",
        "pytest": {
            "tests_collected": len({r["pytest_test"] for r in rows if r["pytest_test"]}),
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
            "B": "functional/positive (ingest + contract)",
            "C": "negative",
            "D": "boundary",
            "E": "malformed input",
            "F": "security",
            "G": "reliability",
            "H": "determinism",
            "I": "error handling",
            "J": "performance",
            "K": "integration contract",
        },
        "not_verifiable": [
            r["test_id"] for r in rows if r["status"] == "NOT VERIFIABLE"
        ],
    }
    (OUT / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(summary["pytest"], indent=2))
    print(json.dumps({h["id"]: h["conclusion"] for h in hypotheses}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
