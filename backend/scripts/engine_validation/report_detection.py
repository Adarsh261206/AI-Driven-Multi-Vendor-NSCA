"""Build Engine 03 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/03_detection/raw_results.jsonl     (pytest run)
    artifacts/engine_validation/03_detection/dataset_summary.json  (sweep)

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
OUT = BACKEND / "artifacts" / "engine_validation" / "03_detection"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H03-01", "the reported platform depends on which branch ran "
               "(ios vs ios_xe)", ["V03-20"]),
    ("H03-02", "platform can be reported from a winner whose platform score is 0",
     ["V03-28"]),
    ("H03-03", "comment-only content still yields a confident vendor",
     ["V03-37"]),
    ("H03-04", "mixed-vendor content is never flagged as ambiguous",
     ["V03-38"]),
    ("H03-05", "unsupported vendors are attributed to a supported vendor "
               "instead of unknown", ["V03-40"]),
    ("H03-06", "one attacker-supplied line reassigns the vendor, including "
               "from inside a comment", ["V03-42", "V03-43"]),
    ("H03-07", "the documented detection_method / evidence contract does not "
               "match the implementation", ["V03-60", "V03-61"]),
    ("H03-08", "an ML result carries no line-level evidence for the platform "
               "it reported", ["V03-63"]),
    ("H03-09", "the result depends on how much content the caller passes",
     ["V03-58", "V03-59"]),
    ("H03-10", "non-str input raises an untyped error", ["V03-51"]),
    ("H03-11", "the project's own detection tests do not all pass on the "
               "deployed path", ["V03-64"]),
    ("H03-12", "firmware version is captured only partially for IOS",
     ["V03-08"]),
    ("H03-13", "implemented vendor scope exceeds the documented MVP scope",
     ["V03-62"]),
    ("H03-14", "the 10-item evidence cap does not hold on the deployed path",
     ["V03-65"]),
    ("H03-15", "identical content yields different results across calls or "
               "instances", ["V03-47", "V03-49", "V03-50"]),
    ("H03-16", "the ML branch is unreachable in this deployment",
     ["V03-10"]),
    ("H03-17", "detect() fails on ordinary configuration input "
               "(1 MiB / unicode / NUL / surrogate / control chars)",
     ["V03-32", "V03-33", "V03-34", "V03-35", "V03-36"]),
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
                "source": row["test_id"],
                "label": f"{r['chars']} chars",
                "p50_ms": r["p50_ms"], "p95_ms": r["p95_ms"],
                "p99_ms": r["p99_ms"], "throughput_mb_s": "",
            })
    t = dataset["timing_ms"]
    perf.append({
        "source": "corpus deployed path",
        "label": f"detect() over {dataset['files_total']} files",
        "p50_ms": t["deployed_path_p50"], "p95_ms": t["deployed_path_p95"],
        "p99_ms": t["deployed_path_p99"], "throughput_mb_s": "",
    })
    perf.append({
        "source": "corpus regex path",
        "label": f"detect() over {dataset['files_total']} files (ML unavailable)",
        "p50_ms": t["regex_path_p50"], "p95_ms": t["regex_path_p95"],
        "p99_ms": t["regex_path_p99"], "throughput_mb_s": "",
    })
    write_csv("performance.csv",
              ["source", "label", "p50_ms", "p95_ms", "p99_ms", "throughput_mb_s"],
              perf)

    det = [r for r in rows if r["category"] == "H" or r["test_id"] == "V03-47"]
    det.append({
        "test_id": "SWEEP-DET", "category": "H",
        "requirement": "a second full pass over 480 dataset files reproduces the "
                       "complete identification signature",
        "input": f"{dataset['files_total']} files, {dataset['bytes_total']} bytes",
        "expected": "0 mismatches",
        "actual": f"{dataset['determinism']['mismatches']} mismatches",
        "status": "PASS" if dataset["determinism"]["mismatches"] == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "scripts/engine_validation/sweep_detection.py determinism pass",
        "recommendation": "", "pytest_test": "",
    })
    write_csv("determinism_results.csv", TEST_FIELDS, det)

    write_csv("security_results.csv", TEST_FIELDS,
              [r for r in rows if r["category"] == "F"
               or r["test_id"] in {"V03-37", "V03-40", "V03-58", "V03-59", "V03-65"}])

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
        "engine": "03_vendor_detection",
        "scope": "backend/app/engines/detection.py only",
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
            "A": "functional (deployed path)",
            "B": "path selection and scoring contract",
            "C": "negative",
            "D": "boundary",
            "E": "content classes",
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
