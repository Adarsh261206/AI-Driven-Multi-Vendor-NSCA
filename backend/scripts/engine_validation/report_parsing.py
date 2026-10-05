"""Build Engine 04 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/04_parsing/raw_results.jsonl    (pytest run)
    artifacts/engine_validation/04_parsing/dataset_summary.json (sweep)

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
OUT = BACKEND / "artifacts" / "engine_validation" / "04_parsing"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H04-01", "top-level IOS sections nest under whatever section preceded them, "
               "so the tree does not match the vendor's flat grammar",
     ["V04-04", "V04-91", "V04-92", "V04-93", "V04-94", "V04-95"]),
    ("H04-02", "the Cisco parser can never report a parse error, a warning or an "
               "unknown section", ["V04-51", "V04-52", "V04-53", "V04-56"]),
    ("H04-03", "the Junos parser never flags an unknown/unsupported section",
     ["V04-54", "V04-56"]),
    ("H04-04", "'no ...' negation is lost in the Cisco parse tree, so an enabled and "
               "a disabled statement are indistinguishable",
     ["V04-41", "V04-42", "V04-44", "V04-100"]),
    ("H04-05", "content that does not match the parser's vendor syntax is accepted "
               "with 0 parse errors", ["V04-58", "V04-59", "V04-60", "V04-61",
                                        "V04-62", "V04-63"]),
    ("H04-06", "an unsupported vendor is routed to the Cisco parser by the pipeline",
     ["V04-35", "V04-64", "V04-99"]),
    ("H04-07", "multi-line banner bodies are parsed as configuration commands",
     ["V04-46", "V04-96"]),
    ("H04-08", "non-IOS formats (JSON) are converted into IOS nodes without any error",
     ["V04-48"]),
    ("H04-09", "the parse tree produced by this engine is not an input to compliance "
               "evaluation or normalization", ["V04-38"]),
    ("H04-10", "parse errors and warnings are discarded when the result is persisted",
     ["V04-39"]),
    ("H04-11", "semantic re-analysis parses every vendor's content with the Cisco parser",
     ["V04-40"]),
    ("H04-12", "a deeply nested configuration exhausts the recursion stack during "
               "serialisation or search", ["V04-70", "V04-71", "V04-72"]),
    ("H04-13", "Juniper style detection is a single global switch, so mixed content is "
               "mangled", ["V04-65"]),
    ("H04-14", "the three parsers disagree on path semantics, value representation and "
               "search/lookup API", ["V04-50", "V04-85", "V04-86", "V04-87", "V04-88"]),
    ("H04-15", "ParseResult does not carry the vendor/platform/id fields that the "
               "ParsedConfiguration contract declares", ["V04-57", "V04-98"]),
    ("H04-16", "non-str input raises an untyped AttributeError/TypeError instead of a "
               "parser-level error", ["V04-66", "V04-67", "V04-68"]),
    ("H04-17", "ACL sequence numbers and Juniper set-style values become node keys, "
               "so lookups by keyword fail", ["V04-47", "V04-49", "V04-97"]),
    ("H04-18", "the pipeline's platform argument is declared but never read, so it has "
               "no effect on parser selection", ["V04-36"]),
    ("H04-19", "the Juniper unclosed-brace warning is not a ParseWarning instance",
     ["V04-19", "V04-90"]),
    ("H04-20", "the parsers lose or invent lines for their own vendor's content",
     ["V04-10", "V04-79"]),
    ("H04-21", "repeated or interleaved parses of the same content differ",
     ["V04-75", "V04-76", "V04-77", "V04-78"]),
    ("H04-22", "hostile content (NUL, control chars, surrogate, whitespace, 1-2 MB) "
               "crashes a parser", ["V04-69", "V04-73", "V04-74", "V04-80",
                                    "V04-81", "V04-82", "V04-101"]),
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

    # ---- performance -------------------------------------------------
    perf: list[dict] = []
    for parser, t in sorted(dataset["timing_ms"].items()):
        perf.append({
            "source": "corpus",
            "label": f"{parser} parser over {t['n']} label-matched dataset files",
            "p50_ms": t["p50"], "p95_ms": t["p95"], "max_ms": t["max"],
            "note": "label-matched files (all sizes)",
        })
    for row in rows:
        if row["category"] == "J":
            perf.append({
                "source": row["test_id"], "label": row["input"],
                "p50_ms": "", "p95_ms": "", "max_ms": "",
                "note": row["actual"],
            })
    for row in rows:
        if row["test_id"] == "V04-73":
            perf.append({
                "source": row["test_id"], "label": "synthetic ~1-2 MB per parser",
                "p50_ms": "", "p95_ms": "", "max_ms": "",
                "note": row["actual"],
            })
    write_csv("performance.csv",
              ["source", "label", "p50_ms", "p95_ms", "max_ms", "note"], perf)

    # ---- determinism -------------------------------------------------
    det = [r for r in rows if r["category"] == "I"]
    totals = dataset["label_parser_totals"]
    nondet = sum(v["files_nondeterministic"] for v in totals.values())
    det.append({
        "test_id": "SWEEP-PARSE", "category": "I",
        "requirement": "a second full parse of every label-matched dataset file "
                       "reproduces the identical tree",
        "input": f"{dataset['files_total']} files, {dataset['bytes_total']} bytes",
        "expected": "0 non-deterministic files",
        "actual": f"{nondet} non-deterministic files",
        "status": "PASS" if nondet == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "scripts/engine_validation/sweep_parsing.py determinism pass "
                    "(per-parser label-matched files)",
        "recommendation": "", "pytest_test": "",
    })
    write_csv("determinism_results.csv", TEST_FIELDS, det)

    # ---- security / hostile-input / wrong-vendor ----------------------
    write_csv("security_results.csv", TEST_FIELDS,
              [r for r in rows
               if r["category"] in {"H", "G"} or r["test_id"] in {"V04-39", "V04-48"}])

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
        "engine": "04_parsing",
        "scope": "backend/app/engines/parsing/{cisco,juniper,fortinet}.py and the "
                 "parser-selection contract in app/engines/compliance/executor.py",
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
            "A": "functional — Cisco parser and section structure",
            "B": "functional — Junos parser",
            "C": "functional — FortiOS parser",
            "D": "parser selection and pipeline integration",
            "E": "semantic fidelity (negation, banner, key selection, format sanity)",
            "F": "diagnostics required by spec 10.3",
            "G": "SEPARATE RECORD — wrong-vendor input (methodology rule)",
            "H": "hostile and boundary input",
            "I": "determinism and evidence fidelity",
            "J": "performance (measurement only)",
            "K": "cross-parser contract consistency",
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
