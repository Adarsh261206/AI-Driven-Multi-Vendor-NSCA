"""Build Engine 12 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/12_audit_trail/raw_results.jsonl    (pytest)
    artifacts/engine_validation/12_audit_trail/dataset_summary.json (sweep)
    artifacts/engine_validation/12_audit_trail/dataset_results.csv  (sweep)
    artifacts/engine_validation/12_audit_trail/contract_results.json (sweep)

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
OUT = BACKEND / "artifacts" / "engine_validation" / "12_audit_trail"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H12-01", "no Audit Trail boundary exists (spec §10.12 names an "
               "engine; logging is unvalidated writes with no served "
               "query surface)",
     ["V12-01", "V12-02", "V12-03", "V12-04", "V12-05"]),
    ("H12-02", "trail entries do not persist faithfully, or misuse "
               "surfaces as untyped/DB-time errors",
     ["V12-06", "V12-07", "V12-08", "V12-09", "V12-10"]),
    ("H12-03", "real pipeline payloads (Decimal, datetime, sets, NUL, "
               "non-finite) break persistence and lose history",
     ["V12-11", "V12-12", "V12-13", "V12-14"]),
    ("H12-04", "trail queries are inexact, unordered, unclamped, or "
               "crash on malformed filters",
     ["V12-15", "V12-16", "V12-17", "V12-18", "V12-41", "V12-42"]),
    ("H12-05", "lifecycle transitions, configuration changes and KB "
               "version events leave no trail",
     ["V12-19", "V12-20", "V12-21", "V12-22"]),
    ("H12-06", "trail history is non-deterministic",
     ["V12-23", "V12-24"]),
    ("H12-07", "wrong/unsupported vendors break history or leak across "
               "actors",
     ["V12-25", "V12-26", "V12-27"]),
    ("H12-08", "hostile and boundary inputs break logging or querying",
     ["V12-28", "V12-29", "V12-30", "V12-31"]),
    ("H12-09", "pipeline content (finding transitions, audit results, "
               "endpoint items) is dropped on the way to history",
     ["V12-32", "V12-33", "V12-34", "V12-35"]),
    ("H12-10", "trail writes/queries exceed practical budgets",
     ["V12-36", "V12-37"]),
    ("H12-11", "entry identity, system entries, or finding linkage is "
               "broken",
     ["V12-38", "V12-39", "V12-40"]),
]

CATEGORIES = {
    "A": "spec structure conformance (section 10.12)",
    "B": "functional - logging contract",
    "C": "serialization (trail never breaks the audited operation)",
    "D": "queries (exact sets, order, clamps, typed misuse)",
    "E": "coverage wiring (lifecycle, changes, versions)",
    "F": "determinism",
    "G": "SEPARATE RECORD - wrong/unsupported-vendor consequences "
         "(methodology rule)",
    "H": "hostile and boundary input",
    "I": "integration with the rest of the pipeline (section 9.1)",
    "J": "performance (measurement only)",
    "K": "identity and linkage spot checks",
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
        "label": f"{dataset['files']} log+flush writes (throwaway DB, "
                 "rolled back)",
        "p50_ms": dataset["log_ms"]["p50"],
        "p95_ms": dataset["log_ms"]["p95"],
        "max_ms": dataset["log_ms"]["max"],
        "note": f"budget 5000ms per write; residue "
                f"{dataset['db_residue_rows']}",
    }]
    for row in rows:
        if row["category"] == "J":
            import re as _re
            actual = row["actual"] or ""
            def _num(key: str) -> str:
                m = _re.search(rf"{key}=([\d.]+)", actual)
                return m.group(1) if m else ""
            perf.append({
                "source": row["test_id"], "label": row["input"],
                "p50_ms": _num("p50_ms"), "p95_ms": _num("p95_ms"),
                "max_ms": _num("max_ms"),
                "note": actual,
            })
    write_csv("performance.csv",
              ["source", "label", "p50_ms", "p95_ms", "max_ms", "note"], perf)

    # ---- determinism -------------------------------------------------
    det = [r for r in rows if r["category"] == "F"]
    det.append({
        "test_id": "SWEEP-C6", "category": "F",
        "requirement": "re-queries return identical sets across the corpus",
        "input": next((c["probes"] for c in contract["checks"]
                       if c["id"] == "C6"), 0),
        "expected": "identical id sets",
        "actual": f"violations="
                  f"{next((c['violations'] for c in contract['checks'] if c['id'] == 'C6'), 'n/a')}",
        "status": "PASS" if next((c["violations"] for c in contract["checks"]
                                  if c["id"] == "C6"), 0) == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "sweep_audit_trail.py check C6",
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
        "engine": "12_audit_trail",
        "scope": "backend/app/repositories/audit_trail.py "
                 "(AuditTrailError, normalize_action/uuid, "
                 "sanitize_details, log helpers, get/count_entries), "
                 "backend/app/api/v1/audit_trail.py (GET /audit-trail), "
                 "backend/app/api/v1/audits.py + audit_execution.py "
                 "(lifecycle), configurations.py (upload), training.py "
                 "(mapping create/edit), app/models (MAPPING_CREATED), "
                 "app/schemas (trail responses), validated against "
                 "docs/PROJECT_MASTER_SPEC.md 10.12, 9.1",
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
