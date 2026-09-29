"""Build Engine 05 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/05_normalization/raw_results.jsonl    (pytest run)
    artifacts/engine_validation/05_normalization/dataset_summary.json (sweep)
    artifacts/engine_validation/05_normalization/dataset_results.csv  (sweep)
    artifacts/engine_validation/05_normalization/probe05.json         (contract probes)
    artifacts/engine_validation/05_normalization/probe05b.json        (evaluation probes)

Outputs (same directory):
    test_results.csv  performance.csv  determinism_results.csv
    security_results.csv  summary.json
"""

from __future__ import annotations

import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
OUT = BACKEND / "artifacts" / "engine_validation" / "05_normalization"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H05-01", "the Universal Security Model is a dead schema: production code never "
               "instantiates it and both mappers and controls reference paths it does "
               "not define", ["V05-08", "V05-53", "V05-54"]),
    ("H05-02", "the model does not implement spec 11: five 11.1 concepts are absent and "
               "the model carries no version (11.3)", ["V05-02", "V05-03"]),
    ("H05-03", "FortiOS section-presence checks never evaluate to true, so NTP, ACL, AAA, "
               "SNMP and logging state are reported absent for valid FortiOS content",
     ["V05-38", "V05-39", "V05-41", "V05-42"]),
    ("H05-04", "FortiOS password-policy and syslog target values are never extracted",
     ["V05-37", "V05-40"]),
    ("H05-05", "FortiOS token matching is substring-based, so an https-only interface "
               "reports management.http.enabled=True", ["V05-35"]),
    ("H05-06", "Junos set-style NTP reports ntp.configured=False while listing its servers",
     ["V05-30"]),
    ("H05-07", "Junos flat statements are grouped under the literal key 'set', producing "
               "phantom conflicts for ordinary configurations", ["V05-33"]),
    ("H05-08", "multi-word value keys are matched against single whitespace tokens, so "
               "NTP servers and syslog targets are never extracted for any vendor",
     ["V05-20", "V05-21", "V05-31"]),
    ("H05-09", "Cisco vty transport matching misses 'transport input ssh telnet', so a "
               "telnet-permitting vty block reports telnet disabled", ["V05-15"]),
    ("H05-10", "comment lines drive normalized security state and control results change "
               "when only comments change",
     ["V05-67", "V05-68", "V05-69", "V05-70", "V05-77"]),
    ("H05-11", "absent configuration is materialized as definite observed state, so an "
               "empty configuration returns SUCCESS with fabricated values",
     ["V05-47", "V05-71"]),
    ("H05-12", "fabricated values satisfy is_set controls and contradict the model's "
               "secure defaults, producing false passes and false failures on an empty "
               "configuration", ["V05-72", "V05-73", "V05-74"]),
    ("H05-13", "normalized values ignore the model's declared data types (password-policy "
               "numbers emitted as strings)", ["V05-23"]),
    ("H05-14", "the hostname is written to a root key outside the model instead of "
               "device.hostname", ["V05-76"]),
    ("H05-15", "ACL rule counting counts any line containing 'permit ' or 'deny ', "
               "including interface descriptions", ["V05-75"]),
    ("H05-16", "NormalizationResult/NormalizationMapping do not implement spec 12.1 "
               "(missing id/version/vendor_specific_syntax, synthetic source_path, "
               "constant confidence)",
     ["V05-43", "V05-44", "V05-45", "V05-46"]),
    ("H05-17", "result_type semantics are exception-driven: SUCCESS is awarded regardless "
               "of model coverage and PARTIAL only ever means a mapper crashed",
     ["V05-47", "V05-49"]),
    ("H05-18", "the engine trusts the caller's vendor/platform, so content of a different "
               "or unsupported vendor normalizes to SUCCESS silently",
     ["V05-61", "V05-62", "V05-63", "V05-66"]),
    ("H05-19", "a failed normalization does not stop control evaluation - an unsupported "
               "vendor is still scored", ["V05-64", "V05-65"]),
    ("H05-20", "control target paths and AI output validation are disconnected from the "
               "model",
     ["V05-55", "V05-58", "V05-59", "V05-60"]),
    ("H05-21", "normalization runs twice per audit and the executor's result is discarded",
     ["V05-79", "V05-80", "V05-86"]),
    ("H05-22", "nothing the engine produces reaches storage, and the specified 10.5 "
               "contract (SemanticInterpretation input, knowledge base) is unmet",
     ["V05-81", "V05-82", "V05-83", "V05-84", "V05-85"]),
    ("H05-23", "a configuration payload without any lines is accepted as a full SUCCESS",
     ["V05-97"]),
    ("H05-24", "control characters in the input are accepted into normalized values",
     ["V05-95"]),
    ("H05-25", "repeated or interleaved normalizations of the same input differ",
     ["V05-88", "V05-89", "V05-90"]),
    ("H05-26", "hostile input (NUL, control characters, surrogate, null entries, 1 MB "
               "line, 20k lines) crashes or hangs the normalizer",
     ["V05-94", "V05-96", "V05-98", "V05-99", "V05-100"]),
]

CATEGORIES = {
    "A": "Universal Security Model structure and spec 11 conformance",
    "B": "functional - Cisco IOS/IOS-XE mapper on Cisco content",
    "C": "functional - Juniper Junos mapper on Junos content",
    "D": "functional - Fortinet FortiOS mapper on FortiOS content",
    "E": "NormalizationResult contract vs spec 12.1",
    "F": "model <-> mapper <-> control registry consistency (drift)",
    "G": "SEPARATE RECORD - wrong/unsupported-vendor consequences (methodology rule)",
    "H": "semantic fidelity - normalized state the input does not contain",
    "I": "pipeline integration, double normalization and persistence",
    "J": "determinism",
    "K": "performance (measurement only)",
    "L": "hostile and boundary input",
}


def load() -> tuple[list[dict], dict, list[dict]]:
    rows = [
        json.loads(line)
        for line in (OUT / "raw_results.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    dataset = json.loads((OUT / "dataset_summary.json").read_text(encoding="utf-8"))
    with open(OUT / "dataset_results.csv", newline="", encoding="utf-8") as fh:
        files = list(csv.DictReader(fh))
    return rows, dataset, files


def write_csv(name: str, fields: list[str], rows: list[dict]) -> None:
    with open(OUT / name, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    rows, dataset, files = load()
    write_csv("test_results.csv", TEST_FIELDS, rows)

    # ---- performance -------------------------------------------------
    elapsed = [float(f["elapsed_ms"]) for f in files if f.get("elapsed_ms")]
    perf: list[dict] = []
    if elapsed:
        ordered = sorted(elapsed)
        perf.append({
            "source": "corpus",
            "label": f"{len(elapsed)} dataset files normalized once each",
            "p50_ms": f"{statistics.median(elapsed):.3f}",
            "p95_ms": f"{ordered[int(len(ordered) * 0.95) - 1]:.3f}",
            "max_ms": f"{max(elapsed):.3f}",
            "note": f"sum={sum(elapsed):.1f}ms; supported labels only "
                    f"({dataset['supported_labels']['files']} files) dominate the tail",
        })
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
    nondet = dataset["overall"]["nondeterministic"]
    det.append({
        "test_id": "SWEEP-NORM", "category": "J",
        "requirement": "a second normalization of every dataset file reproduces the "
                       "identical universal configuration",
        "input": f"{dataset['overall']['files']} files",
        "expected": "0 non-deterministic files",
        "actual": f"{nondet} non-deterministic files",
        "status": "PASS" if nondet == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "scripts/engine_validation/sweep_normalization.py determinism pass",
        "recommendation": "", "pytest_test": "",
    })
    write_csv("determinism_results.csv", TEST_FIELDS, det)

    # ---- security / wrong-vendor / semantic fidelity / hostile --------
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
        "engine": "05_normalization",
        "scope": "backend/app/engines/normalization.py, "
                 "backend/app/engines/universal_model.py and their contract with "
                 "docs/PROJECT_MASTER_SPEC.md 10.5/11/12.1 plus the pipeline consumers "
                 "(app/benchmarks/execution.py, app/engines/compliance/executor.py, "
                 "app/api/v1/audit_execution.py, app/ai/validators.py)",
        "pytest": {
            "evidence_rows": len(rows),
            "status_counts": dict(status_counts),
            "classification_counts": dict(class_counts),
            "category_counts": dict(sorted(cat_counts.items())),
            "category_status": {k: dict(v) for k, v in sorted(cat_status.items())},
        },
        "hypotheses": hypotheses,
        "hypothesis_totals": dict(Counter(h["conclusion"] for h in hypotheses)),
        "dataset": dataset,
        "categories": CATEGORIES,
    }
    (OUT / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(summary["pytest"], indent=2))
    print(json.dumps(summary["hypothesis_totals"], indent=2))
    print(json.dumps({h["id"]: h["conclusion"] for h in hypotheses}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
