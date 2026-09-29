"""Build Engine 07 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/07_compliance/raw_results.jsonl    (pytest run)
    artifacts/engine_validation/07_compliance/dataset_summary.json (sweep)
    artifacts/engine_validation/07_compliance/dataset_results.csv  (sweep)
    artifacts/engine_validation/07_compliance/probe07.json         (contract probes)

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
OUT = BACKEND / "artifacts" / "engine_validation" / "07_compliance"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H07-01", "framework selection is a no-op: AuditExecutor.execute accepts "
               "framework/framework_version but never reads them, so the API's "
               "framework request (audit_execution.py:241-246) cannot select "
               "rules (spec 9.1 step 6, spec 10.7 'Load framework rules') and "
               "framework_version is never persisted (spec 12)",
     ["V07-17", "V07-55", "V07-99", "V07-100", "V07-101"]),
    ("H07-02", "control selection depends on caller-supplied casing: registry "
               "keys are exact-case, so vendor='Cisco' silently drops all 53 "
               "CIS controls and platform='JUNOS' drops all 17 juniper "
               "controls (only the cisco platform alias is normalized)",
     ["V07-14", "V07-15", "V07-16"]),
    ("H07-03", "the controls API cannot filter correctly: a vendor-only "
               "request returns every CIS control, the ios->ios_xe alias is "
               "missing (platform=ios returns 0), and the registry's "
               "platform-only filter ignores platform",
     ["V07-19", "V07-20", "V07-21", "V07-100", "V07-113"]),
    ("H07-04", "three operator vocabularies drift (models.Operator enum, "
               "canonical engine, ControlRegistry): the spec's 'in' operator "
               "is unimplemented, the registry falls through to equality for "
               "greater/less_than_or_equal (wrong verdicts for the juniper "
               "controls that use them), and unknown operators silently "
               "evaluate as equals",
     ["V07-07", "V07-08", "V07-33", "V07-34"]),
    ("H07-05", "control structure defects make six controls permanently "
               "REVIEW (target.model_path values that are not Universal "
               "Security Model leaves) and let a duplicate control_id "
               "silently overwrite another vendor's control in the registry",
     ["V07-05", "V07-10"]),
    ("H07-06", "framework attribution is derived, not stored: controls carry "
               "no framework field, persistence infers it from the control-id "
               "shape, a user who requests NIST gets their CIS rows labelled "
               "NIST (and reports filter on that label), the API advertises "
               "framework versions no control carries, and the report list "
               "hardcodes framework='CIS'",
     ["V07-03", "V07-57", "V07-58", "V07-62", "V07-25"]),
    ("H07-07", "the section 13.3 step 4 confidence model is unimplemented: "
               "controls have no rule-confidence field, normalization "
               "confidence never reaches the evidence (always 0.0), result "
               "confidence is a hardcoded constant, and the section 13.4 "
               "<70%-confidence REVIEW trigger exists only in the dead legacy "
               "path",
     ["V07-43", "V07-44"]),
    ("H07-08", "evidence chains deviate from spec 12 and spec 13.3: the "
               "canonical evidence lacks raw_config/parsed_value/"
               "security_control/reasoning, the persisted chain never "
               "populates parsed_value, a multi-block decisive result leaves "
               "normalized_value null, two decisive controls carry no raw "
               "evidence lines, and regex-only controls PASS/FAIL with no "
               "normalized value at all",
     ["V07-37", "V07-38", "V07-46", "V07-47", "V07-48", "V07-49"]),
    ("H07-09", "one audit run exposes two different overall_score values - "
               "passed/evaluated (46.9) on AuditResult and "
               "passed/(passed+failed) (95.5) on ComplianceEvaluation - so "
               "downstream consumers can report either",
     ["V07-42", "V07-116"]),
    ("H07-10", "SEPARATE RECORD (category G): control selection and verdicts "
               "are produced for wrong or unsupported inputs - the engine "
               "trusts its caller over detection, unsupported vendors get "
               "NIST verdicts (including decisive FAILs) evaluated from raw "
               "text, and an empty configuration yields two decisive FAILs "
               "instead of REVIEW (spec 13.4)",
     ["V07-72", "V07-73", "V07-74", "V07-75", "V07-111", "V07-112"]),
    ("H07-11", "two control systems coexist with drift: the legacy loader/"
               "RuleEngine (10 controls, no NIST) vs the canonical registry "
               "(196), platform labels ios vs ios_xe make legacy rules "
               "inapplicable, applicability contracts differ, and is_set/"
               "regex_match semantics disagree between the evaluators",
     ["V07-63", "V07-65", "V07-66", "V07-67", "V07-69", "V07-70"]),
    ("H07-12", "persistence drifts from the spec: result values are stored "
               "lowercase ('pass') where spec 12 mandates PASS/FAIL/REVIEW, "
               "and the table's link column / confidence precision differ "
               "from the spec DDL (which itself disagrees with the spec-12 "
               "interface)",
     ["V07-59", "V07-60", "V07-102", "V07-103", "V07-104", "V07-105"]),
    ("H07-13", "unknown vendors are silently parsed with CiscoIOSParser, so "
               "detection, parsing and normalization disagree about the "
               "device before evaluation ever runs",
     ["V07-83"]),
    ("H07-14", "hostile inputs lose their error signal: None input surfaces "
               "a raw AttributeError string, an invalid (NUL) config fails "
               "with no step recording why (validation is marked completed), "
               "and a control with an invalid audit_regex yields a confident "
               "FAIL for every input",
     ["V07-91", "V07-92", "V07-93", "V07-96", "V07-97", "V07-98"]),
    ("H07-15", "dead rule data remains in the tree: framework_mappings.py has "
               "zero referencing modules, and the executor still imports the "
               "retired ControlLoader/RuleEngine without using them",
     ["V07-68", "V07-71"]),
    ("H07-16", "result metadata understates the dual baseline: benchmark_id "
               "is taken from controls[0], so a run that evaluated 126 NIST "
               "controls alongside CIS is labelled as a single CIS benchmark",
     ["V07-26"]),
    # --- rejected (predictions that did NOT hold) -----------------------
    ("H07-17", "selection loses or duplicates controls under normal "
               "(correct-case) inputs",
     ["V07-11", "V07-13", "V07-27"]),
    ("H07-18", "the truth tables of the supported operators "
               "(equals/not_equals/contains/greater_than/less_than/"
               "*_or_equal) are wrong",
     ["V07-28", "V07-29", "V07-30", "V07-31", "V07-32"]),
    ("H07-19", "verdicts are fabricated: missing values or manual controls "
               "produce PASS/FAIL instead of REVIEW",
     ["V07-35", "V07-36", "V07-39", "V07-76", "V07-77", "V07-78"]),
    ("H07-20", "evaluation is non-deterministic across runs",
     ["V07-85", "V07-86", "V07-87", "V07-106", "V07-107"]),
    ("H07-21", "the offline pipeline does not run end to end or findings are "
               "not wired from the evaluation",
     ["V07-79", "V07-80", "V07-81", "V07-82", "V07-114", "V07-115"]),
    ("H07-22", "performance is unusable or super-quadratic on large inputs",
     ["V07-88", "V07-89", "V07-90", "V07-95", "V07-108", "V07-109", "V07-110"]),
    ("H07-23", "the API inventory or the current-inventory framework "
               "inference is wrong (missing controls, wrong labels)",
     ["V07-22", "V07-23", "V07-24", "V07-56", "V07-84"]),
    ("H07-24", "the retired legacy pipeline still executes in production "
               "(double scoring / double evaluation)",
     ["V07-64"]),
    ("H07-25", "confidence or remediation disagree between the benchmark and "
               "legacy layers after conversion",
     ["V07-52", "V07-53"]),
    ("H07-26", "the loaded inventory is missing spec-13.2 structure, "
               "severity vocabulary, supported operators or unique ids",
     ["V07-01", "V07-02", "V07-04", "V07-06", "V07-09"]),
    ("H07-27", "the cisco platform alias and the unsupported-vendor NIST "
               "fallback are broken",
     ["V07-12", "V07-18"]),
    ("H07-28", "conflicting duplicate settings or negated controls produce "
               "unsafe verdicts (guessed PASS/FAIL instead of REVIEW)",
     ["V07-40", "V07-41"]),
    ("H07-29", "the persisted audit score or counts are inconsistent with "
               "the evaluation",
     ["V07-45", "V07-61"]),
    ("H07-30", "per-row evidence is missing operator/reasoning or is not "
               "wired into persistence",
     ["V07-50", "V07-51", "V07-54"]),
    ("H07-31", "non-ASCII (unicode) content breaks evaluation",
     ["V07-94"]),
]

CATEGORIES = {
    "A": "spec structure conformance (section 13.1 / 13.2 control structure)",
    "B": "functional - control selection (which controls run; section 10.7, 9.1 step 6)",
    "C": "functional - deterministic evaluation logic (section 13.3 / 13.4)",
    "D": "functional - evidence chains (section 13.3 step 3, section 12)",
    "E": "framework attribution + persistence contract (section 12, DDL, 14.3.2)",
    "F": "drift: legacy engines.compliance vs canonical benchmarks",
    "G": "SEPARATE RECORD - wrong/unsupported-vendor consequences (methodology rule)",
    "H": "semantic fidelity invariants (no fabricated verdicts)",
    "I": "integration with the rest of the pipeline (section 9.1)",
    "J": "determinism",
    "K": "performance (measurement only)",
    "L": "hostile and boundary input",
    "M": "error handling - typed errors, failed steps, no swallowed faults",
    "N": "persistence - framework/version/score/result/enum/link contract",
    "O": "determinism - repeated and fresh-instance runs",
    "P": "performance - registry load, selection, evaluation, audit",
    "Q": "security - hostile input, injection safety, no fabricated verdicts",
    "R": "end-to-end pipeline - request to persistence to reports",
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
        "label": f"{dataset['files']} dataset files through detection + "
                 "normalization + control evaluation",
        "p50_ms": "", "p95_ms": "", "max_ms": "",
        "note": f"total {dataset['elapsed_s']}s (avg "
                f"{round(dataset['elapsed_s'] * 1000 / max(dataset['files'], 1), 1)} "
                "ms/file, incl. interpreter + engine cold start)",
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
    det = [r for r in rows if r["category"] in {"J", "O"}]
    det.append({
        "test_id": "SWEEP-C2", "category": "O",
        "requirement": "re-running corpus files with a fresh engine reproduces "
                       "identical selection, verdicts, score and status",
        "input": next((c["probes"] for c in contract["checks"]
                       if c["id"] == "C2"), 0),
        "expected": "identical outcomes",
        "actual": f"violations="
                  f"{next((c['violations'] for c in contract['checks'] if c['id'] == 'C2'), 'n/a')}",
        "status": "PASS" if next((c["violations"] for c in contract["checks"]
                                  if c["id"] == "C2"), 0) == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "sweep_compliance.py check C2",
        "recommendation": "", "pytest_test": "",
    })
    write_csv("determinism_results.csv", TEST_FIELDS, det)

    # ---- security / wrong-vendor / fidelity / hostile ----------------
    write_csv("security_results.csv", TEST_FIELDS,
              [r for r in rows if r["category"] in {"G", "H", "L", "Q"}])

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
        "engine": "07_compliance",
        "scope": "backend/app/benchmarks/{selection,registry,execution,models,"
                 "cisco_ios_xe_controls,juniper_junos_controls,"
                 "nist_sp800_53_controls,framework_mappings}.py, backend/app/"
                 "engines/compliance/{models,loader,engine,evidence,executor,"
                 "findings,cisco_controls}.py, backend/app/api/v1/"
                 "{compliance,audit_execution,reports}.py and backend/app/"
                 "models (compliance_results) + alembic 006, validated against "
                 "docs/PROJECT_MASTER_SPEC.md 9.1 step 6, 10.7, 12, 13.1-13.4, "
                 "14.3.2 and the compliance_results DDL",
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
