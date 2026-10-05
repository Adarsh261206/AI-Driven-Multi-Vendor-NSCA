"""Build Engine 08 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/08_findings/raw_results.jsonl    (pytest run)
    artifacts/engine_validation/08_findings/dataset_summary.json (sweep)
    artifacts/engine_validation/08_findings/dataset_results.csv  (sweep)

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
OUT = BACKEND / "artifacts" / "engine_validation" / "08_findings"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H08-01", "one Finding concept, four field sets: the section 12 "
               "interface, the engine dataclass, the findings table (model + "
               "section 19.1 DDL) and the API response disagree - the "
               "dataclass has no compliance_result_id but carries "
               "audit_id/risk_score/priority/result, the table adds "
               "affected_platform, and the four shapes were never "
               "reconciled",
     ["V08-01", "V08-05", "V08-58"]),
    ("H08-02", "FindingResponse omits control_id (section 12 Finding field "
               "3), so API consumers of either list endpoint cannot see "
               "which control a finding came from while the engine record "
               "has it",
     ["V08-02"]),
    ("H08-03", "severity vocabulary drifts from the spec: Severity enum and "
               "the persisted findings.severity use lowercase "
               "(critical/high/medium/low) where section 12 / DATA_MODEL "
               "mandate CRITICAL/HIGH/MEDIUM/LOW, and the API only "
               "upper-cases on the way out",
     ["V08-03", "V08-42"]),
    ("H08-04", "the evidence attached to findings deviates from section 12: "
               "the API types it as Optional[dict] (no chain structure "
               "enforced) and the executor-built chain carries "
               "result_reasoning instead of reasoning, has no "
               "security_control, and leaves raw_config empty - the same "
               "drift engine 07 recorded at the chain source (V07-46/47, "
               "upstream context only)",
     ["V08-06", "V08-37"]),
    ("H08-05", "the remediation attached to findings does not carry the "
               "section 12 Remediation interface: the executor builds "
               "title/description/confidence and never sets finding_id, "
               "finding_title or risk_description (executor.py:336-347)",
     ["V08-09"]),
     ("H08-06", "finding status changes are not audited: "
               "AuditTrailRepository.log_finding_update (audit_trail.py:142) "
               "ships zero callers, so spec 9.1 step 13 'Audit Trail stores "
               "complete history' sees nothing when a finding moves to "
               "resolved",
      ["V08-46", "V08-92", "V08-93"]),
     ("H08-07", "the notes field accepted by FindingStatusUpdate are dropped "
               "on the floor - the handler writes only status and the "
               "response exposes no notes",
      ["V08-47", "V08-92", "V08-93"]),
    ("H08-08", "the documented list endpoint GET /api/v1/audits/:id/findings "
               "(section 20.2) is not routed; listing lives at "
               "/findings/audit/{id} and /audit-execution/{id}/findings and "
               "audits.py has no findings route",
     ["V08-49"]),
    ("H08-09", "the two list endpoints drift: they order differently "
               "(created_at DESC vs lexicographic severity, which lists LOW "
               "above MEDIUM), and one validates the status filter as an "
               "enum while the other accepts any string and silently "
               "matches nothing",
     ["V08-53", "V08-54", "V08-55"]),
    ("H08-10", "filtering findings by the spec severity vocabulary is "
               "unusable: severity is stored lowercase, so "
               "?severity=CRITICAL returns 0 rows on both endpoints while "
               "the stored value is 'critical'",
     ["V08-56"]),
    ("H08-11", "SEPARATE RECORD (category G): findings describe the "
               "declared vendor, not the device's true vendor - the "
               "generator trusts evaluation.vendor, so a juniper config "
               "declared cisco yields 164 findings with 9 missed (raised by "
               "the true-vendor audit) and 8 false positives (PASS under "
               "juniper, FAIL-derived under the declared cisco selection); "
               "engine 07 V07-72/73 upstream context only",
     ["V08-60", "V08-61"]),
    ("H08-12", "SEPARATE RECORD (category G): an unsupported vendor "
               "(arista - no mapper, no benchmark) gets decisive FAIL "
               "findings from absent raw text instead of REVIEW "
               "(spec 13.4); engine 07 V07-74 upstream context only",
     ["V08-62"]),
    ("H08-13", "SEPARATE RECORD (category G): an empty configuration "
               "yields FAIL-derived findings instead of none/REVIEW "
               "(spec 13.4 insufficient evidence)",
     ["V08-63"]),
    ("H08-14", "the audit step text advertises 'ML risk scoring "
               "(RandomForest)' even when the ML model is unavailable and "
               "the deterministic formula path runs (audit_execution.py:434)",
     ["V08-77"]),
    ("H08-15", "hostile inputs surface raw internal errors: a None "
               "evaluation raises AttributeError instead of a validation "
               "failure, and a 1 MB affected_device reaches the database "
               "and dies as StringDataRightTruncation instead of being "
               "rejected at the API",
     ["V08-84", "V08-89"]),
    # --- rejected (predictions that did NOT hold) -----------------------
    ("H08-16", "the happy-path generation contract fails: REVIEW "
               "evaluations do not become findings, PASS leaks into "
               "findings, counts drift from failed+review, ids collide, or "
               "control/title/reasoning/status/audit linkage is missing",
     ["V08-11", "V08-12", "V08-13", "V08-14", "V08-15", "V08-16", "V08-17",
      "V08-18", "V08-19", "V08-20", "V08-21", "V08-22", "V08-23", "V08-24"]),
    ("H08-17", "severity/confidence/risk assignment violates its contract: "
               "control severities hit the silent MEDIUM default, "
               "confidence is invented or outside [0, 1], risk leaves "
               "0-100 or does not increase with severity",
     ["V08-25", "V08-26", "V08-27", "V08-28", "V08-29", "V08-30", "V08-31",
      "V08-32", "V08-33"]),
    ("H08-18", "findings are not linked to their compliance results or "
               "their evidence chains are not carried on the record",
     ["V08-34", "V08-35", "V08-36", "V08-38", "V08-39", "V08-40", "V08-41", "V08-94"]),
    ("H08-19", "findings are not persisted or the endpoints do not serve "
               "stored findings: severity/status counters, summary "
               "buckets, status persistence, pagination or ownership "
               "checks fail",
     ["V08-43", "V08-44", "V08-45", "V08-48", "V08-50", "V08-51"]),
    ("H08-20", "the two list endpoints return different record sets or "
               "different filter results for the same audit",
     ["V08-52", "V08-57", "V08-59", "V08-97", "V08-98"]),
    ("H08-21", "the offline pipeline does not run findings end to end: the "
               "step never executes, the step record is missing, the "
               "response contract fields are absent, or ownership/404 "
               "checks fail",
     ["V08-70", "V08-71", "V08-72", "V08-73", "V08-74", "V08-75", "V08-76", "V08-95"]),
    ("H08-22", "finding generation is non-deterministic across runs",
     ["V08-78", "V08-79", "V08-80"]),
    ("H08-23", "performance is unusable or super-linear on large inputs",
     ["V08-81", "V08-82", "V08-83"]),
    ("H08-24", "hostile inputs bypass validation entirely: PASS-only or "
               "empty evaluations still yield findings, an invalid status "
               "is accepted, filters execute injection payloads, or "
               "non-ASCII content breaks generation",
     ["V08-85", "V08-86", "V08-87", "V08-88", "V08-90", "V08-91", "V08-96"]),
    ("H08-25", "basic structure conformance fails: status vocabulary, NOT "
               "NULL columns, section 19.2 indexes or title column limits "
               "are wrong",
     ["V08-04", "V08-07", "V08-08", "V08-10"]),
    ("H08-26", "semantic fidelity invariants are violated: severity "
               "fabricated or blank, confidence/evidence drift from the "
               "evaluation, or wording claims failure for REVIEW findings",
     ["V08-64", "V08-65", "V08-66", "V08-67", "V08-68", "V08-69"]),
]

CATEGORIES = {
    "A": "spec structure conformance (section 12 Finding/Remediation/"
         "EvidenceChain, DDL, section 19.2 indexes)",
    "B": "functional - finding generation contract (section 9.1 step 7, "
         "10.8 'Create finding records')",
    "C": "functional - severity / confidence / risk assignment (section 10.8, "
         "10.9 boundary)",
    "D": "functional - evidence chain linkage (section 10.8 'Link evidence "
         "chains', section 12)",
    "E": "persistence + API contract (section 14.3.2, section 20.2)",
    "F": "drift: two findings list implementations",
    "G": "SEPARATE RECORD - wrong/unsupported-vendor consequences "
         "(methodology rule)",
    "H": "semantic fidelity invariants (no fabricated findings)",
    "I": "integration with the rest of the pipeline (section 9.1)",
    "J": "determinism",
    "K": "performance (measurement only)",
    "L": "hostile and boundary input",
    "M": "audit trail / status lifecycle (spec 9.1 step 13)",
    "N": "evidence persistence round-trip",
    "O": "remediation persistence round-trip",
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
                 "normalization -> evaluation -> finding generation)",
        "p50_ms": dataset["exec_ms"]["p50"],
        "p95_ms": dataset["exec_ms"]["p95"],
        "max_ms": dataset["exec_ms"]["max"],
        "note": f"total {dataset['elapsed_s']}s; per-finding ML inference "
                "(one sklearn predict per finding) dominates",
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
        "requirement": "re-running corpus files reproduces identical "
                       "finding counts and executor statuses",
        "input": next((c["probes"] for c in contract["checks"]
                       if c["id"] == "C7"), 0),
        "expected": "identical outcomes",
        "actual": f"violations="
                  f"{next((c['violations'] for c in contract['checks'] if c['id'] == 'C7'), 'n/a')}",
        "status": "PASS" if next((c["violations"] for c in contract["checks"]
                                  if c["id"] == "C7"), 0) == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "sweep_findings.py check C7",
        "recommendation": "", "pytest_test": "",
    })
    write_csv("determinism_results.csv", TEST_FIELDS, det)

    # ---- security / wrong-vendor / fidelity / hostile ----------------
    write_csv("security_results.csv", TEST_FIELDS,
              [r for r in rows if r["category"] in {"G", "H", "L"}])
    # ---- audit trail / round-trips -----------------------------------
    write_csv("lifecycle_results.csv", TEST_FIELDS,
              [r for r in rows if r["category"] in {"M", "N", "O"}])

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
        "engine": "08_findings",
        "scope": "backend/app/engines/compliance/{findings,models,evidence,"
                 "executor}.py (step 6), backend/app/api/v1/"
                 "{findings,audit_execution,audits,router}.py, backend/app/"
                 "schemas (FindingResponse/FindingStatus/Remediation/"
                 "FindingStatusUpdate/EvidenceChain), backend/app/models "
                 "(Finding), backend/app/repositories/{findings,audit_trail}.py"
                 " + alembic 007, validated against "
                 "docs/PROJECT_MASTER_SPEC.md 9.1 step 7, 10.8, 10.9 "
                 "(boundary), 12 Finding/Remediation/EvidenceChain, 13.4, "
                 "14.3.2, 19.1 findings DDL, 19.2 indexes, 20.2 findings "
                 "endpoints and 20.7 findings UI",
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
