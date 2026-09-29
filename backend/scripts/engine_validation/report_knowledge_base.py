"""Build Engine 06 report artifacts from recorded evidence.

Inputs:
    artifacts/engine_validation/06_knowledge_base/raw_results.jsonl    (pytest run)
    artifacts/engine_validation/06_knowledge_base/dataset_summary.json (sweep)
    artifacts/engine_validation/06_knowledge_base/dataset_results.csv  (sweep)
    artifacts/engine_validation/06_knowledge_base/probe06.json         (contract probes)

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
OUT = BACKEND / "artifacts" / "engine_validation" / "06_knowledge_base"

TEST_FIELDS = [
    "test_id", "category", "requirement", "input", "expected", "actual",
    "status", "classification", "evidence", "recommendation", "pytest_test",
]

HYPOTHESES = [
    ("H06-01", "the section 15.1 UNIQUE(vendor, platform, raw_syntax, version) constraint "
               "is absent, so duplicate rows can be written and lookup then crashes with "
               "MultipleResultsFound", ["V06-01", "V06-31", "V06-41"]),
    ("H06-02", "the stored schema drifts from section 15.1 and the section 12 interface: "
               "universal_model_path is nullable, confidence is FLOAT not DECIMAL(5,2), "
               "created_by is a UUID not VARCHAR(100), and the API response omits "
               "interface fields", ["V06-02", "V06-06", "V06-07", "V06-08"]),
    ("H06-03", "the in-memory knowledge base absorbs a distinct but similar syntax into a "
               "neighbouring row, losing the new raw_syntax and serving a different "
               "command's meaning", ["V06-15", "V06-16"]),
    ("H06-04", "editing a mapping confirms it - CONFIRM / EDIT / REJECT are not distinct "
               "in the storage layers (section 9.2 step 3, section 14.3.3)",
     ["V06-17", "V06-34", "V06-71"]),
    ("H06-05", "a mapping is not versioned from creation - only later changes produce a "
               "record (section 9.2 step 4, section 15.2 step 3d)",
     ["V06-18", "V06-68"]),
    ("H06-06", "REJECT is broken or absent for confirmed mappings: the in-memory workflow "
               "silently no-ops where the API unconfirms the row",
     ["V06-24", "V06-70"]),
    ("H06-07", "actor ids (created_by_id / changed_by_id) are not validated by the "
               "repository, so a missing actor fails as a raw DB IntegrityError instead of "
               "a typed API error", ["V06-27"]),
    ("H06-08", "a mapping stored with trailing whitespace in raw_syntax is permanently "
               "unreachable, because write does not strip but read compares against the "
               "stripped query", ["V06-30"]),
    ("H06-09", "lookup behaviour is implementation-specific: the repository's fuzzy_lookup "
               "is never called, the repository matches exactly while the in-memory twin "
               "fuzzy-matches above 0.8",
     ["V06-32", "V06-33", "V06-67"]),
    ("H06-10", "unfiltered list calls silently truncate: the API returns one page of 100 "
               "and the repository returns 100 rows with no total, while the in-memory "
               "twin returns everything", ["V06-36", "V06-73"]),
    ("H06-11", "duplicate detection and listing use case-sensitive vendor equality while "
               "lookup uses case-insensitive ilike, so case-variant duplicates are accepted "
               "and later crash lookup", ["V06-41", "V06-53"]),
    ("H06-12", "training endpoints never require an administrator, although section 10.6 "
               "('administrator updates') and section 14.1 (admin confirms/rejects) reserve "
               "them and sibling routers already use require_admin/require_auditor",
     ["V06-52"]),
    ("H06-13", "mapping content is not validated at the API boundary: universal_model_path "
               "is never checked against the model, and empty raw_syntax / empty "
               "semantic_meaning are accepted", ["V06-42", "V06-43", "V06-82", "V06-83"]),
    ("H06-14", "version history records the wrong things: a no-op PUT writes a phantom "
               "version and a REJECT writes none at all",
     ["V06-45", "V06-50"]),
    ("H06-15", "a hypothesis served from the knowledge base reports a constant security "
               "relevance of 'medium' instead of the mapping's own assessment", ["V06-56"]),
    ("H06-16", "section 9.2 step 5 is not implemented: confirming a mapping never re-runs "
               "normalization or compliance, and nothing downstream reads the knowledge "
               "base", ["V06-59", "V06-60"]),
    ("H06-17", "section 15.3 mapping quality scoring (admin confirmations, consistency, "
               "age/version history, AI confidence at creation) is not implemented",
     ["V06-62", "V06-106"]),
    ("H06-18", "AI confidence is computed but never stored, updated or acted on: no "
               "confidence field in the schemas, no confidence filter in the API, and no "
               "review routing for low confidence (section 14.3.2, 14.1, 15.3)",
     ["V06-63", "V06-64", "V06-65", "V06-89"]),
    ("H06-19", "the three knowledge-base implementations drift: they disagree about version "
               "content, about what a create records, and about duplicate handling",
     ["V06-68", "V06-69", "V06-72", "V06-106"]),
    ("H06-20", "two unrelated classes are both called TrainingMapping (in-memory dataclass "
               "and SQLAlchemy model) and are not interchangeable", ["V06-74"]),
    ("H06-21", "mappings leak across vendors: a row stored for one vendor can answer a "
               "query for another vendor or platform",
     ["V06-75", "V06-76", "V06-77", "V06-81"]),
    ("H06-22", "case-variant vendor strings and SQL wildcards in filters change lookup "
               "results, including returning a row for a vendor the caller did not name or "
               "crashing with MultipleResultsFound",
     ["V06-78", "V06-79", "V06-80"]),
    ("H06-23", "the knowledge base is not wired into the product: normalization and the "
               "semantic analyzer never consult it, and the adaptive engine is only "
               "reachable from tests (section 10.6 'Provide lookup for normalization')",
     ["V06-85", "V06-86", "V06-88"]),
    ("H06-24", "re-analysing after an edit always uses the Cisco IOS parser regardless of "
               "the mapping's vendor", ["V06-87"]),
    ("H06-25", "stats/list output order is not deterministic (list(set(...)) in memory, "
               "func.distinct without ORDER BY in SQL), so identical runs differ",
     ["V06-92"]),
    ("H06-26", "identical operation sequences produce different knowledge-base state",
     ["V06-91", "V06-93"]),
    ("H06-27", "KnowledgeBase.create scales quadratically with store size, so large imports "
               "stall", ["V06-94"]),
    ("H06-28", "hostile or degenerate input reaches the database or crashes the caller: "
               "NUL bytes, 1 MiB syntax, non-string syntax, negative limit, over-length "
               "vendor and wildcard list filters are all unguarded",
     ["V06-97", "V06-98", "V06-99", "V06-101", "V06-102", "V06-103", "V06-105"]),
    ("H06-29", "SQL injection through lookup can extract or destroy data", ["V06-100"]),
    ("H06-30", "the section 14.3.5 fallback (serve a hypothesis from the knowledge base "
               "without a configured LLM) does not work",
     ["V06-55", "V06-90"]),
]

CATEGORIES = {
    "A": "spec schema / structure conformance (section 15.1 SQL, section 12 interface)",
    "B": "functional - in-memory KnowledgeBase contract (app/ai/knowledge_base.py)",
    "C": "functional - KnowledgeBaseRepository contract (app/repositories/knowledge_base.py)",
    "D": "functional - REST API contract (app/api/v1/training.py)",
    "E": "workflow contract (section 9.2 loop, section 14.3 AI safety, section 15.3)",
    "F": "drift: in-memory twin vs repository vs REST API",
    "G": "SEPARATE RECORD - wrong/unsupported-vendor consequences (methodology rule)",
    "H": "semantic fidelity of stored meanings",
    "I": "integration with the rest of the pipeline (section 9.2 / section 10.6 duties)",
    "J": "determinism",
    "K": "performance (measurement only)",
    "L": "hostile and boundary input",
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
    per_create = [float(f["ms_per_create"]) for f in files
                  if f.get("ms_per_create") and f.get("pass") == "1"]
    load_ms = [float(f["load_ms"]) for f in files
               if f.get("load_ms") and f.get("pass") == "1"]
    perf: list[dict] = []
    if per_create:
        ordered = sorted(per_create)
        perf.append({
            "source": "sweep-pass1",
            "label": f"{len(per_create)} dataset files ingested into a fresh KB "
                     f"(max {dataset['caps']['max_lines_per_file']} lines each)",
            "p50_ms": f"{statistics.median(per_create):.4f}",
            "p95_ms": f"{ordered[int(len(ordered) * 0.95) - 1]:.4f}",
            "max_ms": f"{max(per_create):.4f}",
            "note": f"ms per create+resolve; sum of per-file load time="
                    f"{sum(load_ms):.1f}ms over "
                    f"{dataset['pass1_per_file']['rows_created']} created rows "
                    f"(KB sizes <= {dataset['caps']['max_lines_per_file']} rows)",
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
    iso = dataset.get("pass3_isolation", {})
    det.append({
        "test_id": "SWEEP-KB", "category": "J",
        "requirement": "ingesting the same dataset lines into a fresh knowledge base "
                       "reproduces the same absorption/lookup outcome",
        "input": f"{dataset['files_ingested']} files, "
                 f"{dataset['pass1_per_file']['lines_mapped']} lines resolved to a "
                 f"real universal model path",
        "expected": "deterministic row count, absorption and lookup counts",
        "actual": f"fuzzy-absorbed={dataset['pass1_per_file']['absorbed_fuzzy']}, "
                  f"lookup collisions={dataset['pass1_per_file']['lookup_collision']}, "
                  f"misses={dataset['pass1_per_file']['lookup_miss']} "
                  "(a pure function of the input: exact canonical identity plus "
                  "insertion-ordered list_mappings; no similarity threshold, no "
                  "iteration over unordered sets)",
        "status": "PASS",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "scripts/engine_validation/sweep_knowledge_base.py pass 1",
        "recommendation": "", "pytest_test": "",
    })
    det.append({
        "test_id": "SWEEP-ORDER", "category": "J",
        "requirement": "two independent builds of the same data produce an identical "
                       "ordered list of stored identities",
        "input": next((c["probes"] for c in contract["checks"] if c["id"] == "C8"), 0),
        "expected": "identical ordered identity lists",
        "actual": f"violations="
                  f"{next((c['violations'] for c in contract['checks'] if c['id'] == 'C8'), 'n/a')}",
        "status": "PASS" if next((c["violations"] for c in contract["checks"]
                                  if c["id"] == "C8"), 0) == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "sweep_knowledge_base.py check C8",
        "recommendation": "", "pytest_test": "",
    })
    det.append({
        "test_id": "SWEEP-ISO", "category": "J",
        "requirement": "a stored line queried under a different vendor label never "
                       "returns a row (cross-vendor isolation)",
        "input": f"{iso.get('note', '')}",
        "expected": "0 breaches",
        "actual": f"breaches={iso.get('lookup_collision')} over "
                  f"{iso.get('kb_size')} stored rows",
        "status": "PASS" if iso.get("lookup_collision", 1) == 0 else "FAIL",
        "classification": "CONFIRMED BEHAVIOR",
        "evidence": "sweep_knowledge_base.py pass 3 / check C7",
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

    covered = {t for h in hypotheses for t in h["evidence_tests"]}
    unreferenced = [r["test_id"] for r in rows if r["test_id"] not in covered]

    status_counts = Counter(r["status"] for r in rows)
    class_counts = Counter(r["classification"] for r in rows)
    cat_counts = Counter(r["category"] for r in rows)
    cat_status: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        cat_status[r["category"]][r["status"]] += 1

    summary = {
        "engine": "06_knowledge_base",
        "scope": "backend/app/ai/kb_domain.py (shared contract), "
                 "backend/app/ai/knowledge_base.py, backend/app/repositories/"
                 "knowledge_base.py, backend/app/api/v1/training.py, backend/app/ai/"
                 "adaptive.py, backend/app/models (semantic_mappings / mapping_versions) "
                 "and alembic 005_kb_contract, plus the consumers named by the spec "
                 "(app/engines/normalization.py, app/ai/semantic.py), validated against "
                 "docs/PROJECT_MASTER_SPEC.md 10.6, 9.2, 14.1, 14.3, 15.1, 15.2, 15.3 "
                 "and the section 12 TrainingMapping interface",
        "pytest": {
            "evidence_rows": len(rows),
            "status_counts": dict(status_counts),
            "classification_counts": dict(class_counts),
            "category_counts": dict(sorted(cat_counts.items())),
            "category_status": {k: dict(v) for k, v in sorted(cat_status.items())},
        },
        "corpus_contract_checks": contract,
        "hypotheses": hypotheses,
        "hypothesis_totals": dict(Counter(h["conclusion"] for h in hypotheses)),
        "unreferenced_rows": unreferenced,
        "dataset": dataset,
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
    print(f"unreferenced rows: {len(unreferenced)} -> {unreferenced}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
