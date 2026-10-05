"""Corpus sweep for Engine 12 (Audit Trail, spec 10.12).

For every file in the 480-file dataset: run the real AuditExecutor
(in-memory), sanitize every finding payload (evidence + remediation +
risk) to JSONB-safe form, and persist ONE compliance-evaluation trail
row per file — with a Decimal probe field (the pre-fix live crash) —
against the throwaway database. Query checks then verify exact-set
retrieval, and the whole sweep ROLLS BACK (no residue by design).

entity_id per file is uuid5(NAMESPACE_URL, relpath): stable across runs,
so re-runs address the same rows.

Outputs (artifacts/engine_validation/12_audit_trail/):
    dataset_results.csv  dataset_summary.json  contract_results.json
"""

from __future__ import annotations

import asyncio
import csv
import json
import statistics
import sys
import time
import traceback
import uuid
from decimal import Decimal
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))

from app.engines.compliance.executor import AuditExecutor  # noqa: E402
from app.models import AuditAction  # noqa: E402
from app.repositories.audit_trail import (  # noqa: E402
    AuditTrailError,
    AuditTrailRepository,
    sanitize_details,
)
from sqlalchemy import func, select  # noqa: E402

from app.models import AuditTrail  # noqa: E402
import scripts.engine_validation.dbutil as dbutil  # noqa: E402

CORPUS = Path(r"C:\Users\priye\Downloads\SIH Config\final-dataset")
OUT = BACKEND / "artifacts" / "engine_validation" / "12_audit_trail"

LOG_BUDGET_MS = 5000.0
QUERY_SAMPLE = 30


def _plain(value):
    return value.value if hasattr(value, "value") else value


def finding_payload(f) -> dict:
    return {
        "evidence": dict(f.evidence) if isinstance(f.evidence, dict)
        else {"raw": str(f.evidence)},
        "remediation": dict(f.remediation)
        if isinstance(f.remediation, dict) else {},
        "risk": {"risk_score": f.risk_score, "priority": _plain(f.priority),
                 "severity": _plain(f.severity),
                 "confidence": f.confidence},
    }


async def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in CORPUS.rglob("*") if p.is_file())
    assert len(files) == 480, f"expected 480 corpus files, got {len(files)}"

    engine = AuditExecutor()
    eng, factory = dbutil.make_session_factory()
    session = factory()
    rows: list[dict] = []
    c1_errors: list[str] = []
    c1_typed: list[str] = []
    c2_bad: list[str] = []
    c3_bad: list[str] = []
    c4_bad: list[str] = []
    c7_over: list[str] = []
    log_ms: list[float] = []
    total_findings = 0
    sanitized_payloads = 0
    t0 = time.perf_counter()
    before = (await session.execute(
        select(func.count(AuditTrail.id)))).scalar() or 0

    try:
        for idx, path in enumerate(files, 1):
            text = path.read_text(encoding="utf-8", errors="replace")
            fname = path.relative_to(CORPUS).as_posix()
            row: dict = {"file": fname}
            try:
                run = engine.execute(
                    audit_id=f"e12sw-{fname}", config_content=text,
                    device_name=fname)
                findings = run.findings or []
                row["exec_status"] = run.status
                row["findings"] = len(findings)
                total_findings += len(findings)

                # C3: every finding payload sanitizes + serializes.
                bad_payloads = 0
                for f in findings:
                    try:
                        clean = sanitize_details(finding_payload(f))
                        json.dumps(clean)
                        sanitized_payloads += 1
                    except Exception:
                        bad_payloads += 1
                if bad_payloads:
                    c3_bad.append(f"{fname}:{bad_payloads}")
                row["payloads_bad"] = bad_payloads

                # One compliance row per file (system entry, NULL user)
                # with a Decimal probe field (pre-fix flush crash).
                details = {
                    "audit_id": f"e12sw-{fname}",
                    "total_controls": int(getattr(run, "total_controls",
                                                  0) or 0),
                    "passed": int(getattr(run, "passed", 0) or 0),
                    "failed": int(getattr(run, "failed", 0) or 0),
                    "review": int(getattr(run, "review", 0) or 0),
                    "overall_score": float(run.overall_score or 0.0),
                    "kb_confidence": Decimal(str(run.overall_score or 0)),
                    "e12": fname,
                }
                try:
                    json.dumps(details)
                    c2_bad.append(f"{fname}:raw-serializable-unexpected")
                except TypeError:
                    pass  # expected: raw Decimal is not JSON-serializable
                repo = AuditTrailRepository(session)
                start = time.perf_counter()
                entry = await repo.log(
                    action=AuditAction.COMPLIANCE_EVALUATED,
                    entity_type="audit",
                    entity_id=uuid.uuid5(uuid.NAMESPACE_URL, fname),
                    user_id=None,
                    details=details)
                log_ms.append((time.perf_counter() - start) * 1000.0)
                row["log_ms"] = round(log_ms[-1], 1)
                row["entry_id"] = str(entry.id)
                if log_ms[-1] > LOG_BUDGET_MS:
                    c7_over.append(f"{fname}:{log_ms[-1]:.0f}ms")
                row["error"] = ""
            except AuditTrailError as e:
                c1_typed.append(f"{fname}:{e}")
                row["error"] = f"TYPED {e}"
            except Exception as e:  # noqa: BLE001
                c1_errors.append(f"{fname}:{type(e).__name__}:{e}")
                row["error"] = f"{type(e).__name__}:{e}"
                traceback.print_exc()
            rows.append(row)
            if idx % 60 == 0:
                print(f"{idx}/{len(files)} files...")

        await session.flush()

        # C4: every Decimal probe persisted as float (live-bug scale check).
        repo = AuditTrailRepository(session)
        sample_step = max(1, len(files) // QUERY_SAMPLE)
        c5_bad: list[str] = []
        c6_bad: list[str] = []
        for path in files[::sample_step][:QUERY_SAMPLE]:
            fname = path.relative_to(CORPUS).as_posix()
            eid = uuid.uuid5(uuid.NAMESPACE_URL, fname)
            got = await repo.get_entries(entity_type="audit",
                                         entity_id=str(eid))
            ours = [r for r in got
                    if (r.details or {}).get("e12") == fname]
            if len(ours) != 1:
                c5_bad.append(f"{fname}:rows={len(ours)}")
                continue
            conf = ours[0].details.get("kb_confidence")
            if not isinstance(conf, float):
                c4_bad.append(f"{fname}:kb_confidence={conf!r}")
            # C6: re-query returns the same set.
            again = {r.id for r in await repo.get_entries(
                entity_type="audit", entity_id=str(eid))}
            if {r.id for r in got} != again:
                c6_bad.append(fname)

        n_eval = await repo.count_entries(
            action=AuditAction.COMPLIANCE_EVALUATED)
        n_type = await repo.count_entries(entity_type="audit")
        if n_eval < len(files) or n_type < len(files):
            c5_bad.append(f"counts: action={n_eval} type={n_type} "
                          f"files={len(files)}")
    finally:
        await session.rollback()
        after = (await session.execute(
            select(func.count(AuditTrail.id)))).scalar() or 0
        await session.close()
        await eng.dispose()

    residue = after - before
    checks = [
        {"id": "C1", "name": "no untyped errors across the corpus",
         "probes": len(files), "violations": len(c1_errors),
         "detail": c1_errors[:10]},
        {"id": "C1t", "name": "no typed contract errors either",
         "probes": len(files), "violations": len(c1_typed),
         "detail": c1_typed[:10]},
        {"id": "C2", "name": "sanitize does real work: raw Decimal payloads "
                             "rejected by json pre-sanitize",
         "probes": len(files), "violations": len(c2_bad),
         "detail": c2_bad[:10]},
        {"id": "C3", "name": "every finding payload sanitizes + serializes",
         "probes": sanitized_payloads + sum(
             1 for _ in c3_bad), "violations": len(c3_bad),
         "detail": c3_bad[:10]},
        {"id": "C4", "name": "Decimal probes persisted as floats",
         "probes": QUERY_SAMPLE, "violations": len(c4_bad),
         "detail": c4_bad[:10]},
        {"id": "C5", "name": "entity/action/type queries return exact sets",
         "probes": QUERY_SAMPLE + 2, "violations": len(c5_bad),
         "detail": c5_bad[:10]},
        {"id": "C6", "name": "re-queries return identical sets",
         "probes": QUERY_SAMPLE, "violations": len(c6_bad),
         "detail": c6_bad[:10]},
        {"id": "C7", "name": f"log+flush under {LOG_BUDGET_MS:.0f}ms",
         "probes": len(log_ms), "violations": len(c7_over),
         "detail": c7_over[:10]},
    ]
    total_viol = sum(c["violations"] for c in checks)
    if residue != 0:
        # The sweep must leave no rows behind (rollback by design).
        checks.append({"id": "C0", "name": "zero DB residue after rollback",
                       "probes": 1, "violations": 1,
                       "detail": [f"residue={residue}"]})
        total_viol += 1
    summary = {
        "files": len(files),
        "ok_files": sum(1 for r in rows if not r.get("error")),
        "errors": len(c1_errors) + len(c1_typed),
        "elapsed_s": round(time.perf_counter() - t0, 1),
        "findings": total_findings,
        "finding_payloads_sanitized": sanitized_payloads,
        "db_residue_rows": residue,
        "log_ms": {
            "p50": round(statistics.median(log_ms), 1) if log_ms else 0,
            "p95": round(sorted(log_ms)[int(len(log_ms) * 0.95)], 1)
            if log_ms else 0,
            "max": round(max(log_ms), 1) if log_ms else 0,
        },
        "contract_checks": checks,
        "contract_violations_total": total_viol,
        "contract_verdict": "PASS" if total_viol == 0 else "FAIL",
    }
    with open(OUT / "dataset_results.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["file", "exec_status",
                                           "findings", "payloads_bad",
                                           "log_ms", "entry_id", "error"])
        w.writeheader()
        w.writerows(rows)
    (OUT / "dataset_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    (OUT / "contract_results.json").write_text(
        json.dumps({"checks": checks, "violations_total": total_viol,
                    "verdict": summary["contract_verdict"]}, indent=2),
        encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items()
                      if k not in ("contract_checks",)}, indent=2))
    for c in checks:
        print(f"   {c['id']} {c['name']}: {c['probes']} probes, "
              f"{c['violations']} violations")
    return 0 if total_viol == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
