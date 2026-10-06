"""Offline smoke: full local flow with OPENAI_API_KEY unset.

Proves (with the key absent from the environment, as in .env):
1. configuration analysis runs locally (executor: detect -> parse ->
   normalize -> evaluate -> findings with risk + remediation)
2. PDF reporting renders locally from that output
3. audit-trail writes form a linked chain (genesis-anchored or
   continuing the live head)
4. the AI layer falls back to MockAIProvider (no network)

Writes artifacts/engine_validation/12_audit_trail/offline_smoke.json.
Cleans up its trail rows (tracked ids).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))
OUT = BACKEND / "artifacts" / "engine_validation" / "12_audit_trail"

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": str(detail)[:300]})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")


async def main() -> int:
    import scripts.engine_validation.dbutil as dbutil
    from sqlalchemy import delete

    from app.ai.client import create_ai_client
    from app.engines.compliance.executor import AuditExecutor
    from app.engines.reporting import generate_audit_report
    from app.models import AuditAction, AuditTrail
    from app.repositories.audit_trail import AuditTrailRepository

    assert not os.environ.get("OPENAI_API_KEY"), \
        "smoke requires OPENAI_API_KEY unset"
    check("OPENAI_API_KEY unset in environment", True)

    # 1. local analysis
    sample = (BACKEND / "tests" / "sample_configs" / "insecure.txt"
              ).read_text(encoding="utf-8")
    run = AuditExecutor().execute(
        audit_id="offline-smoke", config_content=sample,
        device_name="offline-sw.cfg")
    check("executor completes locally with findings",
          run.status == "completed" and len(run.findings or []) > 0,
          f"status={run.status} findings={len(run.findings or [])}")

    # 2. local PDF reporting
    findings = [{
        "title": f.title, "severity": str(getattr(f.severity, "value",
                                                  f.severity)),
        "status": "open", "confidence": f.confidence,
        "evidence": dict(f.evidence) if isinstance(f.evidence, dict)
        else {}, "remediation": dict(f.remediation)
        if isinstance(f.remediation, dict) else {},
    } for f in (run.findings or [])]
    pdf = generate_audit_report(
        {"audit_id": "offline-smoke", "audit_name": "Offline smoke",
         "framework": "CIS", "status": "completed",
         "overall_score": run.overall_score or 0.0,
         "configuration_count": 1,
         "file_details": [{"filename": "offline-sw.cfg",
                            "vendor": "cisco", "device_type": "switch",
                            "platform": "ios", "hostname": "offline-sw"}]},
        findings, [])
    check("PDF report renders locally",
          pdf.startswith(b"%PDF") and len(pdf) > 1000, f"bytes={len(pdf)}")

    # 3. chained ledger writes (throwaway DB, cleaned up)
    if not await dbutil.schema_available():
        check("throwaway DB available", False, "schema missing")
    else:
        check("throwaway DB available", True)
        engine, factory = dbutil.make_session_factory()
        session = factory()
        created = []
        try:
            repo = AuditTrailRepository(session)
            e1 = await repo.log(
                action=AuditAction.AUDIT_COMPLETED, entity_type="audit",
                entity_id=uuid.uuid4(), user_id=None,
                details={"smoke": "offline"})
            e2 = await repo.log(
                action=AuditAction.REPORT_GENERATED, entity_type="audit",
                entity_id=e1.entity_id, user_id=None,
                details={"smoke": "offline", "format": "pdf"})
            await session.refresh(e1)
            await session.refresh(e2)
            linked = (e2.previous_hash == e1.event_hash
                      and e1.seq is not None and e2.seq is not None
                      and e2.seq > e1.seq
                      and len(e1.event_hash or "") == 64)
            created.extend([e1.id, e2.id])
            check("chained ledger writes link locally", linked,
                  f"seq={e1.seq}->{e2.seq}")
            await session.commit()
        finally:
            try:
                if created:
                    await session.execute(
                        delete(AuditTrail).where(
                            AuditTrail.id.in_(created)))
                    await session.commit()
            except Exception:
                await session.rollback()
            await session.close()
            await engine.dispose()

    # 4. MockAI fallback (no network)
    from app.ai.providers import MockAIProvider

    client = create_ai_client()
    provider = getattr(client, "provider", None)
    name = type(provider).__name__ if provider is not None else "?"
    check("AI layer uses MockAIProvider with no key",
          isinstance(provider, MockAIProvider), f"provider={name}")

    violations = [c for c in CHECKS if not c["ok"]]
    result = {"smoke": "offline/air-gap ledger flow",
              "openai_key_set": bool(os.environ.get("OPENAI_API_KEY")),
              "checks": CHECKS, "violations_total": len(violations),
              "verdict": "PASS" if not violations else "FAIL"}
    (OUT / "offline_smoke.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
    print(f"offline smoke verdict: {result['verdict']}")
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
