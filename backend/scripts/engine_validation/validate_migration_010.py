"""Execute migration 010 for real against the throwaway validation database.

  1. wipe, upgrade -> 009 (pre-plan head)
  2. insert a finding row (plan FK target)
  3. upgrade -> 010, assert table + columns, insert/read a plan row
  4. downgrade -> 009 (table gone), upgrade -> 010 (round trip)
  5. restore the metadata schema

Writes artifacts/engine_validation/12_audit_trail/migration_010_results.json.
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
OUT.mkdir(parents=True, exist_ok=True)

TEST_DB_URL = "postgresql+asyncpg://postgres:postgres@localhost:5432/engine_validation_test"
os.environ["DATABASE_URL"] = TEST_DB_URL

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": str(detail)[:400]})


def _config():
    from alembic.config import Config

    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    return cfg


def main() -> int:
    from alembic import command

    from scripts.engine_validation import dbutil
    from scripts.engine_validation.validate_migration_009 import (
        alembic_upgrade as _up, drop_everything, q, run_sql)

    drop_everything()
    check("throwaway database wiped", True, "DROP/CREATE SCHEMA public")
    _up("009")
    version = q("SELECT version_num FROM alembic_version")
    check("head is 009 before the plans migration",
          version and version[0][0] == "009", f"{version}")

    user_id, audit_id, finding_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    run_sql(
        "INSERT INTO users (id, email, password_hash, full_name, role, "
        "is_active, created_at, updated_at) VALUES (:id, :email, 'x', "
        "'R', 'admin', true, now(), now())",
        id=user_id, email=f"plan-{user_id}@example.test")
    run_sql(
        "INSERT INTO audits (id, user_id, name, status) VALUES "
        "(:id, :uid, 'plan-audit', 'completed')", id=audit_id, uid=user_id)
    run_sql(
        "INSERT INTO findings (id, audit_id, title, description, "
        "severity, confidence, status, evidence) VALUES (:id, :aid, "
        "'T', 'd', 'HIGH', 0.9, 'open', '{}')", id=finding_id, aid=audit_id)

    _up("010")
    version = q("SELECT version_num FROM alembic_version")
    check("head is 010 after the plans migration",
          version and version[0][0] == "010", f"{version}")
    cols = {r[0] for r in q(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'remediation_plans'")}
    need = {"id", "plan_id", "finding_id", "control_id", "status",
            "plan_json", "configuration_id", "configuration_hash_before",
            "approved_by", "approved_at", "rejection_reason",
            "failure_info", "created_at", "updated_at"}
    check("010 creates remediation_plans with the full column set",
          need <= cols, f"{sorted(cols)}")
    plan_id = uuid.uuid4()
    run_sql(
        "INSERT INTO remediation_plans (id, plan_id, finding_id, "
        "control_id, status, plan_json, created_at, updated_at) VALUES "
        "(:id, 'plan-abc', :fid, '1.1.1', 'draft', '{}', now(), now())",
        id=plan_id, fid=finding_id)
    back = q("SELECT status FROM remediation_plans WHERE id = :id",
             id=plan_id)
    check("plan row round-trips through the migrated schema",
          back and back[0][0] == "draft", f"{back}")

    command.downgrade(_config(), "009")
    gone = q("SELECT to_regclass('public.remediation_plans')")
    check("downgrade -> 009 drops remediation_plans",
          gone and gone[0][0] is None, f"{gone}")
    _up("010")
    rt = q("SELECT version_num FROM alembic_version")
    check("round trip 010 -> 009 -> 010 returns to head",
          rt and rt[0][0] == "010", f"{rt}")

    asyncio.run(dbutil.create_schema())
    check("throwaway schema restored from model metadata",
          True, "dbutil.create_schema")

    violations = [c for c in CHECKS if not c["ok"]]
    result = {"migration": "010_remediation_plans",
              "database": "engine_validation_test (throwaway)",
              "checks": CHECKS, "violations_total": len(violations),
              "verdict": "PASS" if not violations else "FAIL"}
    (OUT / "migration_010_results.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
    for entry in CHECKS:
        print(f"  [{'PASS' if entry['ok'] else 'FAIL'}] {entry['check']}")
    print(f"migration 010 verdict: {result['verdict']}")
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
