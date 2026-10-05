"""Shared fixtures for engine validation tests.

DB-backed tests run only when the throwaway database
`engine_validation_test` has been provisioned (see
scripts.engine_validation.dbutil.create_schema). Otherwise those tests
are reported as NOT VERIFIABLE instead of failing.

A session-scoped `recorder` collects structured evidence rows from each
test and dumps them to a JSONL file so ENGINE reports are built from
observed values rather than prose.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

FIXTURES = Path(__file__).parent / "fixtures"
ARTIFACT_ROOT = BACKEND_ROOT / "artifacts" / "engine_validation"

# test module -> engine label used in every evidence row
ENGINE_BY_MODULE = {
    "test_v01_ingestion.py": "01_configuration_ingestion",
    "test_v02_validation.py": "02_configuration_validation",
    "test_v03_detection.py": "03_vendor_detection",
    "test_v04_parsing.py": "04_parsing",
    "test_v05_normalization.py": "05_normalization",
    "test_v06_knowledge_base.py": "06_knowledge_base",
    "test_v07_compliance.py": "07_compliance",
    "test_v08_findings.py": "08_findings",
    "test_v09_risk.py": "09_risk",
    "test_v10_remediation.py": "10_remediation",
    "test_v11_reporting.py": "11_reporting",
    "test_v12_audit_trail.py": "12_audit_trail",
}
# engine label -> artifact subdirectory
ENGINE_DIR = {
    "01_configuration_ingestion": "01_ingestion",
    "02_configuration_validation": "02_validation",
    "03_vendor_detection": "03_detection",
    "04_parsing": "04_parsing",
    "05_normalization": "05_normalization",
    "06_knowledge_base": "06_knowledge_base",
    "07_compliance": "07_compliance",
    "08_findings": "08_findings",
    "09_risk": "09_risk",
    "10_remediation": "10_remediation",
    "11_reporting": "11_reporting",
    "12_audit_trail": "12_audit_trail",
}


class Recorder:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.current_test = ""

    @property
    def engine(self) -> str:
        module = self.current_test.split("::")[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        return ENGINE_BY_MODULE.get(module, "unknown")

    def add(
        self,
        test_id: str,
        category: str,
        requirement: str,
        input_desc: str,
        expected: str,
        actual: str,
        status: str,
        classification: str,
        evidence: str,
        recommendation: str = "",
    ) -> None:
        self.rows.append(
            {
                "engine": self.engine,
                "test_id": test_id,
                "category": category,
                "requirement": requirement,
                "input": input_desc,
                "expected": expected,
                "actual": actual,
                "status": status,
                "classification": classification,
                "evidence": evidence,
                "recommendation": recommendation,
                "pytest_test": self.current_test,
            }
        )


@pytest.fixture(scope="session")
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture(autouse=True)
def _tag_current_test(request, recorder: Recorder):
    """Attribute evidence rows to the test that is about to run."""
    recorder.current_test = request.node.nodeid
    yield


@pytest.fixture(scope="session", autouse=True)
def _dump_results(recorder: Recorder):
    yield
    by_engine: dict[str, list[dict[str, Any]]] = {}
    for row in recorder.rows:
        by_engine.setdefault(row["engine"], []).append(row)
    for engine, rows in by_engine.items():
        out_dir = ARTIFACT_ROOT / ENGINE_DIR.get(engine, engine)
        out_dir.mkdir(parents=True, exist_ok=True)
        with open(out_dir / "raw_results.jsonl", "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")


@pytest.fixture()
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture()
def engine_pure():
    """IngestionEngine with no database.

    `_validate_extension`, `_validate_size`, `_calculate_hash` and
    `_decode_content` never touch `self.db`, so this instance is valid
    for every non-DB contract test.
    """
    from app.engines.ingestion import IngestionEngine

    return IngestionEngine(db=None)


@pytest.fixture()
async def db_env():
    """(engine_with_db, session) — skips when schema is not provisioned."""
    import scripts.engine_validation.dbutil as dbutil

    if not await dbutil.schema_available():
        pytest.skip("throwaway database engine_validation_test not provisioned")

    db_engine, factory = dbutil.make_session_factory()
    session = factory()
    try:
        from app.engines.ingestion import IngestionEngine

        yield IngestionEngine(db=session), session
    finally:
        try:
            await session.rollback()
        except Exception:
            pass
        await session.close()
        await db_engine.dispose()
