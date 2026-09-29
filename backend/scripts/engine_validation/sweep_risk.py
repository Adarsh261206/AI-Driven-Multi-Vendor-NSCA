"""Engine 09 dataset sweep - risk scoring over the production path.

Runs AuditExecutor().execute() (validation -> detection -> parsing ->
normalization -> compliance evaluation -> finding generation with canonical
RiskEngine assessment, exactly as the audit API wires it) over every file in
the final dataset and records the risk/priority each file's findings receive:
risk distributions, exact P1..P4 band counts, normative-vs-advisory tracking
(advisory only, never a decision input), and category G flags
(wrong/unsupported-vendor risk behavior).

Contract checks (exit code 1 on violation):
- C1 no untyped errors (per-file exceptions recorded, never fatal)
- C2 every risk score a float in [0, 100]
- C3 every priority valid and consistent with its own score
- C4 every finding scored by the normative method (deterministic:v1)
- C5 boundary runs (failed executor status) carry zero findings
- C6 unsupported vendors receive zero decisive findings
- C7 determinism sample: re-running files reproduces outcomes

Directory labels are diagnostic metadata only, never vendor truth.

Outputs:
    artifacts/engine_validation/09_risk/dataset_results.csv
    artifacts/engine_validation/09_risk/dataset_summary.json
    artifacts/engine_validation/09_risk/contract_results.json
"""

from __future__ import annotations

import csv
import json
import statistics
import sys
import time
import traceback
from collections import Counter
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))

CORPUS = Path(r"C:\Users\priye\Downloads\SIH Config\final-dataset")
OUT = BACKEND / "artifacts" / "engine_validation" / "09_risk"

from app.engines.compliance.executor import AuditExecutor  # noqa: E402
from app.engines.compliance.models import (  # noqa: E402
    ComplianceResultType,
)
from app.engines.compliance.risk import (  # noqa: E402
    advisory_score,
    priority_for,
)

LABEL_VENDOR = {
    "A10": "a10", "Arista": "arista", "Cisco": "cisco", "F5": "f5",
    "Fortinet": "fortinet", "FRR": "frr", "Juniper": "juniper",
    "NAPALM": None, "PaloAlto": "paloalto",
}
SUPPORTED = {"cisco", "juniper"}

CSV_FIELDS = [
    "file", "label", "bytes",
    "exec_status", "exec_ms",
    "findings", "risk_min", "risk_max", "risk_mean",
    "risk_out_of_range", "risk_non_float",
    "priority_p1", "priority_p2", "priority_p3", "priority_p4",
    "priority_invalid", "priority_mismatch",
    "method_non_normative",
    "advisory_max_diff", "advisory_none",
    "label_vendor", "det_vendor", "attrib_vendors",
    "wrong_vendor_attrib", "risk_vendor_unsupported",
    "g_flags", "error",
    "contract_violations",
]


def _category_of(run, finding) -> str:
    """Recover the evaluation category for a finding (sweep diagnostics).

    Findings do not store category; the sweep re-derives it from the run's
    evaluations by control id. Unknown when the evaluation is absent.
    """
    evaluation = getattr(run, "compliance_evaluation", None)
    evaluations = getattr(evaluation, "evaluations", None) or []
    for ev in evaluations:
        if getattr(ev, "control_id", None) == finding.control_id:
            return getattr(ev, "category", "") or ""
    return ""


def main() -> None:
    limit = 0
    for i, a in enumerate(sys.argv):
        if a == "--limit" and i + 1 < len(sys.argv):
            limit = int(sys.argv[i + 1])
    OUT.mkdir(parents=True, exist_ok=True)
    executor = AuditExecutor()
    files = sorted(p for p in CORPUS.rglob("*") if p.is_file())
    if limit:
        files = files[:limit]
    rows: list[dict] = []
    t_all = time.perf_counter()

    for i, path in enumerate(files, 1):
        rel = path.relative_to(CORPUS).as_posix()
        label = path.relative_to(CORPUS).parts[0]
        row = {k: "" for k in CSV_FIELDS}
        row["file"] = rel
        row["label"] = label
        row["label_vendor"] = LABEL_VENDOR.get(label, "unknown") or "none"
        try:
            data = path.read_bytes()
        except OSError as exc:
            row["error"] = f"read: {exc}"
            rows.append(row)
            continue
        row["bytes"] = len(data)
        text = data.decode("utf-8", errors="replace")

        try:
            t0 = time.perf_counter()
            run = executor.execute(
                audit_id=f"e09sw-{i}",
                config_content=text,
                device_name=rel[:80],
            )
            row["exec_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            row["exec_status"] = run.status

            findings = run.findings or []
            row["findings"] = len(findings)

            pri = Counter()
            risks: list[float] = []
            out_of_range = non_float = mismatch = non_norm = 0
            adv_diffs: list[float] = []
            adv_none = 0
            for f in findings:
                if f.priority in ("P1", "P2", "P3", "P4"):
                    pri[f.priority] += 1
                else:
                    pri["invalid"] += 1
                if not isinstance(f.risk_score, float):
                    non_float += 1
                    continue
                risks.append(f.risk_score)
                if not 0.0 <= f.risk_score <= 100.0:
                    out_of_range += 1
                try:
                    if priority_for(f.risk_score) != f.priority:
                        mismatch += 1
                except Exception:  # noqa: BLE001 - counted as mismatch
                    mismatch += 1
                if getattr(f, "risk_method", "") != "deterministic":
                    non_norm += 1
                # Advisory tracking (informational only): recompute the
                # advisory opinion for the finding's own inputs.
                try:
                    adv = advisory_score(
                        f.severity, f.affected_vendor or "",
                        _category_of(run, f), f.confidence)
                except Exception:  # noqa: BLE001
                    adv = "error"
                if adv is None or adv == "error":
                    adv_none += 1
                else:
                    adv_diffs.append(abs(adv - f.risk_score))

            row["priority_p1"] = pri.get("P1", 0)
            row["priority_p2"] = pri.get("P2", 0)
            row["priority_p3"] = pri.get("P3", 0)
            row["priority_p4"] = pri.get("P4", 0)
            row["priority_invalid"] = pri.get("invalid", 0)
            row["priority_mismatch"] = mismatch
            row["method_non_normative"] = non_norm
            row["risk_min"] = round(min(risks), 2) if risks else ""
            row["risk_max"] = round(max(risks), 2) if risks else ""
            row["risk_mean"] = round(statistics.mean(risks), 2) if risks else ""
            row["risk_out_of_range"] = out_of_range
            row["risk_non_float"] = non_float
            row["advisory_max_diff"] = (
                round(max(adv_diffs), 2) if adv_diffs else "")
            row["advisory_none"] = adv_none

            det_vendor = ""
            det = getattr(run, "detection_result", None)
            if det is not None:
                det_vendor = getattr(det, "vendor", "") or ""
            row["det_vendor"] = det_vendor

            attrib = {f.affected_vendor for f in findings if f.affected_vendor}
            row["attrib_vendors"] = "|".join(sorted(attrib))

            # Per-file contract violations (E09 acceptance invariants).
            violations = []
            if out_of_range or non_float:
                violations.append(
                    f"C2:range={out_of_range}+nonfloat={non_float}")
            if pri.get("invalid", 0) or mismatch:
                violations.append(
                    f"C3:invalid={pri.get('invalid', 0)}+mismatch={mismatch}")
            if non_norm:
                violations.append(f"C4:non_normative={non_norm}")
            if run.status != "completed" and findings:
                violations.append(
                    f"C5:findings_on_{run.status}={len(findings)}")
            if (det_vendor and det_vendor not in SUPPORTED
                    and sum(1 for f in findings
                            if f.result == ComplianceResultType.FAIL)):
                violations.append("C6:decisive_on_unsupported")
            row["contract_violations"] = "|".join(violations)

            # Category G flags (diagnostic consequences).
            flags = []
            expected = LABEL_VENDOR.get(label)
            if expected and attrib and attrib != {expected}:
                flags.append("wrong_vendor_attributed")
                row["wrong_vendor_attrib"] = "|".join(sorted(attrib))
            if det_vendor and det_vendor not in SUPPORTED:
                flags.append("risk_vendor_unsupported")
            if findings and not text.strip():
                flags.append("findings_on_empty_input")
            row["g_flags"] = "|".join(flags)
        except Exception as exc:  # noqa: BLE001
            row["error"] = f"{type(exc).__name__}: {exc}"
            if "--trace" in sys.argv:
                traceback.print_exc()

        rows.append(row)
        if i % 60 == 0:
            print(f"  {i}/{len(files)} files...", flush=True)

    elapsed = round(time.perf_counter() - t_all, 1)

    csv_path = OUT / "dataset_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)

    ok_rows = [r for r in rows if not r["error"]]
    timed = [float(r["exec_ms"]) for r in ok_rows if r["exec_ms"] != ""]
    total_findings = sum(int(r["findings"] or 0) for r in ok_rows)

    # C7: determinism sample — re-run files, compare finding outcomes.
    det_sample = [r for r in ok_rows if not r["error"]][:30]
    det_engine = AuditExecutor()
    det_mismatch = []
    for r in det_sample:
        text = (CORPUS / r["file"]).read_text(encoding="utf-8",
                                              errors="replace")
        rerun = det_engine.execute(
            audit_id="e09sw-det", config_content=text,
            device_name=r["file"][:80])
        first = sorted((f.control_id, f.risk_score, f.priority)
                       for f in (rerun.findings or []))
        second_run = det_engine.execute(
            audit_id="e09sw-det2", config_content=text,
            device_name=r["file"][:80])
        second = sorted((f.control_id, f.risk_score, f.priority)
                        for f in (second_run.findings or []))
        if (rerun.status != r["exec_status"]
                or len(rerun.findings or []) != int(r["findings"] or 0)
                or first != second):
            det_mismatch.append(r["file"])

    contract_checks = [
        {
            "id": "C1",
            "name": "no untyped errors (per-file exceptions recorded only)",
            "probes": len(rows),
            "violations": sum(
                1 for r in rows
                if r["error"] and "TYPED:" not in r["error"]),
            "detail": [r["file"] for r in rows
                       if r["error"] and "TYPED:" not in r["error"]][:5],
        },
        {
            "id": "C2",
            "name": "every risk score a float in [0, 100]",
            "probes": total_findings,
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C2:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C3",
            "name": "every priority valid and consistent with its score",
            "probes": total_findings,
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C3:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C4",
            "name": "every finding scored by the normative method",
            "probes": total_findings,
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C4:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C5",
            "name": "boundary runs carry zero findings",
            "probes": len(ok_rows),
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C5:findings_on_" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C6",
            "name": "unsupported vendors zero decisive findings",
            "probes": len(ok_rows),
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C6:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C7",
            "name": "deterministic risk outcomes across runs",
            "probes": len(det_sample),
            "violations": len(det_mismatch),
            "detail": det_mismatch[:5],
        },
    ]
    contract_violations = sum(c["violations"] for c in contract_checks)

    prio_totals = {
        k: sum(int(r[f"priority_{k}"] or 0) for r in ok_rows)
        for k in ("p1", "p2", "p3", "p4")
    }
    prio_invalid = sum(int(r["priority_invalid"] or 0) for r in ok_rows)

    g_counts = Counter()
    for r in ok_rows:
        for f in (r["g_flags"] or "").split("|"):
            if f:
                g_counts[f] += 1

    by_label: dict[str, dict] = {}
    for label in sorted({r["label"] for r in rows}):
        lr = [r for r in rows if r["label"] == label]
        ok_lr = [r for r in lr if not r["error"]]
        by_label[label] = {
            "files": len(lr),
            "errors": len(lr) - len(ok_lr),
            "findings": sum(int(r["findings"] or 0) for r in ok_lr),
            "g_files": sum(1 for r in ok_lr if r["g_flags"]),
        }

    def _pcts(vals: list[float]) -> dict:
        if not vals:
            return {}
        vs = sorted(vals)
        return {
            "p50": round(vs[len(vs) // 2], 1),
            "p95": round(vs[int(len(vs) * 0.95)], 1),
            "max": round(max(vs), 1),
        }

    summary = {
        "files": len(rows),
        "ok_files": len(ok_rows),
        "errors": len(rows) - len(ok_rows),
        "elapsed_s": elapsed,
        "findings": total_findings,
        "exec_ms": _pcts(timed),
        "priority_totals": prio_totals,
        "priority_invalid": prio_invalid,
        "risk_range_observed": {
            "min": min((float(r["risk_min"]) for r in ok_rows if r["risk_min"] != ""), default=None),
            "max": max((float(r["risk_max"]) for r in ok_rows if r["risk_max"] != ""), default=None),
        },
        "risk_out_of_range": sum(int(r["risk_out_of_range"] or 0) for r in ok_rows),
        "advisory_tracking": {
            "files_with_advisory": sum(1 for r in ok_rows if r["advisory_max_diff"] != ""),
            "max_diff": max((float(r["advisory_max_diff"]) for r in ok_rows if r["advisory_max_diff"] != ""), default=None),
        },
        "g_flags": dict(g_counts),
        "by_label": by_label,
        "contract_checks": contract_checks,
        "contract_violations_total": contract_violations,
        "contract_verdict": "PASS" if contract_violations == 0 else "FAIL",
    }

    with (OUT / "dataset_summary.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    with (OUT / "contract_results.json").open("w", encoding="utf-8") as fh:
        json.dump({"checks": contract_checks,
                   "violations_total": contract_violations,
                   "verdict": summary["contract_verdict"]}, fh, indent=2)

    print(json.dumps({k: v for k, v in summary.items() if k != "by_label"}, indent=2))
    for check in contract_checks:
        print(f"  {check['id']:>3} {check['name']}: {check['probes']} probes, "
              f"{check['violations']} violations")
    if contract_violations:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
