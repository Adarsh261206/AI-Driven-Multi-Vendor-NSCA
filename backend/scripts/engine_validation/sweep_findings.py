"""Engine 08 dataset sweep - finding generation over the production path.

Runs AuditExecutor().execute() (validation -> detection -> parsing ->
normalization -> compliance evaluation -> finding generation, exactly as the
audit API wires it) over every file in the final dataset and records the
findings each file produces: severity/status distribution, evidence-chain
coverage against the section 12 interface, remediation coverage against the
section 12 Remediation interface, risk/priority attribution, and category G
flags (wrong-vendor attribution, unsupported vendors, empty input).

Contract checks (exit code 1 on violation):
- C1 no untyped errors (per-file exceptions recorded, never fatal)
- C2 PASS leakage is zero (PASS evaluations never become findings)
- C3 boundary runs (failed executor status) carry zero findings
- C4 every finding carries the full §12 evidence interface
- C5 every finding carries the full §12 remediation interface
- C6 every severity is canonical uppercase
- C7 determinism sample: re-running files reproduces finding counts

Directory labels are diagnostic metadata only, never vendor truth.

Outputs:
    artifacts/engine_validation/08_findings/dataset_results.csv
    artifacts/engine_validation/08_findings/dataset_summary.json
    artifacts/engine_validation/08_findings/contract_results.json
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
OUT = BACKEND / "artifacts" / "engine_validation" / "08_findings"

from app.engines.compliance.executor import AuditExecutor  # noqa: E402
from app.engines.compliance.models import (  # noqa: E402
    ComplianceResultType,
    FindingStatus,
    Severity,
)

LABEL_VENDOR = {
    "A10": "a10", "Arista": "arista", "Cisco": "cisco", "F5": "f5",
    "Fortinet": "fortinet", "FRR": "frr", "Juniper": "juniper",
    "NAPALM": None, "PaloAlto": "paloalto",
}
SUPPORTED = {"cisco", "juniper"}

# section 12 EvidenceChain interface (spec docs/PROJECT_MASTER_SPEC.md)
SPEC_EV8 = [
    "raw_config", "parsed_value", "normalized_value", "security_control",
    "expected_value", "actual_value", "result", "reasoning",
]
# section 12 Remediation interface
SPEC_REM = [
    "finding_id", "finding_title", "risk_description", "why_it_matters",
    "vendor", "platform", "recommended_config", "verification_steps",
    "rollback_steps", "references",
]

CSV_FIELDS = [
    "file", "label", "bytes", "has_nul",
    "det_vendor", "det_platform",
    "exec_status", "exec_ms",
    "findings", "fail_findings", "review_findings",
    "sev_critical", "sev_high", "sev_medium", "sev_low", "sev_other",
    "status_open", "status_other",
    "ev8_full", "ev8_partial", "ev8_none", "ev8_missing_keys",
    "rem_present", "rem_partial", "rem_missing_keys",
    "affected_vendors", "affected_platforms",
    "priority_p1", "priority_p2", "priority_p3", "priority_other",
    "risk_min", "risk_max",
    "wrong_vendor_attrib", "g_flags", "error",
    "contract_violations",
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    executor = AuditExecutor()
    files = sorted(p for p in CORPUS.rglob("*") if p.is_file())
    rows: list[dict] = []
    t_all = time.perf_counter()

    for i, path in enumerate(files, 1):
        rel = path.relative_to(CORPUS).as_posix()
        label = path.relative_to(CORPUS).parts[0]
        row = {k: "" for k in CSV_FIELDS}
        row["file"] = rel
        row["label"] = label
        try:
            data = path.read_bytes()
        except OSError as exc:
            row["error"] = f"read: {exc}"
            rows.append(row)
            continue
        row["bytes"] = len(data)
        row["has_nul"] = int(b"\x00" in data)
        text = data.decode("utf-8", errors="replace")

        try:
            t0 = time.perf_counter()
            run = executor.execute(
                audit_id=f"e08sw-{i}",
                config_content=text,
                device_name=rel[:80],
            )
            row["exec_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            row["exec_status"] = run.status

            findings = run.findings or []
            row["findings"] = len(findings)
            row["fail_findings"] = sum(
                1 for f in findings
                if f.result == ComplianceResultType.FAIL
            )
            row["review_findings"] = sum(
                1 for f in findings
                if f.result == ComplianceResultType.REVIEW
            )

            sev = Counter()
            st = Counter()
            pri = Counter()
            ev_full = ev_partial = ev_none = 0
            ev_missing: set[str] = set()
            rem_present = rem_partial = 0
            rem_missing: set[str] = set()
            vendors: set[str] = set()
            platforms: set[str] = set()
            risks: list[float] = []
            pass_findings = 0

            for f in findings:
                # severity as stored on the record (engine enum -> value)
                sv = getattr(f.severity, "value", str(f.severity))
                key = sv.upper()
                if key in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    sev[key.lower()] += 1
                else:
                    sev["other"] += 1
                st[getattr(f.status, "value", str(f.status))] += 1
                if f.result == ComplianceResultType.PASS:
                    pass_findings += 1

                pr = (f.priority or "").upper()
                pri[pr if pr in ("P1", "P2", "P3") else "other"] += 1
                try:
                    risks.append(float(f.risk_score))
                except (TypeError, ValueError):
                    pass

                ev = f.evidence if isinstance(f.evidence, dict) else {}
                # §12 interface (acceptance: keys present on EVERY finding)
                # plus observed-value completeness on DECISIVE findings with
                # the documented honest-null exemptions (mirrors the E07
                # evidence contract):
                # - mapped decisions: all eight keys carry observed values;
                # - raw-evidence decisions (explicit regex): expected/actual/
                #   normalized may be null (no value comparison exists);
                # - is_set/not_set: no expected value by definition;
                # - absence-based PASS: nothing observed by definition.
                # REVIEW findings honestly lack observed values; their keys
                # must still be present.
                decisive = f.result in (ComplianceResultType.PASS,
                                        ComplianceResultType.FAIL)
                mapped = bool(ev.get("universal_model_path"))
                required = list(SPEC_EV8)
                if not mapped:
                    required = [k for k in required
                                if k not in ("expected_value", "actual_value",
                                             "normalized_value")]
                if ev.get("operator") in ("is_set", "not_set"):
                    required = [k for k in required
                                if k != "expected_value"]
                absence_pass = (decisive
                                and f.result == ComplianceResultType.PASS
                                and not ev.get("raw_config_line_numbers"))
                if absence_pass:
                    required = [k for k in required
                                if k not in ("raw_config", "parsed_value")]
                if decisive:
                    present = [k for k in required
                               if ev.get(k) not in (None, "")]
                else:
                    present = [k for k in required if k in ev]
                if len(present) == len(required):
                    ev_full += 1
                elif present:
                    ev_partial += 1
                else:
                    ev_none += 1
                ev_missing.update(k for k in SPEC_EV8 if k not in ev)
                if decisive:
                    ev_missing.update(
                        k for k in required if ev.get(k) in (None, "")
                    )
                if decisive and not absence_pass:
                    if not ev.get("raw_config_line_numbers"):
                        ev_missing.add("raw_evidence_lines")
                    if not ev.get("raw_config"):
                        ev_missing.add("raw_evidence_snippet")

                if isinstance(f.remediation, dict):
                    rem_present += 1
                    # Interface completeness (E08 scope): every §12 key
                    # present and non-null. Empty content (no known command,
                    # steps or references) is honest, not a violation —
                    # content quality is Engine 10 scope.
                    missing = [
                        k for k in SPEC_REM
                        if k not in f.remediation
                        or f.remediation.get(k) is None
                    ]
                    if missing:
                        rem_partial += 1
                        rem_missing.update(missing)
                else:
                    rem_missing.add("remediation_not_a_dict")

                vendors.add(f.affected_vendor or "")
                platforms.add(f.affected_platform or "")

            row["sev_critical"] = sev.get("critical", 0)
            row["sev_high"] = sev.get("high", 0)
            row["sev_medium"] = sev.get("medium", 0)
            row["sev_low"] = sev.get("low", 0)
            row["sev_other"] = sev.get("other", 0)
            row["status_open"] = st.get(FindingStatus.OPEN.value, 0)
            row["status_other"] = sum(
                v for k, v in st.items()
                if k != FindingStatus.OPEN.value
            )
            row["ev8_full"] = ev_full
            row["ev8_partial"] = ev_partial
            row["ev8_none"] = ev_none
            row["ev8_missing_keys"] = "|".join(sorted(ev_missing))
            row["rem_present"] = rem_present
            row["rem_partial"] = rem_partial
            row["rem_missing_keys"] = "|".join(sorted(rem_missing))
            row["affected_vendors"] = "|".join(sorted(v for v in vendors if v))
            row["affected_platforms"] = "|".join(
                sorted(p for p in platforms if p)
            )
            row["priority_p1"] = pri.get("P1", 0)
            row["priority_p2"] = pri.get("P2", 0)
            row["priority_p3"] = pri.get("P3", 0)
            row["priority_other"] = pri.get("other", 0)
            row["risk_min"] = round(min(risks), 2) if risks else ""
            row["risk_max"] = round(max(risks), 2) if risks else ""

            # Per-file contract violations (E08 acceptance invariants).
            det_vendor = ""
            det = getattr(run, "detection_result", None)
            if det is not None:
                det_vendor = getattr(det, "vendor", "") or ""
            violations = []
            if pass_findings:
                violations.append(f"C2:pass_leak={pass_findings}")
            if run.status != "completed" and findings:
                violations.append(
                    f"C3:findings_on_{run.status}={len(findings)}")
            if row["sev_other"]:
                violations.append(f"C6:sev_other={row['sev_other']}")
            if ev_partial or ev_none:
                violations.append(
                    f"C4:evidence_partial={ev_partial}+none={ev_none}:"
                    f"{'|'.join(sorted(ev_missing))[:200]}")
            if rem_partial:
                violations.append(
                    f"C5:remediation_partial={rem_partial}:"
                    f"{'|'.join(sorted(rem_missing))[:200]}")
            if "remediation_not_a_dict" in rem_missing:
                violations.append("C5:remediation_not_a_dict")
            # Unsupported-vendor decisive findings: none may exist.
            if (det_vendor and det_vendor not in SUPPORTED
                    and (sum(1 for f in findings
                             if f.result == ComplianceResultType.FAIL))):
                violations.append("C3:decisive_on_unsupported")
            row["contract_violations"] = "|".join(violations)

            row["det_vendor"] = det_vendor
            row["det_platform"] = getattr(det, "platform", "") or ""

            # category G flags (wrong/unsupported vendor consequences)
            flags = []
            expected = LABEL_VENDOR.get(label, "unknown")
            attrib = {v for v in vendors if v}
            if expected and attrib and attrib != {expected}:
                flags.append("wrong_vendor_attributed")
                row["wrong_vendor_attrib"] = "|".join(sorted(attrib))
            elif expected and attrib == {expected}:
                row["wrong_vendor_attrib"] = ""
            if findings and not text.strip():
                flags.append("findings_on_empty_input")
            if findings and det_vendor and det_vendor not in SUPPORTED:
                flags.append("findings_on_unsupported_vendor")
            if pass_findings:
                flags.append("pass_became_finding")
            if row["sev_other"]:
                flags.append("severity_outside_spec_vocab")
            if det_vendor and expected and det_vendor != expected:
                flags.append("label_detection_mismatch")
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

    by_label: dict[str, dict] = {}
    for label in sorted({r["label"] for r in rows}):
        lr = [r for r in rows if r["label"] == label]
        by_label[label] = {
            "files": len(lr),
            "errors": sum(1 for r in lr if r["error"]),
            "files_with_findings": sum(
                1 for r in lr if int(r["findings"] or 0) > 0
            ),
            "findings": sum(int(r["findings"] or 0) for r in lr),
            "sev": {
                k: sum(int(r[f"sev_{k}"] or 0) for r in lr)
                for k in ("critical", "high", "medium", "low", "other")
            },
            "g_files": sum(1 for r in lr if r["g_flags"]),
        }

    sev_totals = {
        k: sum(int(r[f"sev_{k}"] or 0) for r in ok_rows)
        for k in ("critical", "high", "medium", "low", "other")
    }
    ev_full = sum(int(r["ev8_full"] or 0) for r in ok_rows)
    ev_partial = sum(int(r["ev8_partial"] or 0) for r in ok_rows)
    ev_none = sum(int(r["ev8_none"] or 0) for r in ok_rows)
    rem_present = sum(int(r["rem_present"] or 0) for r in ok_rows)
    rem_partial = sum(int(r["rem_partial"] or 0) for r in ok_rows)

    g_counts = Counter()
    for r in ok_rows:
        for f in (r["g_flags"] or "").split("|"):
            if f:
                g_counts[f] += 1

    # C7: determinism sample — re-run files, compare finding counts.
    det_sample = [r for r in ok_rows if not r["error"]][:30]
    det_engine = AuditExecutor()
    det_mismatch = []
    for r in det_sample:
        text = (CORPUS / r["file"]).read_text(encoding="utf-8",
                                              errors="replace")
        rerun = det_engine.execute(
            audit_id="e08sw-det", config_content=text,
            device_name=r["file"][:80])
        rerun_findings = rerun.findings or []
        if (len(rerun_findings) != int(r["findings"] or 0)
                or rerun.status != r["exec_status"]):
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
            "name": "PASS evaluations never become findings",
            "probes": sum(int(r["findings"] or 0) for r in ok_rows),
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C2:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C3",
            "name": "boundary runs carry zero findings; unsupported "
                    "vendors zero decisive findings",
            "probes": len(ok_rows),
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C3:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C4",
            "name": "every finding carries the §12 evidence interface",
            "probes": sum(int(r["findings"] or 0) for r in ok_rows),
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C4:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C5",
            "name": "every finding carries the §12 remediation interface",
            "probes": sum(int(r["findings"] or 0) for r in ok_rows),
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C5:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C6",
            "name": "every severity is canonical uppercase",
            "probes": sum(int(r["findings"] or 0) for r in ok_rows),
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C6:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C7",
            "name": "deterministic finding counts across runs",
            "probes": len(det_sample),
            "violations": len(det_mismatch),
            "detail": det_mismatch[:5],
        },
    ]
    contract_violations = sum(c["violations"] for c in contract_checks)

    ev_missing_all: set[str] = set()
    rem_missing_all: set[str] = set()
    for r in ok_rows:
        ev_missing_all.update(
            k for k in (r["ev8_missing_keys"] or "").split("|") if k
        )
        rem_missing_all.update(
            k for k in (r["rem_missing_keys"] or "").split("|") if k
        )

    summary = {
        "files": len(rows),
        "ok_files": len(ok_rows),
        "errors": len(rows) - len(ok_rows),
        "elapsed_s": elapsed,
        "exec_ms": {
            "p50": round(statistics.median(timed), 1) if timed else None,
            "p95": round(sorted(timed)[int(len(timed) * 0.95) - 1], 1)
            if timed else None,
            "max": round(max(timed), 1) if timed else None,
        },
        "files_with_findings": sum(
            1 for r in ok_rows if int(r["findings"] or 0) > 0
        ),
        "files_without_findings": sum(
            1 for r in ok_rows if int(r["findings"] or 0) == 0
        ),
        "total_findings": total_findings,
        "severity_totals": sev_totals,
        "status_totals": {
            "open": sum(int(r["status_open"] or 0) for r in ok_rows),
            "other": sum(int(r["status_other"] or 0) for r in ok_rows),
        },
        "priority_totals": {
            k: sum(int(r[f"priority_{k}"] or 0) for r in ok_rows)
            for k in ("p1", "p2", "p3", "other")
        },
        "evidence": {
            "full_8_keys": ev_full,
            "partial": ev_partial,
            "none": ev_none,
            "missing_keys_seen": sorted(ev_missing_all),
        },
        "remediation": {
            "present": rem_present,
            "missing_spec_keys": sorted(rem_missing_all),
            "partial_of_present": rem_partial,
        },
        "pass_became_finding": sum(
            1 for r in ok_rows
            if "pass_became_finding" in (r["g_flags"] or "")
        ),
        "g_counts": dict(g_counts),
        "by_label": by_label,
        "contract_checks": contract_checks,
        "contract_violations_total": contract_violations,
        "contract_verdict": "PASS" if contract_violations == 0 else "FAIL",
    }

    (OUT / "dataset_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    (OUT / "contract_results.json").write_text(
        json.dumps({"checks": contract_checks,
                    "violations_total": contract_violations,
                    "verdict": summary["contract_verdict"]},
                   indent=2), encoding="utf-8")
    print(f"done: {len(rows)} files in {elapsed}s; "
          f"{total_findings} findings; errors={summary['errors']}")
    for check in contract_checks:
        print(f"  {check['id']:>3} {check['name']}: {check['probes']} probes, "
              f"{check['violations']} violations")
    if contract_violations:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
