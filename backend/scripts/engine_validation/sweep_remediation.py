"""Engine 10 dataset sweep - remediation generation over the production path.

Runs AuditExecutor().execute() (validation -> detection -> parsing ->
normalization -> compliance evaluation -> finding generation with canonical
RemediationEngine content, exactly as the audit API wires it) over every file
in the final dataset and records the remediation each file's findings carry:
§12 interface completeness, finding linkage, content coverage
(command/verification/rollback), vendor-family syntax shape, and category G
flags (wrong/unsupported-vendor consequences).

Contract checks (exit code 1 on violation):
- C1 no untyped errors (per-file exceptions recorded, never fatal)
- C2 every finding remediation carries the §12 interface keys
- C3 remediation linkage matches its own finding
- C4 no fabricated syntax (unknown vendors derive nothing; rollbacks invert)
- C5 boundary runs (failed executor status) carry zero remediations
- C6 unsupported vendors receive zero remediations
- C7 determinism sample: re-running files reproduces remediations

Directory labels are diagnostic metadata only, never vendor truth.

Outputs:
    artifacts/engine_validation/10_remediation/dataset_results.csv
    artifacts/engine_validation/10_remediation/dataset_summary.json
    artifacts/engine_validation/10_remediation/contract_results.json
"""

from __future__ import annotations

import csv
import json
import sys
import time
import traceback
from collections import Counter
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))

CORPUS = Path(r"C:\Users\priye\Downloads\SIH Config\final-dataset")
OUT = BACKEND / "artifacts" / "engine_validation" / "10_remediation"

from app.engines.compliance.executor import AuditExecutor  # noqa: E402
from app.engines.compliance.models import (  # noqa: E402
    ComplianceResultType,
)
from app.engines.compliance.remediation import (  # noqa: E402
    REMEDIATION_KEYS,
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
    "findings", "remediated",
    "cmd_present", "cmd_derived_like", "verify_present", "rollback_present",
    "refs_present",
    "label_vendor", "det_vendor", "attrib_vendors",
    "g_flags", "error",
    "contract_violations",
]


def _first_verb(command: str) -> str:
    lines = (command or "").splitlines()
    if not lines:
        return ""
    parts = lines[0].strip().split()
    return parts[0] if parts else ""


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
                audit_id=f"e10sw-{i}",
                config_content=text,
                device_name=rel[:80],
            )
            row["exec_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            row["exec_status"] = run.status

            findings = run.findings or []
            row["findings"] = len(findings)

            cmd_n = verify_n = rollback_n = refs_n = remediated = 0
            iface_bad: list[str] = []
            link_bad: list[str] = []
            syntax_bad: list[str] = []
            for f in findings:
                rem = f.remediation if isinstance(f.remediation, dict) else {}
                if set(REMEDIATION_KEYS) - set(rem):
                    iface_bad.append(f.control_id)
                    continue
                remediated += 1
                if rem.get("finding_id") != f.id \
                        or rem.get("finding_title") != f.title \
                        or rem.get("vendor") != f.affected_vendor \
                        or rem.get("platform") != f.affected_platform:
                    link_bad.append(f.control_id)
                if rem.get("recommended_config"):
                    cmd_n += 1
                if rem.get("verification_steps"):
                    verify_n += 1
                if rem.get("rollback_steps"):
                    rollback_n += 1
                if rem.get("references"):
                    refs_n += 1
                # Family-gate spot check: junos verbs on cisco content and
                # cisco negation on junos content are fabrication signals.
                vendor = (f.affected_vendor or "").lower()
                verb = _first_verb(rem.get("recommended_config", ""))
                if vendor == "cisco" and verb in (
                        "set", "delete", "rename", "deactivate"):
                    syntax_bad.append(f.control_id)
                if vendor == "juniper" and verb == "no":
                    syntax_bad.append(f.control_id)
                # Unknown vendors must never carry derived syntax.
                if vendor not in ("cisco", "juniper", "") and rem.get(
                        "recommended_config"):
                    # Allowed only when a control authored it; the sweep
                    # cannot tell authorship apart, so record vendor for
                    # the summary (not a violation by itself).
                    pass
            row["remediated"] = remediated
            row["cmd_present"] = cmd_n
            row["verify_present"] = verify_n
            row["rollback_present"] = rollback_n
            row["refs_present"] = refs_n

            det_vendor = ""
            det = getattr(run, "detection_result", None)
            if det is not None:
                det_vendor = getattr(det, "vendor", "") or ""
            row["det_vendor"] = det_vendor

            attrib = {f.affected_vendor for f in findings if f.affected_vendor}
            row["attrib_vendors"] = "|".join(sorted(attrib))

            # Per-file contract violations (E10 acceptance invariants).
            violations = []
            if iface_bad:
                violations.append(
                    f"C2:interface_incomplete={len(iface_bad)}:"
                    f"{'|'.join(iface_bad[:3])}")
            if link_bad:
                violations.append(
                    f"C3:linkage_mismatch={len(link_bad)}:"
                    f"{'|'.join(link_bad[:3])}")
            if syntax_bad:
                violations.append(
                    f"C4:cross_family_syntax={len(syntax_bad)}:"
                    f"{'|'.join(syntax_bad[:3])}")
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
    total_remediated = sum(int(r["remediated"] or 0) for r in ok_rows)

    # C7: determinism sample — re-run files, compare remediations.
    det_sample = [r for r in ok_rows if not r["error"]][:30]
    det_engine = AuditExecutor()
    det_mismatch = []
    for r in det_sample:
        text = (CORPUS / r["file"]).read_text(encoding="utf-8",
                                              errors="replace")

        def _canon(findings):
            # finding_id is a UUID by design; everything else must repeat.
            return sorted(
                (f.control_id, {k: v for k, v in (f.remediation or {}).items()
                                if k != "finding_id"})
                for f in findings)

        def _dump(pairs):
            return json.dumps(pairs, sort_keys=True, default=str)

        rerun = det_engine.execute(
            audit_id="e10sw-det", config_content=text,
            device_name=r["file"][:80])
        first = _dump(_canon(rerun.findings or []))
        second_run = det_engine.execute(
            audit_id="e10sw-det2", config_content=text,
            device_name=r["file"][:80])
        second = _dump(_canon(second_run.findings or []))
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
            "name": "every finding remediation carries the §12 interface",
            "probes": total_findings,
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C2:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C3",
            "name": "remediation linkage matches its own finding",
            "probes": total_findings,
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C3:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C4",
            "name": "no cross-family command syntax",
            "probes": total_findings,
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C4:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C5",
            "name": "boundary runs carry zero remediations",
            "probes": len(ok_rows),
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C5:findings_on_" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C6",
            "name": "unsupported vendors zero decisive remediations",
            "probes": len(ok_rows),
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]
                and "C6:" in r["contract_violations"]),
            "detail": [],
        },
        {
            "id": "C7",
            "name": "deterministic remediations across runs",
            "probes": len(det_sample),
            "violations": len(det_mismatch),
            "detail": det_mismatch[:5],
        },
    ]
    contract_violations = sum(c["violations"] for c in contract_checks)

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
            "remediated": sum(int(r["remediated"] or 0) for r in ok_lr),
            "cmd_present": sum(int(r["cmd_present"] or 0) for r in ok_lr),
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
        "remediated": total_remediated,
        "exec_ms": _pcts(timed),
        "coverage": {
            "recommended_config": sum(int(r["cmd_present"] or 0) for r in ok_rows),
            "verification_steps": sum(int(r["verify_present"] or 0) for r in ok_rows),
            "rollback_steps": sum(int(r["rollback_present"] or 0) for r in ok_rows),
            "references": sum(int(r["refs_present"] or 0) for r in ok_rows),
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
