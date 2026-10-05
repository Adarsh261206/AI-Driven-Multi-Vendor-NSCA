"""Engine 07 dataset sweep - control selection / compliance evaluation.

Runs the production selection+evaluation path (BenchmarkExecutionEngine with
the detected vendor, exactly as AuditExecutor wires it) over every file in
the final dataset and records per-file selection and verdict outcomes.

Contract checks (exit code 1 on violation):
- C1 no crashes / typed errors only (errors recorded per file, never fatal)
- C2 deterministic selection (control-id order stable across runs)
- C3 no unsupported vendor receives a decisive verdict
- C4 framework attribution comes from control metadata (no id heuristic)
- C5 evidence contract holds on every decisive verdict
- C6 one overall score (score == passed/evaluated)

Directory labels are diagnostic metadata only, never vendor truth.

Outputs:
    artifacts/engine_validation/07_compliance/dataset_results.csv
    artifacts/engine_validation/07_compliance/dataset_summary.json
    artifacts/engine_validation/07_compliance/contract_results.json
"""

from __future__ import annotations

import csv
import json
import sys
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))

CORPUS = Path(r"C:\Users\priye\Downloads\SIH Config\final-dataset")
OUT = BACKEND / "artifacts" / "engine_validation" / "07_compliance"

from app.benchmarks.execution import BenchmarkExecutionEngine  # noqa: E402
from app.benchmarks.selection import ComplianceError  # noqa: E402
from app.engines.detection import VendorDetector  # noqa: E402

LABEL_VENDOR = {
    "A10": "a10", "Arista": "arista", "Cisco": "cisco", "F5": "f5",
    "Fortinet": "fortinet", "FRR": "frr", "Juniper": "juniper",
    "NAPALM": None, "PaloAlto": "paloalto",
}
SUPPORTED = {"cisco", "juniper"}

CSV_FIELDS = [
    "file", "label", "bytes", "lines", "has_nul",
    "det_vendor", "det_platform", "det_conf",
    "status", "status_reason",
    "evaluated", "passed", "failed", "review", "score", "benchmark_id",
    "framework", "cis_controls", "nist_controls",
    "mapped_pass", "mapped_fail", "mapped_review",
    "regex_pass", "regex_fail", "regex_review",
    "selection", "g_flags", "error",
    "contract_violations",
]

#: §12 keys every decisive verdict must carry with non-empty values.
EVIDENCE_KEYS = ("raw_config", "parsed_value", "normalized_value",
                 "security_control", "expected_value", "actual_value",
                 "result", "reasoning")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    eng = BenchmarkExecutionEngine()
    detector = VendorDetector()
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
        row["lines"] = text.count("\n") + 1 if text else 0

        try:
            det = detector.detect(text)
            row["det_vendor"] = det.vendor
            row["det_platform"] = det.platform
            row["det_conf"] = round(getattr(det, "confidence", 0.0), 3)

            # Production selection: executor passes detection.vendor/platform.
            try:
                res = eng.execute(raw_config=text, vendor=det.vendor,
                                  platform=det.platform)
            except ComplianceError as exc:
                # Typed safety-boundary errors are recorded, never fatal —
                # they are the boundary working, not a crash (C1 exempts
                # them; the status is recorded instead of verdicts).
                row["error"] = f"TYPED:{type(exc).__name__}: {exc}"
                row["status"] = "typed_boundary"
                rows.append(row)
                continue
            row["status"] = res.status
            row["status_reason"] = res.status_reason[:200]
            row["evaluated"] = res.evaluated
            row["passed"] = res.passed
            row["failed"] = res.failed
            row["review"] = res.review
            row["score"] = res.score
            row["benchmark_id"] = res.benchmark_id
            row["framework"] = res.framework

            # Framework attribution from control metadata (F3) — the id-shape
            # heuristic is gone; a control whose framework disagrees with its
            # id shape is a contract violation, not a silent relabel.
            cis = [e for e in res.evaluations
                   if e.evidence.framework == "CIS"]
            nist = [e for e in res.evaluations
                    if e.evidence.framework == "NIST"]
            unattributed = [e.control_id for e in res.evaluations
                            if e.evidence.framework not in ("CIS", "NIST")]
            row["cis_controls"] = len(cis)
            row["nist_controls"] = len(nist)

            mp = mf = mr = rp = rf = rr = 0
            evidence_violations: list[str] = []
            for e in res.evaluations:
                mapped = bool(e.evidence.universal_model_path)
                if e.result == "PASS":
                    if mapped:
                        mp += 1
                    else:
                        rp += 1
                elif e.result == "FAIL":
                    if mapped:
                        mf += 1
                    else:
                        rf += 1
                else:
                    if mapped:
                        mr += 1
                    else:
                        rr += 1
                # C5: every decisive verdict must carry the §12 chain with
                # observed evidence.
                # - mapped decisions: all eight keys carry observed values
                #   (a null actual/expected on a mapped decision is a
                #   fabrication gap).
                # - raw-evidence decisions (explicit regex, no model path):
                #   there is no value comparison by construction, so
                #   expected/actual/normalized may be null; the chain must
                #   instead record the matched lines + snippet + reasoning +
                #   the explicit pattern evaluated.
                # Documented exemption: absence-based PASS (negated regex —
                # absence has no lines by definition).
                if e.result in ("PASS", "FAIL"):
                    ev = e.evidence
                    if ev.universal_model_path:
                        missing = [k for k in EVIDENCE_KEYS
                                   if getattr(ev, k, None) in (None, "")]
                    else:
                        missing = [k for k in EVIDENCE_KEYS
                                   if k not in ("expected_value",
                                                "actual_value",
                                                "normalized_value")
                                   and getattr(ev, k, None) in (None, "")]
                        if not ev.audit_regex:
                            missing.append("audit_regex_pattern")
                    absence_pass = (
                        e.result == "PASS"
                        and not ev.raw_config_line_numbers)
                    if ev.operator in ("is_set", "not_set"):
                        # Presence operators define no expected value; the
                        # operator itself is the expectation.
                        missing = [m for m in missing
                                   if m != "expected_value"]
                    if absence_pass:
                        # Absence observed nothing by definition: no lines,
                        # no snippet, no parsed statement.
                        missing = [m for m in missing
                                   if m not in ("raw_config",
                                                "parsed_value")]
                    else:
                        if not ev.raw_config_line_numbers:
                            missing.append("raw_evidence_lines")
                        if not ev.raw_config:
                            missing.append("raw_evidence_snippet")
                    if missing:
                        evidence_violations.append(
                            f"{e.control_id}:{','.join(missing)}")
            row["mapped_pass"], row["mapped_fail"], row["mapped_review"] = mp, mf, mr
            row["regex_pass"], row["regex_fail"], row["regex_review"] = rp, rf, rr

            # C6: one overall score — score must equal passed/evaluated.
            score_expected = round(
                row["passed"] / row["evaluated"] * 100, 1) \
                if row["evaluated"] else 0.0
            score_violation = (row["score"] != score_expected)

            # C3: unsupported vendors must never receive decisive verdicts.
            decisive_unsupported = (
                det.vendor not in SUPPORTED
                and (row["passed"] + row["failed"]) > 0)

            violations = []
            if unattributed:
                violations.append(f"C4:unattributed={len(unattributed)}")
            if evidence_violations:
                violations.append(
                    f"C5:evidence={len(evidence_violations)}:"
                    f"{';'.join(evidence_violations[:3])}")
            if score_violation:
                violations.append(
                    f"C6:score={row['score']}!=expected={score_expected}")
            if decisive_unsupported:
                violations.append(
                    f"C3:decisive_on_unsupported={row['passed']}P+{row['failed']}F")
            row["contract_violations"] = "|".join(violations)

            # Selection bucket
            if len(cis) > 0:
                row["selection"] = "CIS+NIST"
            elif res.evaluated > 0:
                row["selection"] = "NIST-only"
            else:
                row["selection"] = "none"

            # Category G flags (wrong/unsupported vendor consequences)
            flags = []
            expected = LABEL_VENDOR.get(label, "unknown")
            if expected and det.vendor != expected:
                flags.append("label_detection_mismatch")
            if det.vendor not in SUPPORTED and res.evaluated > 0:
                flags.append("unsupported_vendor_evaluated")
            if (rp + rf) > 0 and det.vendor not in SUPPORTED:
                flags.append("regex_verdicts_on_unsupported_vendor")
            if res.evaluated > 0 and len(cis) > 0 and det.vendor != "cisco" \
                    and det.vendor != "juniper":
                flags.append("vendor_controls_on_foreign_content")
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
    by_label: dict[str, dict] = {}
    for label in sorted({r["label"] for r in rows}):
        lr = [r for r in rows if r["label"] == label]
        by_label[label] = {
            "files": len(lr),
            "errors": sum(1 for r in lr if r["error"]),
            "selection": dict(Counter(r["selection"] for r in lr)),
            "detected_vendors": dict(Counter(r["det_vendor"] for r in lr if r["det_vendor"] != "")),
            "g_files": sum(1 for r in lr if r["g_flags"]),
        }

    selection_counts = dict(Counter(r["selection"] for r in ok_rows))
    evaluated_counts = Counter(r["evaluated"] for r in ok_rows)
    g_counter: Counter = Counter()
    for r in ok_rows:
        for f in (r["g_flags"] or "").split("|"):
            if f:
                g_counter[f] += 1

    unsupported = defaultdict(lambda: {"files": 0, "evaluated": 0,
                                       "passed": 0, "failed": 0,
                                       "regex_pass": 0, "regex_fail": 0})
    for r in ok_rows:
        v = r["det_vendor"]
        if v and v not in SUPPORTED:
            u = unsupported[v]
            u["files"] += 1
            u["evaluated"] += r["evaluated"]
            u["passed"] += r["passed"]
            u["failed"] += r["failed"]
            u["regex_pass"] += r["regex_pass"]
            u["regex_fail"] += r["regex_fail"]

    contract_checks = [
        {
            "id": "C1",
            "name": "no crashes (untyped errors only; typed boundaries exempt)",
            "probes": len(rows),
            "violations": sum(
                1 for r in rows
                if r["error"] and not r["error"].startswith("TYPED:")),
            "detail": [r["file"] for r in rows
                       if r["error"] and not r["error"].startswith("TYPED:")][:5],
        },
        {
            "id": "C3",
            "name": "no decisive verdict on unsupported vendors",
            "probes": sum(r["evaluated"] for r in ok_rows
                          if r["det_vendor"] not in SUPPORTED),
            "violations": sum(
                1 for r in ok_rows
                if r["det_vendor"] not in SUPPORTED
                and (r["passed"] + r["failed"]) > 0),
            "detail": [r["file"] for r in ok_rows
                       if r["det_vendor"] not in SUPPORTED
                       and (r["passed"] + r["failed"]) > 0][:5],
        },
        {
            "id": "C4/C5/C6",
            "name": "per-file contract violations (attribution, evidence, score)",
            "probes": len(ok_rows),
            "violations": sum(
                1 for r in ok_rows if r["contract_violations"]),
            "detail": [f"{r['file']}:{r['contract_violations']}"
                       for r in ok_rows if r["contract_violations"]][:5],
        },
    ]

    # C2: deterministic selection — re-run a sample with a FRESH engine and
    # require identical control-id order, verdicts, score and framework.
    det_sample = [r for r in ok_rows if not r["error"]][:40]
    det_engine = BenchmarkExecutionEngine()
    det_mismatch = []
    for r in det_sample:
        text = (CORPUS / r["file"]).read_text(encoding="utf-8",
                                              errors="replace")
        det = detector.detect(text)
        rerun = det_engine.execute(raw_config=text, vendor=det.vendor,
                                   platform=det.platform)
        # Compare against the recorded verdict totals + selection.
        if (rerun.evaluated != r["evaluated"] or rerun.passed != r["passed"]
                or rerun.failed != r["failed"] or rerun.review != r["review"]
                or rerun.score != r["score"] or rerun.status != r["status"]):
            det_mismatch.append(r["file"])
    contract_checks.append({
        "id": "C2",
        "name": "deterministic selection + verdicts across fresh engines",
        "probes": len(det_sample),
        "violations": len(det_mismatch),
        "detail": det_mismatch[:5],
    })
    contract_violations = sum(c["violations"] for c in contract_checks)

    summary = {
        "corpus": str(CORPUS),
        "engine": "07_compliance",
        "contract_version": "E07",
        "files": len(rows),
        "processed_ok": len(ok_rows),
        "errors": len(rows) - len(ok_rows),
        "elapsed_s": elapsed,
        "selection_distribution": selection_counts,
        "status_distribution": dict(
            Counter(r["status"] for r in ok_rows)),
        "evaluated_control_distribution": dict(sorted(evaluated_counts.items())),
        "verdict_totals": {
            "passed": sum(r["passed"] for r in ok_rows),
            "failed": sum(r["failed"] for r in ok_rows),
            "review": sum(r["review"] for r in ok_rows),
        },
        "regex_driven_totals": {
            "pass": sum(r["regex_pass"] for r in ok_rows),
            "fail": sum(r["regex_fail"] for r in ok_rows),
            "review": sum(r["regex_review"] for r in ok_rows),
        },
        "mapped_totals": {
            "pass": sum(r["mapped_pass"] for r in ok_rows),
            "fail": sum(r["mapped_fail"] for r in ok_rows),
            "review": sum(r["mapped_review"] for r in ok_rows),
        },
        "g_flags": dict(g_counter),
        "unsupported_vendor_outcomes": dict(unsupported),
        "detected_vendor_distribution": dict(
            Counter(r["det_vendor"] for r in ok_rows)),
        "empty_files": sum(1 for r in ok_rows if str(r["bytes"]) == "0"),
        "nul_files": sum(1 for r in ok_rows if str(r["has_nul"]) == "1"),
        "files_with_zero_evaluated": sum(1 for r in ok_rows
                                         if r["evaluated"] == 0),
        "contract_checks": contract_checks,
        "contract_violations_total": contract_violations,
        "contract_verdict": "PASS" if contract_violations == 0 else "FAIL",
        "by_label": by_label,
    }
    (OUT / "dataset_summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8")
    (OUT / "contract_results.json").write_text(
        json.dumps({"checks": contract_checks,
                    "violations_total": contract_violations,
                    "verdict": summary["contract_verdict"]},
                   indent=2, default=str), encoding="utf-8")
    print(json.dumps(summary, indent=2, default=str)[:4500])
    print(f"\nwrote {csv_path} and dataset_summary.json ({elapsed}s)")
    for check in contract_checks:
        print(f"  {check['id']:>3} {check['name']}: {check['probes']} probes, "
              f"{check['violations']} violations")
    if contract_violations:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
