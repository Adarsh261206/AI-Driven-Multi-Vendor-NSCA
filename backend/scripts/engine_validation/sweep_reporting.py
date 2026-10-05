"""Corpus sweep for Engine 11 (Reporting, spec 10.11).

For every file in the 480-file dataset: run the real AuditExecutor, shape
the output API-style (plain scalars, as the ORM VARCHAR round-trip serves),
build audit_data with real pipeline identification values, generate the PDF,
and verify contract checks C1-C7. Two report variants per file:

  A (matched):   file_details filename == affected_device -> every finding
                 attributed, no Unattributed row expected.
  B (unmatched): file_details filename suffixed '-nomatch' -> every finding
                 unattributed (when findings exist), Unattributed row expected.

Outputs (artifacts/engine_validation/11_reporting/):
    dataset_results.csv  dataset_summary.json  contract_results.json
"""

from __future__ import annotations

import base64
import csv
import json
import re
import statistics
import sys
import time
import traceback
import zlib
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))

from app.engines.compliance.executor import AuditExecutor  # noqa: E402
from app.engines.reporting import (  # noqa: E402
    ReportEngineError,
    generate_audit_report,
)

CORPUS = Path(r"C:\Users\priye\Downloads\SIH Config\final-dataset")
OUT = BACKEND / "artifacts" / "engine_validation" / "11_reporting"

PER_REPORT_BUDGET_S = 30.0  # roadmap §7: PDF generation < 30 s per report
DET_SAMPLE = 30


def _plain(value):
    return value.value if hasattr(value, "value") else value


def pdf_text(pdf: bytes) -> str:
    out: list[bytes] = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        raw = m.group(1).strip()
        for fn in (lambda: zlib.decompress(base64.a85decode(raw, adobe=True)),
                   lambda: zlib.decompress(raw)):
            try:
                out.append(fn())
                break
            except Exception:
                continue
    return b"\n".join(out).decode("latin-1", errors="replace")


def canon(text: str) -> str:
    text = re.sub(r"\)\s*[-+0-9.]+\s*\(", "", text)
    text = text.replace(") Tj (", "").replace(")Tj(", "")
    # reportlab escapes literal parens/backslash inside content strings
    return text.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")


def normalize(text: str) -> str:
    return re.sub(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC", "<GENERATED>", text)


def shape_run(run, filename: str):
    """API-shaped (finding dicts, result rows, audit_data) from a run."""
    det = run.detection_result
    findings = [{
        "title": f.title, "description": f.description,
        "severity": _plain(f.severity), "status": _plain(f.status),
        "confidence": f.confidence,
        "evidence": dict(f.evidence) if isinstance(f.evidence, dict)
        else {"raw": str(f.evidence)},
        "remediation": dict(f.remediation)
        if isinstance(f.remediation, dict) else {},
        "affected_device": f.affected_device,
        "risk_score": f.risk_score, "priority": f.priority,
    } for f in (run.findings or [])]
    ce = run.compliance_evaluation
    evals = ce.evaluations if hasattr(ce, "evaluations") else (ce or [])
    results = [{
        "control_id": e.control_id, "control_name": e.control_title,
        "result": _plain(e.result), "severity": _plain(e.severity),
    } for e in evals]
    audit = {
        "audit_id": f"e11sw-{filename}", "audit_name": filename,
        "framework": _plain(getattr(run, "framework", "CIS")) or "CIS",
        "status": run.status,
        "overall_score": (run.overall_score
                          if run.overall_score is not None else 0.0),
        "configuration_count": 1,
        "file_details": [{
            "filename": filename,
            "vendor": _plain(getattr(run, "vendor", "unknown")) or "unknown",
            "device_type": _plain(getattr(det, "device_type", "unknown"))
            or "unknown",
            "platform": _plain(getattr(run, "platform", "unknown"))
            or "unknown",
            "hostname": getattr(det, "hostname", None),
            "firmware_version": getattr(run, "firmware_version", None),
            "confidence": getattr(run, "detection_confidence", None),
            "detection_method": _plain(getattr(det, "detection_method", ""))
            or "",
        }],
    }
    return findings, results, audit


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in CORPUS.rglob("*") if p.is_file())
    assert len(files) == 480, f"expected 480 corpus files, got {len(files)}"

    engine = AuditExecutor()
    rows: list[dict] = []
    c1_errors: list[str] = []      # untyped errors
    c1_typed: list[str] = []       # ReportEngineError (typed, still a defect here)
    c2_bad: list[str] = []
    c3_missing: list[str] = []
    c3_count_bad: list[str] = []
    c4_bad: list[str] = []
    c5_bad: list[str] = []
    c7_over: list[str] = []
    gen_ms: list[float] = []
    total_findings = 0
    total_bytes = 0
    t0 = time.perf_counter()

    for idx, path in enumerate(files, 1):
        text = path.read_text(encoding="utf-8", errors="replace")
        fname = path.relative_to(CORPUS).as_posix()
        row: dict = {"file": fname}
        try:
            run = engine.execute(audit_id=f"e11sw-{fname}",
                                 config_content=text,
                                 device_name=fname)
            findings, results, audit = shape_run(run, fname)
            row["exec_status"] = run.status
            row["findings"] = len(findings)
            row["results"] = len(results)
            total_findings += len(findings)

            # Variant A: matched attribution.
            start = time.perf_counter()
            pdf_a = generate_audit_report(audit, findings, results)
            gen_ms.append((time.perf_counter() - start) * 1000.0)
            # Variant B: unmatched attribution.
            audit_b = dict(audit)
            audit_b["file_details"] = [dict(audit["file_details"][0],
                                            filename=fname + "-nomatch",
                                            hostname=None)]
            start = time.perf_counter()
            pdf_b = generate_audit_report(audit_b, findings, results)
            gen_ms.append((time.perf_counter() - start) * 1000.0)

            for tag, pdf in (("A", pdf_a), ("B", pdf_b)):
                if not (pdf.startswith(b"%PDF")
                        and pdf.rstrip().endswith(b"%%EOF")):
                    c2_bad.append(f"{path.name}:{tag}")
            row["pdf_bytes"] = len(pdf_a)

            ctext = canon(pdf_text(pdf_a))
            # C3: summary count cells + every finding title rendered.
            if ("Total Findings" not in ctext
                    or f"({len(findings)})" not in ctext):
                c3_count_bad.append(path.name)
            missing = [f["title"] for f in findings
                       if f["title"] not in ctext]
            if missing:
                c3_missing.append(f"{fname}:{len(missing)}")
            row["titles_missing"] = len(missing)

            # C4: Unattributed presence matches expectation on both variants.
            ctext_b = canon(pdf_text(pdf_b))
            if len(findings) == 0:
                if "Unattributed" in ctext or "Unattributed" in ctext_b:
                    c4_bad.append(f"{fname}:empty-but-unattributed")
            else:
                if "Unattributed" in ctext:
                    c4_bad.append(f"{fname}:matched-but-unattributed")
                if "Unattributed" not in ctext_b:
                    c4_bad.append(f"{fname}:unmatched-but-attributed")

            # C5: no unconditional ML claim; neutral cover line present.
            if "Powered by ML" in ctext:
                c5_bad.append(fname)
            row["neutral_cover"] = ("Automated analysis of device" in ctext)

            for ms in gen_ms[-2:]:
                if ms / 1000.0 > PER_REPORT_BUDGET_S:
                    c7_over.append(f"{fname}:{ms:.0f}ms")
            row["gen_ms_a"] = round(gen_ms[-2], 1)
            row["gen_ms_b"] = round(gen_ms[-1], 1)
            total_bytes += len(pdf_a) + len(pdf_b)
            row["error"] = ""
        except ReportEngineError as e:
            c1_typed.append(f"{fname}:{e}")
            row["error"] = f"TYPED {e}"
        except Exception as e:  # noqa: BLE001
            c1_errors.append(f"{fname}:{type(e).__name__}:{e}")
            row["error"] = f"{type(e).__name__}: {e}"
            traceback.print_exc()
        rows.append(row)
        if idx % 60 == 0:
            print(f"{idx}/{len(files)} files...")

    # C6: determinism sample — re-run executor + report, compare normalized.
    det_bad: list[str] = []
    step = max(1, len(files) // DET_SAMPLE)
    for path in files[::step][:DET_SAMPLE]:
        text = path.read_text(encoding="utf-8", errors="replace")
        fname = path.relative_to(CORPUS).as_posix()
        try:
            r1 = engine.execute(audit_id="e11sw-det", config_content=text,
                                device_name=fname)
            f1, s1, a1 = shape_run(r1, fname)
            first = normalize(canon(pdf_text(
                generate_audit_report(a1, f1, s1))))
            r2 = engine.execute(audit_id="e11sw-det2", config_content=text,
                                device_name=fname)
            f2, s2, a2 = shape_run(r2, fname)
            second = normalize(canon(pdf_text(
                generate_audit_report(a2, f2, s2))))
            if first != second:
                det_bad.append(fname)
        except Exception as e:  # noqa: BLE001
            det_bad.append(f"{fname}:{type(e).__name__}")

    elapsed = time.perf_counter() - t0
    checks = [
        {"id": "C1", "name": "no untyped errors across the corpus",
         "probes": len(files), "violations": len(c1_errors),
         "detail": c1_errors[:10]},
        {"id": "C1t", "name": "no typed contract errors either",
         "probes": len(files), "violations": len(c1_typed),
         "detail": c1_typed[:10]},
        {"id": "C2", "name": "every report is a well-formed PDF",
         "probes": len(files) * 2, "violations": len(c2_bad),
         "detail": c2_bad[:10]},
        {"id": "C3", "name": "summary counts + every finding title rendered",
         "probes": total_findings + len(files),
         "violations": len(c3_missing) + len(c3_count_bad),
         "detail": (c3_missing + c3_count_bad)[:10]},
        {"id": "C4", "name": "Unattributed presence matches attribution "
                             "expectation on matched/unmatched variants",
         "probes": len(files) * 2, "violations": len(c4_bad),
         "detail": c4_bad[:10]},
        {"id": "C5", "name": "no unconditional ML claim in any report",
         "probes": len(files), "violations": len(c5_bad),
         "detail": c5_bad[:10]},
        {"id": "C6", "name": "deterministic reports across re-runs",
         "probes": min(DET_SAMPLE, len(files)), "violations": len(det_bad),
         "detail": det_bad[:10]},
        {"id": "C7", "name": f"per-report build under {PER_REPORT_BUDGET_S}s",
         "probes": len(gen_ms), "violations": len(c7_over),
         "detail": c7_over[:10]},
    ]
    total_viol = sum(c["violations"] for c in checks)
    summary = {
        "files": len(files),
        "ok_files": sum(1 for r in rows if not r.get("error")),
        "errors": len(c1_errors) + len(c1_typed),
        "elapsed_s": round(elapsed, 1),
        "findings": total_findings,
        "pdf_bytes_total": total_bytes,
        "gen_ms": {
            "p50": round(statistics.median(gen_ms), 1) if gen_ms else 0,
            "p95": round(sorted(gen_ms)[int(len(gen_ms) * 0.95)], 1)
            if gen_ms else 0,
            "max": round(max(gen_ms), 1) if gen_ms else 0,
        },
        "contract_checks": checks,
        "contract_violations_total": total_viol,
        "contract_verdict": "PASS" if total_viol == 0 else "FAIL",
    }
    with open(OUT / "dataset_results.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["file", "exec_status", "findings",
                                           "results", "pdf_bytes",
                                           "gen_ms_a", "gen_ms_b",
                                           "titles_missing", "neutral_cover",
                                           "error"])
        w.writeheader()
        w.writerows(rows)
    (OUT / "dataset_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    (OUT / "contract_results.json").write_text(
        json.dumps({"checks": checks, "violations_total": total_viol,
                    "verdict": summary["contract_verdict"]}, indent=2),
        encoding="utf-8")
    print(json.dumps(summary, indent=2)[:2000])
    for c in checks:
        print(f"   {c['id']} {c['name']}: {c['probes']} probes, "
              f"{c['violations']} violations")
    return 0 if total_viol == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
