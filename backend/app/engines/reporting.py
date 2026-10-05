from __future__ import annotations

import io
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#DC2626"),
    "HIGH": colors.HexColor("#EA580C"),
    "MEDIUM": colors.HexColor("#CA8A04"),
    "LOW": colors.HexColor("#2563EB"),
}

RESULT_COLORS = {
    "PASS": colors.HexColor("#16A34A"),
    "FAIL": colors.HexColor("#DC2626"),
    "REVIEW": colors.HexColor("#CA8A04"),
}


class ReportEngineError(Exception):
    """Typed error for Reporting Engine (E11) contract violations.

    Raised for structural input violations (wrong container types,
    non-mapping entries) — never for missing optional display values,
    which render as explicit defaults ("N/A", "0", ...). Callers can
    rely on: no AttributeError/TypeError/ValueError from untrusted or
    partial audit data; either valid PDF bytes or ReportEngineError.
    """


def _str(value: Any, default: str = "N/A") -> str:
    """Display coercion: None means missing (yields the default).

    Strings pass through; other scalars are str()-ified so stored data
    (ints, floats) renders instead of crashing Paragraph.
    """
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def _esc(value: Any) -> str:
    """Escape untrusted data interpolated into Paragraph markup.

    ReportLab Paragraph parses a markup subset: a stray '<' from config
    content (evidence, titles, commands) can abort the whole document
    with ValueError, and well-formed tags would render as formatting
    instead of literal text. Escaping keeps data literal (V03-44).
    """
    return _xml_escape(_str(value, ""))


def _score(value: Any) -> str:
    """Overall-score display: '80.0%'; missing -> '0.0%'; garbage -> 'N/A'."""
    if value is None:
        return "0.0%"
    try:
        return f"{float(value):.1f}%"
    except (TypeError, ValueError):
        return "N/A"


def _confidence(value: Any) -> str:
    """Finding-confidence display: '90%'; missing -> '0%'; garbage -> 'N/A'."""
    if value is None:
        return "0%"
    try:
        return f"{float(value) * 100:.0f}%"
    except (TypeError, ValueError):
        return "N/A"


def _file_confidence(value: Any) -> str:
    """Device-identification confidence: '90%'; missing -> 'N/A'."""
    if value is None:
        return "N/A"
    try:
        return f"{float(value) * 100:.0f}%"
    except (TypeError, ValueError):
        return "N/A"


def _str_list(value: Any) -> List[str]:
    """Remediation step lists: lists/tuples of coerced strings, else []."""
    if isinstance(value, (list, tuple)):
        return [_str(v, "") for v in value]
    return []


def _as_list(value: Any, name: str) -> List[Any]:
    """Structural gate: report collections must be lists (None = empty)."""
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise ReportEngineError(
            f"{name} must be a list of mappings, got {type(value).__name__}")
    return list(value)


def validate_report_inputs(
    audit_data: Any,
    findings: Any,
    compliance_results: Any,
) -> Dict[str, List[Any]]:
    """Validate the §10.11 input contract; return normalized collections.

    Raises ReportEngineError on structural violations (wrong container
    types, non-mapping entries). Scalar display values are NOT rejected
    here — they are coerced at render time so partial stored data still
    yields a report instead of a 500.
    """
    if not isinstance(audit_data, dict):
        raise ReportEngineError(
            "audit_data must be a mapping, got "
            f"{type(audit_data).__name__}")
    findings = _as_list(findings, "findings")
    compliance_results = _as_list(compliance_results, "compliance_results")
    file_details = _as_list(audit_data.get("file_details"), "file_details")
    for entry in findings:
        if not isinstance(entry, dict):
            raise ReportEngineError(
                "every finding must be a mapping, got "
                f"{type(entry).__name__}")
    for entry in compliance_results:
        if not isinstance(entry, dict):
            raise ReportEngineError(
                "every compliance result must be a mapping, got "
                f"{type(entry).__name__}")
    for entry in file_details:
        if not isinstance(entry, dict):
            raise ReportEngineError(
                "every file detail must be a mapping, got "
                f"{type(entry).__name__}")
    return {
        "findings": findings,
        "compliance_results": compliance_results,
        "file_details": file_details,
    }


def _get_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=22,
            leading=28,
            spaceAfter=6,
            textColor=colors.HexColor("#111827"),
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Normal"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#6B7280"),
            spaceAfter=20,
        ),
        "heading1": ParagraphStyle(
            "Heading1Custom",
            parent=base["Heading1"],
            fontSize=16,
            leading=20,
            spaceBefore=18,
            spaceAfter=8,
            textColor=colors.HexColor("#1F2937"),
        ),
        "heading2": ParagraphStyle(
            "Heading2Custom",
            parent=base["Heading2"],
            fontSize=13,
            leading=16,
            spaceBefore=12,
            spaceAfter=6,
            textColor=colors.HexColor("#374151"),
        ),
        "body": ParagraphStyle(
            "BodyCustom",
            parent=base["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#374151"),
        ),
        "small": ParagraphStyle(
            "SmallCustom",
            parent=base["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#6B7280"),
        ),
        "cell": ParagraphStyle(
            "CellCustom",
            parent=base["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#374151"),
        ),
        "cell_header": ParagraphStyle(
            "CellHeader",
            parent=base["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.white,
        ),
        "pass": ParagraphStyle(
            "PassText",
            parent=base["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#16A34A"),
        ),
        "fail": ParagraphStyle(
            "FailText",
            parent=base["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#DC2626"),
        ),
    }


def _header_footer(canvas, doc, audit_data: Dict[str, Any]):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#9CA3AF"))
    canvas.drawString(2 * cm, A4[1] - 1.2 * cm, "ConfigShield — Network Security Compliance Auditor — Confidential")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    canvas.drawCentredString(A4[0] / 2, 1.2 * cm, _str(audit_data.get("audit_name"), "Audit Report"))
    canvas.restoreState()


def generate_audit_report(
    audit_data: Dict[str, Any],
    findings: List[Dict[str, Any]],
    compliance_results: List[Dict[str, Any]],
    output_path: Optional[str] = None,
) -> bytes:
    # E11: fail fast with a typed error on structural violations; scalar
    # display values are coerced at render time (never a crash).
    normalized = validate_report_inputs(audit_data, findings,
                                        compliance_results)
    findings = normalized["findings"]
    compliance_results = normalized["compliance_results"]
    file_details = normalized["file_details"]

    buffer = io.BytesIO()
    styles = _get_styles()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    elements: List[Any] = []

    # === Cover / Title ===
    elements.append(Spacer(1, 2 * cm))
    elements.append(Paragraph("ConfigShield — Compliance Audit Report", styles["title"]))
    elements.append(Paragraph(
        f"<b>{_esc(audit_data.get('audit_name') or 'N/A')}</b>",
        styles["subtitle"],
    ))
    # E11 F8: the cover carries no unconditional ML claim. Per-engine
    # model availability is disclosed in the footer only when the models
    # actually run (V09-69); the cover line is model-agnostic.
    elements.append(Paragraph(
        "<font size='8' color='#6B7280'>Automated analysis of device "
        "configurations against the specified compliance framework</font>",
        styles["small"],
    ))

    meta_data = [
        ["Audit ID", _esc(audit_data.get("audit_id") or "N/A")],
        ["Framework", _esc(audit_data.get("framework") or "CIS")],
        ["Status", _esc(audit_data.get("status") or "N/A")],
        ["Overall Score", _score(audit_data.get("overall_score", 0))],
        ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Configurations Audited", _str(audit_data.get("configuration_count", 0), "0")],
    ]
    meta_table = Table(meta_data, colWidths=[5 * cm, 10 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#374151")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#1F2937")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, -1), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 0.6 * cm))

    # === Per-File Device Details (Real Analysis) ===
    # E11: file_details was normalized by validate_report_inputs.
    if file_details:
        elements.append(Paragraph("Analyzed Files — Device Identification", styles["heading1"]))
        fd_header = [
            Paragraph("<b>File</b>", styles["cell_header"]),
            Paragraph("<b>Vendor</b>", styles["cell_header"]),
            Paragraph("<b>Device Type</b>", styles["cell_header"]),
            Paragraph("<b>Platform</b>", styles["cell_header"]),
            Paragraph("<b>Hostname</b>", styles["cell_header"]),
        ]
        fd_data = [fd_header]
        for fd in file_details:
            vendor = _str(fd.get("vendor", "unknown"), "unknown")
            dtype = _str(fd.get("device_type", "unknown"), "unknown")
            # Color device type
            dtype_display = f'<font color="#1F2937">{_esc(dtype.title())}</font>'
            if dtype.lower() == "switch":
                dtype_display = f'<font color="#2563EB">{_esc(dtype.title())}</font>'
            elif dtype.lower() == "router":
                dtype_display = f'<font color="#EA580C">{_esc(dtype.title())}</font>'
            elif dtype.lower() == "firewall":
                dtype_display = f'<font color="#DC2626">{_esc(dtype.title())}</font>'
            fd_data.append([
                Paragraph(_esc(_str(fd.get("filename"), "N/A")[:30]), styles["cell"]),
                Paragraph(_esc(vendor.title()) if vendor.lower() != "unknown" else "Unknown", styles["cell"]),
                Paragraph(dtype_display, styles["cell"]),
                Paragraph(_esc(fd.get("platform", "unknown")), styles["cell"]),
                Paragraph(_esc(fd.get("hostname") or "—"), styles["cell"]),
            ])
        fd_table = Table(fd_data, colWidths=[5 * cm, 3 * cm, 3 * cm, 3 * cm, 3 * cm])
        fd_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("GRID", (0, 0), (-1, 0), 0.5, colors.HexColor("#D1D5DB")),
            ("GRID", (0, 1), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ]))
        elements.append(fd_table)
        elements.append(Spacer(1, 0.6 * cm))

        # Firmware + confidence row if available
        for fd in file_details:
            if fd.get("firmware_version") or fd.get("confidence") is not None:
                elements.append(Paragraph(
                    f"<font size='7' color='#6B7280'><b>{_esc(fd.get('filename') or '')}:</b> "
                    f"Firmware {_esc(fd.get('firmware_version') or 'N/A')} · "
                    f"Confidence {_file_confidence(fd.get('confidence'))} · "
                    f"{_esc(fd.get('detection_method') or '')}</font>",
                    styles["small"]
                ))
        elements.append(Spacer(1, 0.4 * cm))

    # === Per-Device Compliance Breakdown (Next-Level) ===
    if file_details and findings:
        elements.append(Paragraph("Per-Device Compliance Breakdown", styles["heading1"]))
        from collections import defaultdict
        # E11 F7: attribution is matched-only. A finding belongs to a
        # device when its affected_device (or evidence hostname) names
        # that device's filename or hostname. Findings that match
        # neither are listed under an explicit "Unattributed" row — the
        # old proportional fallback (slicing the global finding list per
        # device) invented per-device counts and is deleted.
        findings_by_file: dict[str, list] = defaultdict(list)
        findings_by_host: dict[str, list] = defaultdict(list)
        for f in findings:
            ev = f.get("evidence")
            ev = ev if isinstance(ev, dict) else {}
            dev = f.get("affected_device") or ev.get("hostname") or "unknown"
            findings_by_file[_str(dev, "unknown")].append(f)
            if ev.get("hostname"):
                findings_by_host[_str(ev.get("hostname"), "unknown")].append(f)
        per_file_header = [
            Paragraph("<b>Device</b>", styles["cell_header"]),
            Paragraph("<b>Type</b>", styles["cell_header"]),
            Paragraph("<b>Findings</b>", styles["cell_header"]),
            Paragraph("<b>Critical</b>", styles["cell_header"]),
            Paragraph("<b>High</b>", styles["cell_header"]),
        ]
        per_file_data = [per_file_header]
        matched_ids: set[int] = set()
        for fd in file_details:
            fname = _str(fd.get("filename", "unknown"), "unknown")
            dtype = _str(fd.get("device_type", "unknown"), "unknown")
            hostname = _str(fd.get("hostname") or "", "")
            f_list = list(findings_by_file.get(fname, []))
            if not f_list and hostname:
                f_list = list(findings_by_host.get(hostname, []))
            matched_ids.update(id(fl) for fl in f_list)
            crit = sum(1 for fl in f_list if fl.get("severity") == "CRITICAL")
            high = sum(1 for fl in f_list if fl.get("severity") == "HIGH")
            dtype_col = f'<font color="#2563EB">{_esc(dtype.title())}</font>' if dtype.lower() == "switch" else f'<font color="#DC2626">{_esc(dtype.title())}</font>' if dtype.lower() == "firewall" else f'<font color="#EA580C">{_esc(dtype.title())}</font>' if dtype.lower() == "router" else _esc(dtype.title())
            per_file_data.append([
                Paragraph(_esc(fname[:20]), styles["cell"]),
                Paragraph(dtype_col, styles["cell"]),
                Paragraph(str(len(f_list)), styles["cell"]),
                Paragraph(str(crit), styles["cell"]),
                Paragraph(str(high), styles["cell"]),
            ])
        unattributed = [fl for fl in findings if id(fl) not in matched_ids]
        if unattributed:
            crit = sum(1 for fl in unattributed if fl.get("severity") == "CRITICAL")
            high = sum(1 for fl in unattributed if fl.get("severity") == "HIGH")
            per_file_data.append([
                Paragraph("Unattributed", styles["cell"]),
                Paragraph("—", styles["cell"]),
                Paragraph(str(len(unattributed)), styles["cell"]),
                Paragraph(str(crit), styles["cell"]),
                Paragraph(str(high), styles["cell"]),
            ])
        per_file_table = Table(per_file_data, colWidths=[5 * cm, 3 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm])
        per_file_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
        ]))
        elements.append(per_file_table)
        elements.append(Spacer(1, 0.6 * cm))

    # === Executive Summary ===
    elements.append(Paragraph("Executive Summary", styles["heading1"]))

    total_findings = len(findings)
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")
    total_pass = sum(1 for c in compliance_results if c.get("result") == "PASS")
    total_fail = sum(1 for c in compliance_results if c.get("result") == "FAIL")
    total_review = sum(1 for c in compliance_results if c.get("result") == "REVIEW")
    total_controls = len(compliance_results)

    summary_data = [
        [
            Paragraph("<b>Metric</b>", styles["cell_header"]),
            Paragraph("<b>Value</b>", styles["cell_header"]),
        ],
        ["Overall Score", _score(audit_data.get("overall_score", 0))],
        ["Total Findings", str(total_findings)],
        ["Critical", str(critical_count)],
        ["High", str(high_count)],
        ["Medium", str(medium_count)],
        ["Low", str(low_count)],
        ["Controls Evaluated", str(total_controls)],
        ["Controls Passed", f"{total_pass} ({(total_pass/total_controls*100):.0f}%)" if total_controls else "0"],
        ["Controls Failed", f"{total_fail} ({(total_fail/total_controls*100):.0f}%)" if total_controls else "0"],
        ["Controls Review", f"{total_review} ({(total_review/total_controls*100):.0f}%)" if total_controls else "0"],
    ]

    summary_table = Table(summary_data, colWidths=[8 * cm, 7 * cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("GRID", (0, 0), (-1, 0), 0.5, colors.HexColor("#D1D5DB")),
    ]))
    elements.append(summary_table)
    # E11 F9: break only when more content follows — an unconditional
    # break here left a trailing blank page on finding-less reports.
    if findings or compliance_results:
        elements.append(PageBreak())

    # === Findings Detail ===
    if findings:
        elements.append(Paragraph("Findings", styles["heading1"]))

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "LOW"), 4))

        for i, finding in enumerate(sorted_findings, 1):
            sev = _str(finding.get("severity", "LOW"), "LOW")
            sev_color = SEVERITY_COLORS.get(sev, colors.gray)

            elements.append(Paragraph(
                f"<b>{i}. {_esc(finding.get('title', 'Untitled Finding'))}</b>",
                styles["heading2"],
            ))

            info_data = [
                ["Severity", sev],
                ["Status", _str(finding.get("status", "open"), "open")],
                ["Confidence", _confidence(finding.get("confidence", 0))],
                # E09 F1/F9: persisted 10.9 output rendered from the same
                # values storage holds (never recomputed for the report).
                ["Risk", (f"{finding.get('risk_score')} "
                          f"({_str(finding.get('priority'), 'N/A')})"
                          if finding.get("risk_score") is not None
                          else "not assessed")],
            ]
            info_table = Table(info_data, colWidths=[4 * cm, 11 * cm])
            info_table.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (1, 0), (1, 0), sev_color),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(info_table)

            if finding.get("description"):
                elements.append(Spacer(1, 3 * mm))
                elements.append(Paragraph(f"<b>Description:</b> {_esc(finding['description'])}", styles["body"]))

            evidence = finding.get("evidence")
            evidence = evidence if isinstance(evidence, dict) else {}
            if isinstance(evidence, dict):
                evidence_parts = []
                if evidence.get("vendor"):
                    evidence_parts.append(f"Vendor: {_esc(evidence['vendor'])}")
                    dtype = evidence.get("device_type") or finding.get("device_type") or audit_data.get("device_type")
                    if dtype and _str(dtype, "unknown") != "unknown":
                        evidence_parts[-1] += f" ({_esc(dtype)})"
                if evidence.get("platform"):
                    evidence_parts.append(f"Platform: {_esc(evidence['platform'])}")
                if evidence.get("hostname"):
                    evidence_parts.append(f"Hostname: {_esc(evidence['hostname'])}")
                if evidence.get("device_type") and not evidence.get("vendor"):
                    evidence_parts.append(f"Device Type: {_esc(evidence['device_type'])}")
                if evidence.get("control_id"):
                    evidence_parts.append(f"Control: {_esc(evidence['control_id'])}")
                if evidence.get("actual_value"):
                    evidence_parts.append(f"Actual: {_esc(evidence['actual_value'])}")
                if evidence.get("expected_value"):
                    evidence_parts.append(f"Expected: {_esc(evidence['expected_value'])}")
                if evidence_parts:
                    elements.append(Spacer(1, 3 * mm))
                    elements.append(Paragraph("<b>Evidence:</b>", styles["body"]))
                    for part in evidence_parts:
                        elements.append(Paragraph(f"  {part}", styles["small"]))

            remediation = finding.get("remediation")
            remediation = remediation if isinstance(remediation, dict) else {}
            # E10: §12 remediation keys (risk_description, recommended_config,
            # verification/rollback steps); legacy description/command keys
            # are honored when present for backward compatibility.
            if isinstance(remediation, dict) and (remediation.get("risk_description") or remediation.get("description")):
                elements.append(Spacer(1, 3 * mm))
                elements.append(Paragraph(f"<b>Remediation:</b> {_esc(remediation.get('risk_description') or remediation.get('description'))}", styles["body"]))
                command = remediation.get("recommended_config") or remediation.get("command") or ""
                if command:
                    elements.append(Paragraph(
                        f"<font face='Courier' size='8'>  {_esc(command)}</font>",
                        styles["small"],
                    ))
                for step in _str_list(remediation.get("verification_steps"))[:5]:
                    elements.append(Paragraph(f"  Verify: {_esc(step)}", styles["small"]))
                for step in _str_list(remediation.get("rollback_steps"))[:5]:
                    elements.append(Paragraph(f"  Rollback: {_esc(step)}", styles["small"]))

            elements.append(Spacer(1, 6 * mm))

        # E11 F9: trailing break only when the compliance section follows.
        if compliance_results:
            elements.append(PageBreak())

    # === Compliance Results ===
    if compliance_results:
        elements.append(Paragraph("Compliance Evaluation Results", styles["heading1"]))

        header_row = [
            Paragraph("<b>Control ID</b>", styles["cell_header"]),
            Paragraph("<b>Control Name</b>", styles["cell_header"]),
            Paragraph("<b>Result</b>", styles["cell_header"]),
            Paragraph("<b>Severity</b>", styles["cell_header"]),
        ]
        table_data = [header_row]

        for cr in compliance_results:
            result_val = _str(cr.get("result", ""), "")
            result_color = RESULT_COLORS.get(result_val, colors.gray)
            table_data.append([
                Paragraph(_esc(cr.get("control_id", "")), styles["cell"]),
                Paragraph(_esc(cr.get("control_name", "")), styles["cell"]),
                Paragraph(f'<font color="{result_color.hexval()}">{_esc(result_val)}</font>', styles["cell"]),
                Paragraph(_esc(cr.get("severity", "")), styles["cell"]),
            ])

        cr_table = Table(table_data, colWidths=[3 * cm, 5.5 * cm, 3 * cm, 3.5 * cm])
        cr_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("GRID", (0, 0), (-1, 0), 0.5, colors.HexColor("#D1D5DB")),
        ]))
        elements.append(cr_table)

    # === Footer Note ===
    elements.append(Spacer(1, 0.6 * cm))
    # ML model info (real, not hardcoded) — all 3 engines
    try:
        from app.ml.model import get_all_engines_info
        ml_info = get_all_engines_info()
        if ml_info.get("available"):
            # Vendor + Risk + Semantic + Normalisation
            vendor_acc = ml_info.get("vendor_accuracy", 0) * 100
            device_acc = ml_info.get("device_type_accuracy", 0) * 100
            sem_acc = ml_info.get("semantic_meta", {}).get("accuracy", 0) * 100
            norm_acc = ml_info.get("normalisation_meta", {}).get("accuracy", 0) * 100
            # E09 §15: the risk-model claim is gated on RISK model
            # availability (separate metadata), never the vendor flag —
            # and the fit metric is labeled for what it measures
            # (formula-emulation fit on synthetic labels).
            from app.engines.compliance.risk import advisory_model_info
            risk_info = advisory_model_info()
            if risk_info.get("available"):
                risk_line = (
                    f"• Risk Scoring (advisory): RandomForest "
                    f"(formula-emulation R² "
                    f"{risk_info.get('r2_formula_emulation', 0):.3f}) → "
                    f"severity×vendor×category×confidence → risk 0-100<br/>"
                )
            else:
                risk_line = ("• Risk Scoring: deterministic formula "
                             "(advisory model unavailable)<br/>")
            elements.append(Paragraph(
                f"<font size='7' color='#059669'><b>ML Analysis — All Engines Trained:</b><br/>"
                f"• Vendor Detection: TF-IDF+LR (Acc {vendor_acc:.0f}%, {ml_info.get('train_size',0)} samples) → Switch/Router/Firewall<br/>"
                f"• Normalisation: TF-IDF+LR (Acc {norm_acc:.0f}%, 28 universal paths) → raw line → universal model<br/>"
                f"• Semantic: TF-IDF+LR (Acc {sem_acc:.0f}%, HIGH/MEDIUM/LOW) → unknown syntax security relevance<br/>"
                f"{risk_line}"
                f"Device type and hostname extracted per file via ML + pattern evidence.</font>",
                styles["small"],
            ))
            elements.append(Spacer(1, 3 * mm))
    except Exception:
        pass
    elements.append(Paragraph(
        "This report was generated by the Network Security Compliance Auditor. "
        "Findings are based on automated analysis of device configurations against "
        "the specified compliance framework. Manual review is recommended for all "
        "critical and high severity findings.",
        styles["small"],
    ))

    doc.build(
        elements,
        onFirstPage=lambda c, d: _header_footer(c, d, audit_data),
        onLaterPages=lambda c, d: _header_footer(c, d, audit_data),
    )

    pdf_bytes = buffer.getvalue()
    buffer.close()

    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes
