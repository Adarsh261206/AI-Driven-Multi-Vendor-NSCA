from __future__ import annotations

import io
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

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
    canvas.drawString(2 * cm, A4[1] - 1.2 * cm, "Network Security Compliance Auditor — Confidential")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    canvas.drawCentredString(A4[0] / 2, 1.2 * cm, audit_data.get("audit_name", "Audit Report"))
    canvas.restoreState()


def generate_audit_report(
    audit_data: Dict[str, Any],
    findings: List[Dict[str, Any]],
    compliance_results: List[Dict[str, Any]],
    output_path: Optional[str] = None,
) -> bytes:
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
    elements.append(Paragraph("Compliance Audit Report", styles["title"]))
    elements.append(Paragraph(
        f"<b>{audit_data.get('audit_name', 'N/A')}</b>",
        styles["subtitle"],
    ))

    meta_data = [
        ["Audit ID", str(audit_data.get("audit_id", "N/A"))],
        ["Framework", audit_data.get("framework", "CIS")],
        ["Status", audit_data.get("status", "N/A")],
        ["Overall Score", f"{audit_data.get('overall_score', 0):.1f}%"],
        ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Configurations Audited", str(audit_data.get("configuration_count", 0))],
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
    elements.append(Spacer(1, 1 * cm))

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
        ["Overall Score", f"{audit_data.get('overall_score', 0):.1f}%"],
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
    elements.append(PageBreak())

    # === Findings Detail ===
    if findings:
        elements.append(Paragraph("Findings", styles["heading1"]))

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "LOW"), 4))

        for i, finding in enumerate(sorted_findings, 1):
            sev = finding.get("severity", "LOW")
            sev_color = SEVERITY_COLORS.get(sev, colors.gray)

            elements.append(Paragraph(
                f"<b>{i}. {finding.get('title', 'Untitled Finding')}</b>",
                styles["heading2"],
            ))

            info_data = [
                ["Severity", sev],
                ["Status", finding.get("status", "open")],
                ["Confidence", f"{finding.get('confidence', 0)*100:.0f}%"],
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
                elements.append(Paragraph(f"<b>Description:</b> {finding['description']}", styles["body"]))

            evidence = finding.get("evidence", {})
            if isinstance(evidence, dict):
                evidence_parts = []
                if evidence.get("vendor"):
                    evidence_parts.append(f"Vendor: {evidence['vendor']}")
                if evidence.get("platform"):
                    evidence_parts.append(f"Platform: {evidence['platform']}")
                if evidence.get("control_id"):
                    evidence_parts.append(f"Control: {evidence['control_id']}")
                if evidence.get("actual_value"):
                    evidence_parts.append(f"Actual: {evidence['actual_value']}")
                if evidence.get("expected_value"):
                    evidence_parts.append(f"Expected: {evidence['expected_value']}")
                if evidence_parts:
                    elements.append(Spacer(1, 3 * mm))
                    elements.append(Paragraph("<b>Evidence:</b>", styles["body"]))
                    for part in evidence_parts:
                        elements.append(Paragraph(f"  {part}", styles["small"]))

            remediation = finding.get("remediation", {})
            if isinstance(remediation, dict) and remediation.get("description"):
                elements.append(Spacer(1, 3 * mm))
                elements.append(Paragraph(f"<b>Remediation:</b> {remediation['description']}", styles["body"]))
                if remediation.get("command"):
                    elements.append(Paragraph(
                        f"<font face='Courier' size='8'>  {remediation['command']}</font>",
                        styles["small"],
                    ))

            elements.append(Spacer(1, 6 * mm))

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
            result_val = cr.get("result", "")
            result_color = RESULT_COLORS.get(result_val, colors.gray)
            table_data.append([
                Paragraph(cr.get("control_id", ""), styles["cell"]),
                Paragraph(cr.get("control_name", ""), styles["cell"]),
                Paragraph(f'<font color="{result_color.hexval()}">{result_val}</font>', styles["cell"]),
                Paragraph(cr.get("severity", ""), styles["cell"]),
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
    elements.append(Spacer(1, 2 * cm))
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
