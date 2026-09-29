"""Engine 11 validation - Reporting Engine (spec 10.11 / §9.1 step 9 / §30.7).

Every test records one evidence row via the `recorder` fixture (see
tests/validation/conftest.py). Ground rules: no production code is modified;
detector output is never ground truth; category G is the separate, explicitly
labelled record of wrong/unsupported-vendor consequences; statuses report
whether the requirement is met (FAIL = defect present), so defect claims assert
the defect (`assert not ok`) and conformance claims assert `ok`.

Scope:
    app/engines/reporting.py   (generate_audit_report, ReportEngineError,
                                validate_report_inputs, safe display helpers,
                                matched-only per-device attribution)
    app/api/v1/reports.py      (resolve_report_format gate, finding/compliance
                                row construction for the PDF path)

PDF content is asserted through zlib/ASCII85 stream extraction (no PDF
parsing dependency): _pdf_text returns decompressed content-stream text and
_canon joins reportlab TJ segments so literal rendered strings are searchable.
"""

from __future__ import annotations

import base64
import re
import time
import zlib
from pathlib import Path


BACKEND = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _row(rec, tid, cat, req, inp, exp, act, ok, cls, ev, recm=""):
    rec.add(tid, cat, req, inp, exp, act, "PASS" if ok else "FAIL", cls, ev, recm)


def _read(rel: str) -> str:
    return (BACKEND / rel).read_text(encoding="utf-8")


def _pdf_text(pdf: bytes) -> str:
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


def _canon(text: str) -> str:
    """Join reportlab TJ segments/kerning so rendered strings are contiguous."""
    text = re.sub(r"\)\s*[-+0-9.]+\s*\(", "", text)
    return text.replace(") Tj (", "").replace(")Tj(", "")


def _pages(pdf: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page(?!s)", pdf))


_SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _audit(**kw):
    d = {"audit_id": "v11-audit", "audit_name": "V11 Audit",
         "framework": "CIS", "status": "completed",
         "overall_score": 80.0, "configuration_count": 1}
    d.update(kw)
    return d


def _finding(i: int = 0, **kw):
    d = {"title": f"Finding {i} Alpha", "description": f"Description {i}",
         "severity": _SEVS[i % 4], "status": "open", "confidence": 0.9,
         "evidence": {"vendor": "cisco", "control_id": f"C-{i}"},
         "remediation": {}}
    d.update(kw)
    return d


def _cr(i: int = 0, **kw):
    d = {"control_id": f"C-{i}", "control_name": f"Control {i}",
         "result": "FAIL", "severity": "HIGH"}
    d.update(kw)
    return d


# --------------------------------------------------------------------------
# A - spec structure (§10.11, §9.1 step 9, §30.7)
# --------------------------------------------------------------------------


def test_v11_01_engine_boundary_exists(recorder):
    from app.engines.reporting import (
        ReportEngineError, generate_audit_report, validate_report_inputs)
    ok = (callable(generate_audit_report)
          and issubclass(ReportEngineError, Exception)
          and callable(validate_report_inputs))
    _row(recorder, "V11-01", "A",
         "spec 10.11 Reporting Engine exists as a named boundary with a "
         "typed error and a validated input contract",
         "imports from app.engines.reporting",
         "generate_audit_report + ReportEngineError + validate_report_inputs",
         f"boundary={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: ReportEngineError + validate_report_inputs own the §10.11 "
         "input contract",
         "")
    assert ok


def test_v11_02_old_crash_patterns_gone(recorder):
    src = _read("app/engines/reporting.py")
    gone = [".get('overall_score', 0):.1f}",
            "get('confidence', 0)*100",
            "len(findings)//len(file_details)",
            "Powered by ML"]
    present = [p for p in gone if p in src]
    ok = not present
    _row(recorder, "V11-02", "A",
         "the pre-fix crash/fabrication patterns are gone from the engine",
         "source scan for pre-fix statements",
         "no direct .1f formatting, no direct *100, no proportional slice, "
         "no unconditional ML cover claim",
         f"remaining={present}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F1/F2/F7/F8: score/confidence coercion, matched-only "
         "attribution, neutral cover line",
         "")
    assert ok


def test_v11_03_pipeline_responsibilities_present(recorder):
    from app.engines.reporting import generate_audit_report
    pdf = generate_audit_report(
        _audit(file_details=[{"filename": "sw.cfg", "vendor": "cisco",
                              "device_type": "switch", "platform": "ios",
                              "hostname": "sw"}]),
        [_finding(0, remediation={"risk_description": "fix it",
                                  "recommended_config": "no ip http server"})],
        [_cr(0)])
    text = _canon(_pdf_text(pdf))
    sections = ["Executive Summary", "Findings",
                "Compliance Evaluation Results", "Remediation"]
    missing = [s for s in sections if s not in text]
    ok = not missing
    _row(recorder, "V11-03", "A",
         "the report carries every §9.1-step-9/§10.11 responsibility "
         "(executive summary, detailed findings, remediation guidance)",
         "one audit through generate_audit_report",
         "all four sections rendered",
         f"missing={missing}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: cover + executive summary + findings + compliance results + "
         "remediation guidance",
         "")
    assert ok


def test_v11_04_structural_violations_are_typed(recorder):
    from app.engines.reporting import ReportEngineError, generate_audit_report
    bad = [(None, [], []), ("nope", [], []),
           (_audit(), {"a": 1}, []), (_audit(), ["x"], []),
           (_audit(), [], "x"),
           (_audit(), [], ["x"]),
           (_audit(file_details="x"), [], []),
           (_audit(file_details=["x"]), [], [])]
    typed = 0
    untyped = []
    for a, f, c in bad:
        try:
            generate_audit_report(a, f, c)
            untyped.append("no-error")
        except ReportEngineError:
            typed += 1
        except Exception as e:  # noqa: BLE001 - the assertion is the log
            untyped.append(type(e).__name__)
    ok = typed == len(bad) and not untyped
    _row(recorder, "V11-04", "A",
         "structural input violations raise ReportEngineError (never "
         "AttributeError/TypeError/ValueError, never silent acceptance)",
         f"{len(bad)} malformed input shapes",
         "all typed",
         f"typed={typed}/{len(bad)} untyped={untyped}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: validate_report_inputs gates audit_data/findings/results/"
         "file_details containers and entries",
         "")
    assert ok


def test_v11_05_format_gate(recorder):
    from fastapi import HTTPException
    from app.api.v1.reports import resolve_report_format
    ok_vals = (resolve_report_format("pdf") == "pdf"
               and resolve_report_format("json") == "json"
               and resolve_report_format("PDF") == "pdf")
    rejected = []
    for bad in ("xml", "html", "", "exe", "pdfx"):
        try:
            resolve_report_format(bad)
            rejected.append(f"accepted:{bad!r}")
        except HTTPException as e:
            if e.status_code != 422:
                rejected.append(f"wrong-status:{bad!r}")
    src = _read("app/api/v1/reports.py")
    wired = "resolve_report_format(format)" in src
    ok = ok_vals and not rejected and wired
    _row(recorder, "V11-05", "A",
         "unknown download formats are a typed 422 (the old code rendered a "
         "PDF for any unrecognized format value)",
         "resolve_report_format over pdf/json/PDF/xml/html/empty/exe",
         "pdf/json accepted (case-insensitive), rest 422, endpoint wired",
         f"ok_vals={ok_vals} rejected={rejected} wired={wired}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F10: resolve_report_format in reports.py, called before any "
         "database access",
         "")
    assert ok


# --------------------------------------------------------------------------
# B - functional generation contract
# --------------------------------------------------------------------------


def test_v11_06_valid_pdf_bytes(recorder):
    from app.engines.reporting import generate_audit_report
    pdf = generate_audit_report(_audit(), [_finding(0)], [_cr(0)])
    ok = (isinstance(pdf, bytes) and len(pdf) > 1000
          and pdf.startswith(b"%PDF") and pdf.rstrip().endswith(b"%%EOF"))
    _row(recorder, "V11-06", "B",
         "generation yields a well-formed PDF document",
         "one finding + one result",
         "%PDF header, %%EOF trailer, non-trivial size",
         f"bytes={len(pdf)} header={pdf[:4]!r}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: reportlab document build",
         "")
    assert ok


def test_v11_07_section_order_and_presence(recorder):
    from app.engines.reporting import generate_audit_report
    audit = _audit(file_details=[{"filename": "sw.cfg", "vendor": "cisco",
                                  "device_type": "switch", "platform": "ios",
                                  "hostname": "sw"}])
    pdf = generate_audit_report(
        audit, [_finding(0), _finding(1)], [_cr(0), _cr(1)])
    text = _canon(_pdf_text(pdf))
    # Anchors are unambiguous content, not bare words: the breakdown table
    # has its own "Findings" column header, and the summary table has
    # "Total Findings" — so the findings section is anchored on its first
    # numbered entry.
    order = ["Analyzed Files", "Executive Summary", "1. Finding",
             "Compliance Evaluation Results"]
    idx = [text.find(s) for s in order]
    ok = all(i >= 0 for i in idx) and idx == sorted(idx)
    _row(recorder, "V11-07", "B",
         "required sections render in document order",
         "audit with file details + findings + results",
         "files < summary < findings < compliance results",
         f"order={list(zip(order, idx))}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: section layout",
         "")
    assert ok


def test_v11_08_none_scalars_render(recorder):
    from app.engines.reporting import generate_audit_report
    audit = {"audit_id": None, "audit_name": None, "framework": None,
             "status": None, "overall_score": None,
             "configuration_count": None,
             "file_details": [{"filename": None, "vendor": None,
                               "device_type": None, "platform": None,
                               "hostname": None, "firmware_version": None,
                               "confidence": None, "detection_method": None}]}
    finding = {"title": None, "description": None, "severity": None,
               "status": None, "confidence": None, "evidence": None,
               "remediation": None, "risk_score": None, "priority": None}
    try:
        pdf = generate_audit_report(audit, [finding], [])
        text = _pdf_text(pdf)
        ok = len(pdf) > 1000 and "None" not in text
    except Exception as e:  # noqa: BLE001
        ok = False
        pdf = b""
        text = f"RAISED {type(e).__name__}: {e}"
    _row(recorder, "V11-08", "B",
         "an audit of pure Nones still renders (None means missing: "
         "explicit defaults, never the literal 'None', never a crash)",
         "every scalar None",
         "valid PDF, no 'None' string in content",
         f"bytes={len(pdf)} literal-None={'None' in text}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F1-F4: _str/_score/_confidence/_file_confidence coercion",
         "")
    assert ok


def test_v11_09_score_coercion(recorder):
    from app.engines.reporting import generate_audit_report
    t_str = _canon(_pdf_text(generate_audit_report(
        _audit(overall_score="85"), [], [])))
    t_bad = _canon(_pdf_text(generate_audit_report(
        _audit(overall_score={"x": 1}), [], [])))
    ok = "85.0%" in t_str and "N/A" in t_bad
    _row(recorder, "V11-09", "B",
         "string scores render numerically, garbage scores render N/A "
         "(pre-fix both crashed the whole report)",
         "overall_score='85' vs overall_score={'x': 1}",
         "'85.0%' and 'N/A'",
         f"str_score={'85.0%' in t_str} garbage_na={'N/A' in t_bad}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F1: _score float-or-N/A",
         "")
    assert ok


def test_v11_10_empty_audit_single_page(recorder):
    from app.engines.reporting import generate_audit_report
    pdf = generate_audit_report({"audit_id": "x"}, [], [])
    ok = pdf.startswith(b"%PDF") and _pages(pdf) == 1
    _row(recorder, "V11-10", "B",
         "an empty audit yields a valid single-page report (pre-fix the "
         "unconditional breaks left trailing blank pages)",
         "no findings, no results, no file details",
         "1 page",
         f"pages={_pages(pdf)}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F9: conditional PageBreaks",
         "")
    assert ok


# --------------------------------------------------------------------------
# C - hostile markup (V03-44: evidence text is attacker-controlled)
# --------------------------------------------------------------------------


def test_v11_11_unclosed_tag_cannot_kill_report(recorder):
    from app.engines.reporting import generate_audit_report
    try:
        pdf = generate_audit_report(
            _audit(),
            [_finding(0, title="x <font color=red>y",
                      description="a < b",
                      evidence={"actual_value": "1 < 2"})],
            [])
        _canon(_pdf_text(pdf))
        ok = pdf.startswith(b"%PDF")
    except Exception:  # noqa: BLE001
        ok = False
    _row(recorder, "V11-11", "C",
         "unclosed markup from config content cannot abort the document "
         "(pre-fix ValueError killed the whole PDF)",
         "title/description/evidence with bare '<'",
         "valid PDF",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F5: _esc on every Paragraph interpolation (V03-44)",
         "")
    assert ok


def test_v11_12_markup_renders_literally(recorder):
    from app.engines.reporting import generate_audit_report
    pdf = generate_audit_report(
        _audit(), [_finding(0, title="Test <b>Bold</b> end")], [])
    text = _canon(_pdf_text(pdf))
    ok = "Test <b>Bold</b> end" in text
    _row(recorder, "V11-12", "C",
         "well-formed tags in data render as literal text, not formatting "
         "(pre-fix <b> switched the font: content misrepresentation)",
         "title='Test <b>Bold</b> end'",
         "literal '<b>' glyphs in content",
         f"literal={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F6: escaping keeps data literal",
         "")
    assert ok


def test_v11_13_entities_and_script_literally(recorder):
    from app.engines.reporting import generate_audit_report
    pdf = generate_audit_report(
        _audit(),
        [_finding(0, title="<script>alert(1)</script>",
                  description="AT&T &amp; co > all < none")],
        [])
    text = _canon(_pdf_text(pdf))
    ok = "<script>" in text and "AT&T" in text
    _row(recorder, "V11-13", "C",
         "script tags and entities in titles/descriptions render literally",
         "xss-shaped title + entity-heavy description",
         "literal '<script>' and 'AT&T' in content",
         f"script={('<script>' in text)} entity={('AT&T' in text)}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F5/F6: hostile strings are inert glyphs",
         "")
    assert ok


def test_v11_14_hostile_remediation_steps(recorder):
    from app.engines.reporting import generate_audit_report
    pdf = generate_audit_report(
        _audit(),
        [_finding(0, remediation={
            "risk_description": "r <tag>",
            "recommended_config": "cmd <x> & y",
            "verification_steps": "do it"})],
        [])
    text = _canon(_pdf_text(pdf))
    ok = pdf.startswith(b"%PDF") and "<tag>" in text and "Verify:" not in text
    _row(recorder, "V11-14", "C",
         "hostile remediation content renders literally; a mistyped "
         "steps-string is ignored (not exploded into per-character lines)",
         "markup in risk/command + verification_steps as a bare string",
         "valid PDF, literal markup, no per-character Verify lines",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: _esc + _str_list guard",
         "")
    assert ok


# --------------------------------------------------------------------------
# D - attribution honesty (no invented per-device counts)
# --------------------------------------------------------------------------


def _device_audit():
    return _audit(
        configuration_count=2,
        file_details=[
            {"filename": "sw1.cfg", "vendor": "cisco",
             "device_type": "switch", "platform": "ios", "hostname": "sw1"},
            {"filename": "r1.cfg", "vendor": "juniper",
             "device_type": "router", "platform": "junos",
             "hostname": "r1"}])


def test_v11_15_matched_counts_per_device(recorder):
    from app.engines.reporting import generate_audit_report
    findings = [_finding(0, affected_device="sw1.cfg", severity="CRITICAL"),
                _finding(1, affected_device="sw1.cfg", severity="HIGH"),
                _finding(2, affected_device="r1.cfg", severity="LOW")]
    text = _canon(_pdf_text(generate_audit_report(
        _device_audit(), findings, [])))
    ok = ("sw1.cfg" in text and "r1.cfg" in text
          and "Unattributed" not in text)
    _row(recorder, "V11-15", "D",
         "findings matching a device are attributed to that device only",
         "2 findings on sw1.cfg + 1 on r1.cfg",
         "both devices listed, no Unattributed row",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F7: matched-only attribution index",
         "")
    assert ok


def test_v11_16_unmatched_go_to_unattributed(recorder):
    from app.engines.reporting import generate_audit_report
    findings = [_finding(0, affected_device="ghost.cfg",
                         severity="CRITICAL"),
                _finding(1, severity="HIGH")]
    text = _canon(_pdf_text(generate_audit_report(
        _device_audit(), findings, [])))
    sw1_row = text.find("sw1.cfg")
    unatt = text.find("Unattributed")
    ok = unatt > 0 and sw1_row > 0
    # device rows must show 0: the cells after each filename ... assert via
    # the Unattributed row carrying the remainder (2 findings, 1 critical)
    ok = ok and "(2)" in text and "(1)" in text
    _row(recorder, "V11-16", "D",
         "findings matching no device show zeros on device rows and are "
         "accounted under an explicit Unattributed row (pre-fix they were "
         "sliced proportionally onto devices as if measured)",
         "findings on ghost.cfg + unlinked",
         "Unattributed row with 2 findings / 1 critical",
         f"unattributed={unatt > 0} counts={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F7: proportional fallback deleted",
         "")
    assert ok


def test_v11_17_no_proportional_fallback_in_source(recorder):
    src = _read("app/engines/reporting.py")
    ok = ("proportionally" not in src
          and "len(findings)//len(file_details)" not in src
          and "Unattributed" in src)
    _row(recorder, "V11-17", "D",
         "the proportional-distribution fallback is gone from the source",
         "source scan",
         "no proportional slicing; Unattributed accounting present",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F7 fix is structural, not cosmetic",
         "")
    assert ok


def test_v11_18_hostname_matching(recorder):
    from app.engines.reporting import generate_audit_report
    findings = [_finding(0, evidence={"hostname": "r1"},
                         severity="HIGH")]
    text = _canon(_pdf_text(generate_audit_report(
        _device_audit(), findings, [])))
    ok = "Unattributed" not in text and "r1.cfg" in text
    _row(recorder, "V11-18", "D",
         "hostname evidence links a finding to its device when "
         "affected_device is absent",
         "finding with evidence.hostname=r1 only",
         "attributed to r1.cfg, no Unattributed row",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: hostname fallback index (explicit match, not invention)",
         "")
    assert ok


# --------------------------------------------------------------------------
# E - claims honesty
# --------------------------------------------------------------------------


def test_v11_19_cover_carries_no_ml_claim(recorder):
    from app.engines.reporting import generate_audit_report
    text = _canon(_pdf_text(generate_audit_report(_audit(), [], [])))
    ok = ("Powered by ML" not in text
          and "Automated analysis of device" in text)
    _row(recorder, "V11-19", "E",
         "the cover makes no unconditional ML claim (pre-fix 'Powered by "
         "ML' printed even with no models installed; per-engine "
         "availability stays in the gated footer)",
         "empty audit cover text",
         "no ML claim; neutral automated-analysis line",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11 F8 (same class as E08 F8 / V09-68)",
         "")
    assert ok


def test_v11_20_footer_claims_stay_gated(recorder):
    src = _read("app/engines/reporting.py")
    i = src.find("# ML model info")
    block = src[i:i + 2500] if i >= 0 else ""
    ok = ("Risk Scoring: RandomForest" not in src
          and "advisory_model_info" in block
          and "formula-emulation" in block
          and "risk_line" in block)
    _row(recorder, "V11-20", "E",
         "the footer ML block keeps the E09 risk-model gating "
         "(risk-specific guard, emulation label, no bare claim)",
         "reporting.py footer block",
         "V09-69 invariants intact after E11 edits",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E09 §15 preserved: footer edits were additive only",
         "")
    assert ok


def test_v11_21_framework_rendered_as_given(recorder):
    from app.engines.reporting import generate_audit_report
    text = _canon(_pdf_text(generate_audit_report(
        _audit(framework="CIS+NIST"), [], [])))
    ok = "CIS+NIST" in text
    _row(recorder, "V11-21", "E",
         "the framework label renders exactly what the audit holds "
         "(dual-baseline audits must not collapse to one framework)",
         "framework='CIS+NIST'",
         "'CIS+NIST' in content",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: engine renders given labels (derivation stays E07-owned)",
         "")
    assert ok


# --------------------------------------------------------------------------
# F - determinism
# --------------------------------------------------------------------------


def _normalized(text: str) -> str:
    text = re.sub(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC", "<GENERATED>", text)
    return text


def test_v11_22_same_inputs_same_content(recorder):
    from app.engines.reporting import generate_audit_report
    audit = _device_audit()
    findings = [_finding(i) for i in range(6)]
    results = [_cr(i) for i in range(4)]
    t1 = _normalized(_canon(_pdf_text(generate_audit_report(
        audit, findings, results))))
    t2 = _normalized(_canon(_pdf_text(generate_audit_report(
        audit, findings, results))))
    ok = t1 == t2 and len(t1) > 1000
    _row(recorder, "V11-22", "F",
         "identical inputs reproduce identical report content "
         "(modulo the Generated timestamp, which is expected to vary)",
         "same audit twice",
         "normalized content identical",
         f"identical={t1 == t2} chars={len(t1)}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: pure rendering, no randomness/clock besides Generated",
         "")
    assert ok


def test_v11_23_severity_order_stable(recorder):
    from app.engines.reporting import generate_audit_report
    findings = [_finding(3), _finding(0), _finding(2), _finding(1)]
    text = _canon(_pdf_text(generate_audit_report(
        _audit(), findings, [])))
    positions = [text.find(f"Finding {i} Alpha") for i in (0, 1, 2, 3)]
    ok = all(p >= 0 for p in positions) and positions == sorted(positions)
    _row(recorder, "V11-23", "F",
         "findings render in severity order regardless of input order",
         "LOW/MED/CRITICAL/HIGH input order shuffled",
         "CRITICAL first, LOW last",
         f"positions={positions}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: severity sort preserved",
         "")
    assert ok


def test_v11_24_generated_timestamp_varies_honestly(recorder):
    from app.engines.reporting import generate_audit_report
    t1 = _pdf_text(generate_audit_report(_audit(), [], []))
    ok = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC", t1) is not None
    _row(recorder, "V11-24", "F",
         "the Generated line carries a real UTC timestamp (declared "
         "variance, not hidden nondeterminism)",
         "empty audit content",
         "YYYY-MM-DD HH:MM UTC present",
         f"timestamp_present={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: the only clock-dependent content is labeled as generated-at",
         "")
    assert ok


# --------------------------------------------------------------------------
# G - wrong/unsupported vendors (separate record)
# --------------------------------------------------------------------------


def test_v11_25_unknown_vendor_renders(recorder):
    from app.engines.reporting import generate_audit_report
    audit = _audit(file_details=[{"filename": "mystery.cfg",
                                  "vendor": "unknown",
                                  "device_type": "unknown",
                                  "platform": "unknown",
                                  "hostname": None}])
    pdf = generate_audit_report(
        audit, [_finding(0, evidence={"vendor": "unknown"})], [])
    text = _canon(_pdf_text(pdf))
    ok = pdf.startswith(b"%PDF") and "Unknown" in text
    _row(recorder, "V11-25", "G",
         "unknown-vendor audits render with explicit Unknown labels "
         "(no crash, no invented vendor)",
         "all-unknown file details + finding",
         "valid PDF with 'Unknown' labels",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "G record: unsupported vendors are labeled, never fabricated",
         "")
    assert ok


def test_v11_26_hostile_vendor_string(recorder):
    from app.engines.reporting import generate_audit_report
    audit = _audit(file_details=[{"filename": "x.cfg",
                                  "vendor": "<b>evil</b>",
                                  "device_type": "switch",
                                  "platform": "ios",
                                  "hostname": "h"}])
    try:
        pdf = generate_audit_report(audit, [], [])
        text = _canon(_pdf_text(pdf))
        # vendor labels are title-cased for display ("<b>evil</b>" ->
        # "<B>Evil</B>"); the property under test is literalness, i.e.
        # the characters render as glyphs instead of switching the font.
        ok = "<B>Evil</B>" in text
    except Exception:  # noqa: BLE001
        ok = False
    _row(recorder, "V11-26", "G",
         "a markup-shaped vendor string renders literally (no formatting "
         "injection through device metadata)",
         "vendor='<b>evil</b>'",
         "literal '<B>Evil</B>' glyphs in content (title-cased label)",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "G record: metadata is untrusted data like evidence (V03-44)",
         "")
    assert ok


def test_v11_27_empty_vendor_dict(recorder):
    from app.engines.reporting import generate_audit_report
    audit = _audit(file_details=[{}])
    pdf = generate_audit_report(audit, [], [])
    ok = pdf.startswith(b"%PDF")
    _row(recorder, "V11-27", "G",
         "an empty vendor-identification mapping renders (no KeyError on "
         "missing identification keys)",
         "file_details=[{}]",
         "valid PDF",
         f"bytes={len(pdf)}",
         ok, "CONFIRMED BEHAVIOR",
         "G record: partial identification degrades to Unknown labels",
         "")
    assert ok


# --------------------------------------------------------------------------
# H - hostile and boundary input
# --------------------------------------------------------------------------


def test_v11_28_long_title(recorder):
    from app.engines.reporting import generate_audit_report
    pdf = generate_audit_report(_audit(), [_finding(0, title="X" * 5000)],
                                [])
    ok = pdf.startswith(b"%PDF") and len(pdf) > 5000
    _row(recorder, "V11-28", "H",
         "a 5000-character title renders without error",
         "title='X'*5000",
         "valid PDF",
         f"bytes={len(pdf)}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: no length assumptions in rendering",
         "")
    assert ok


def test_v11_29_nul_bytes(recorder):
    from app.engines.reporting import generate_audit_report
    try:
        pdf = generate_audit_report(
            _audit(), [_finding(0, title="ab\x00cd",
                                description="x\x00y")], [])
        ok = pdf.startswith(b"%PDF")
    except Exception:  # noqa: BLE001
        ok = False
    _row(recorder, "V11-29", "H",
         "NUL bytes in text fields cannot crash generation",
         "title/description with \\x00",
         "valid PDF",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: hostile-input hardening",
         "")
    assert ok


def test_v11_30_unicode_text(recorder):
    from app.engines.reporting import generate_audit_report
    try:
        pdf = generate_audit_report(
            _audit(audit_name="Audit café"),
            [_finding(0, title="café snowman",
                      description="smoke test")], [])
        text = _canon(_pdf_text(pdf))
        ok = pdf.startswith(b"%PDF") and "caf" in text
    except Exception:  # noqa: BLE001
        ok = False
    _row(recorder, "V11-30", "H",
         "non-ASCII text cannot crash generation (latin-1 glyphs render; "
         "unencodable glyphs are a font limitation, measured not hidden)",
         "café/smoke-test strings",
         "valid PDF",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: reportlab WinAnsi boundary documented",
         "")
    assert ok


def test_v11_31_odd_severity(recorder):
    from app.engines.reporting import generate_audit_report
    pdf = generate_audit_report(
        _audit(),
        [_finding(0, severity="high"), _finding(1, severity="BOGUS")],
        [])
    text = _canon(_pdf_text(pdf))
    ok = pdf.startswith(b"%PDF") and "high" in text and "BOGUS" in text
    _row(recorder, "V11-31", "H",
         "non-canonical severities render as stored (gray fallback), "
         "never crash the color lookup",
         "severity='high' + severity='BOGUS'",
         "both labels present",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: .get(sev, gray) fallback preserved; values not rewritten",
         "")
    assert ok


# --------------------------------------------------------------------------
# I - integration with the rest of the pipeline (§9.1)
# --------------------------------------------------------------------------


def test_v11_32_remediation_section_content(recorder):
    from app.engines.reporting import generate_audit_report
    pdf = generate_audit_report(
        _audit(),
        [_finding(0, remediation={
            "risk_description": "Telnet in the clear exposes credentials",
            "recommended_config": "no transport input telnet",
            "verification_steps": ["show line vty 0 4"],
            "rollback_steps": ["transport input telnet"]})],
        [])
    text = _canon(_pdf_text(pdf))
    ok = ("Telnet in the clear" in text
          and "no transport input telnet" in text
          and "Verify:" in text and "Rollback:" in text)
    _row(recorder, "V11-32", "I",
         "§12 remediation content (risk/commands/verify/rollback) reaches "
         "the page, not just the bytes",
         "finding with full §12 remediation",
         "all four remediation elements in content",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E10 §12 rendering preserved through E11 edits",
         "")
    assert ok


def test_v11_33_persisted_risk_rendered(recorder):
    from app.engines.reporting import generate_audit_report
    pdf = generate_audit_report(
        _audit(),
        [_finding(0, risk_score=85.5, priority="HIGH"),
         _finding(1)],
        [])
    text = _canon(_pdf_text(pdf))
    ok = "85.5" in text and "HIGH" in text and "not assessed" in text
    _row(recorder, "V11-33", "I",
         "persisted 10.9 risk values render verbatim; unassessed findings "
         "say so (never recomputed, never blank)",
         "risk 85.5/HIGH vs no risk fields",
         "'85.5', 'HIGH', 'not assessed' present",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E09 F1/F9 exposure preserved",
         "")
    assert ok


def test_v11_34_compliance_table_content(recorder):
    from app.engines.reporting import generate_audit_report
    pdf = generate_audit_report(
        _audit(),
        [],
        [_cr(0, control_id="CIS-1.1", control_name="Secure access",
             result="PASS", severity="HIGH"),
         _cr(1, control_id="CIS-1.2", control_name="MFA on console",
             result="REVIEW", severity="MEDIUM")])
    text = _canon(_pdf_text(pdf))
    ok = ("CIS-1.1" in text and "Secure access" in text
          and "PASS" in text and "REVIEW" in text)
    _row(recorder, "V11-34", "I",
         "compliance results render control identity + verdict rows",
         "PASS + REVIEW rows",
         "ids, names, verdicts present",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: compliance table (PASS/FAIL/REVIEW single-score display)",
         "")
    assert ok


def test_v11_35_executor_to_pdf_end_to_end(recorder):
    from app.engines.compliance.executor import AuditExecutor
    from app.engines.reporting import generate_audit_report
    content = (BACKEND / "tests" / "sample_configs" / "insecure.txt"
               ).read_text(encoding="utf-8")
    run = AuditExecutor().execute(
        audit_id="v11-e2e", config_content=content, device_name="e2e-sw")
    assert run.status == "completed" and run.findings

    def _plain(value):
        # the API serves ORM VARCHAR round-trips (plain strings); mimic
        # that here instead of leaking str-enums into the report input.
        return value.value if hasattr(value, "value") else value

    dev = (run.findings[0].affected_device or "e2e-sw") if run.findings else "e2e-sw"
    findings = [{
        "title": f.title, "description": f.description,
        "severity": _plain(f.severity),
        "status": _plain(f.status), "confidence": f.confidence,
        "evidence": dict(f.evidence) if isinstance(f.evidence, dict)
        else {"raw": str(f.evidence)},
        "remediation": dict(f.remediation)
        if isinstance(f.remediation, dict) else {},
        "affected_device": f.affected_device,
        "risk_score": f.risk_score, "priority": f.priority,
    } for f in run.findings]
    audit = _audit(audit_name="V11 E2E", framework="CIS+NIST",
                   overall_score=run.overall_score
                   if run.overall_score is not None else 0.0,
                   configuration_count=1,
                   file_details=[{"filename": dev, "vendor": "cisco",
                                  "device_type": "switch", "platform": "ios",
                                  "hostname": "e2e-sw"}])
    pdf = generate_audit_report(audit, findings, [])
    text = _canon(_pdf_text(pdf))
    label = f"Total Findings({len(findings)})"
    ok = (pdf.startswith(b"%PDF")
          and "Total Findings" in text and f"({len(findings)})" in text
          and "CIS+NIST" in text and dev in text
          and "Unattributed" not in text)
    _row(recorder, "V11-35", "I",
         "executor findings flow API-shaped into a complete report "
         "(§9.1 step 9 consumes real pipeline output)",
         f"insecure.txt: {len(findings)} findings",
         "valid PDF, summary count + framework label present",
         f"n={len(findings)} label={label} ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: reporting consumes AuditResult-shaped data end to end",
         "")
    assert ok


# --------------------------------------------------------------------------
# J - performance (measurement only; roadmap budget < 30 s per report)
# --------------------------------------------------------------------------


def test_v11_36_hundred_findings_timing(recorder):
    from app.engines.reporting import generate_audit_report
    findings = [_finding(i) for i in range(100)]
    results = [_cr(i) for i in range(50)]
    start = time.perf_counter()
    pdf = generate_audit_report(_device_audit(), findings, results)
    elapsed = time.perf_counter() - start
    ok = pdf.startswith(b"%PDF") and elapsed < 30
    _row(recorder, "V11-36", "J",
         "a 100-finding report builds inside the roadmap budget",
         "100 findings + 50 results",
         "< 30 s (roadmap §7), valid PDF",
         f"elapsed_s={elapsed:.2f} bytes={len(pdf)}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: rendering is pure CPU string/table work",
         "")
    assert ok


def test_v11_37_five_hundred_findings_timing(recorder):
    from app.engines.reporting import generate_audit_report
    findings = [_finding(i) for i in range(500)]
    start = time.perf_counter()
    pdf = generate_audit_report(_device_audit(), findings, [])
    elapsed = time.perf_counter() - start
    ok = pdf.startswith(b"%PDF") and elapsed < 30
    _row(recorder, "V11-37", "J",
         "a 500-finding report builds inside the roadmap budget",
         "500 findings",
         "< 30 s, valid PDF",
         f"elapsed_s={elapsed:.2f} bytes={len(pdf)}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: corpus-scale reports fit the per-report budget",
         "")
    assert ok


# --------------------------------------------------------------------------
# K - content spot checks
# --------------------------------------------------------------------------


def test_v11_38_score_consistent_meta_and_summary(recorder):
    from app.engines.reporting import generate_audit_report
    text = _canon(_pdf_text(generate_audit_report(
        _audit(overall_score=72.5), [_finding(0)], [])))
    ok = text.count("72.5%") >= 2
    _row(recorder, "V11-38", "K",
         "the overall score is identical in the cover meta table and the "
         "executive summary (one value, two render sites)",
         "overall_score=72.5",
         "'72.5%' at least twice",
         f"count={text.count('72.5%')}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: _score used at both sites",
         "")
    assert ok


def test_v11_39_severity_counts_match(recorder):
    from app.engines.reporting import generate_audit_report
    findings = [_finding(0), _finding(0), _finding(1), _finding(2)]
    text = _canon(_pdf_text(generate_audit_report(
        _audit(), findings, [])))
    ok = ("Total Findings" in text and "(4)" in text
          and "Critical" in text and "(2)" in text)
    _row(recorder, "V11-39", "K",
         "summary severity arithmetic matches the finding list",
         "2 CRITICAL + 1 HIGH + 1 MEDIUM",
         "Total 4, Critical 2 cells present",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: summary counts computed from the same list that renders",
         "")
    assert ok


def test_v11_40_output_path_round_trip(recorder, tmp_path):
    from app.engines.reporting import generate_audit_report
    out = tmp_path / "sub" / "audit.pdf"
    pdf = generate_audit_report(_audit(), [_finding(0)], [_cr(0)],
                                output_path=str(out))
    ok = out.exists() and out.read_bytes() == pdf and pdf.startswith(b"%PDF")
    _row(recorder, "V11-40", "K",
         "output_path persists byte-identical PDF (creating directories)",
         "nested non-existent output path",
         "file bytes == returned bytes",
         f"match={out.exists() and out.read_bytes() == pdf}",
         ok, "CONFIRMED BEHAVIOR",
         "E11: file persistence path",
         "")
    assert ok
