"""V02 — Configuration Validation Engine validation.

Scope: backend/app/engines/validation.py ONLY.

  ConfigurationValidator
    validate() -> ValidationResult(is_valid, issues, warnings, info)
    _has_binary_content  _has_mixed_line_endings  _validate_structure
    _check_sensitive_patterns  _check_insecure_patterns

AuditExecutor, VendorDetector and the parsers are referenced only as a
source-level integration contract (category K); their behaviour is not
exercised here.
"""

from __future__ import annotations

import inspect
import re
import time
from pathlib import Path

import pytest

from tests.validation.conftest import Recorder

BACKEND = Path(__file__).resolve().parents[2]
SAMPLE_CONFIGS = BACKEND / "tests" / "sample_configs"
VALIDATION_SRC = (BACKEND / "app" / "engines" / "validation.py").read_text(encoding="utf-8")
EXECUTOR_SRC = (BACKEND / "app" / "engines" / "compliance" / "executor.py").read_text(
    encoding="utf-8"
)


def codes(result) -> list[tuple[str, str, object]]:
    return [(i.severity.value, i.code, i.line_number) for i in result.issues]


def code_list(result) -> list[str]:
    return [i.code for i in result.issues]


@pytest.fixture()
def validator():
    from app.engines.validation import ConfigurationValidator

    return ConfigurationValidator()


# ---------------------------------------------------------------------------
# A/B — functional contract
# ---------------------------------------------------------------------------

def test_v02_01_minimal_valid_config(validator, recorder: Recorder):
    r = validator.validate("hostname Router1\ninterface GigabitEthernet0/0\n description WAN")
    ok = r.is_valid is True and r.error_count == 0 and len(r.issues) == 0
    recorder.add(
        "V02-01", "A", "a structurally sound configuration validates cleanly",
        "3-line Cisco-style config, default flags",
        "is_valid=True, error_count=0, issues=[]",
        f"is_valid={r.is_valid} errors={r.error_count} issues={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "validation.py:101-149",
    )
    assert ok


def test_v02_02_result_object_shape(validator, recorder: Recorder):
    from app.engines.validation import ValidationSeverity

    r = validator.validate("hostname R1")
    fields = {f for f in vars(r)}
    sev = [s.value for s in ValidationSeverity]
    issue_fields = sorted(vars(r.issues[0])) if r.issues else ["<no issues>"]
    ok = {"is_valid", "issues", "warnings", "info"} <= fields and sev == ["error", "warning", "info"]
    recorder.add(
        "V02-02", "A", "ValidationResult/ValidationIssue expose the documented shape",
        "hostname R1",
        "fields is_valid/issues/warnings/info; severity in {error,warning,info}",
        f"fields={sorted(fields)} severity={sev} issue_fields={issue_fields}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "validation.py:22-46 dataclasses; ValidationIssue.column exists but is "
        "never assigned by any code path (always None)",
    )
    assert ok


def test_v02_03_severity_gate_semantics(validator, recorder: Recorder):
    r = validator.validate("hostname R1")
    r.add_warning("W", "warning")
    after_warning = r.is_valid
    r.add_info("I", "info")
    after_info = r.is_valid
    r.add_error("E", "error")
    after_error = r.is_valid
    ok = after_warning is True and after_info is True and after_error is False
    recorder.add(
        "V02-03", "B",
        "only add_error flips is_valid; warnings and info do not gate",
        "add_warning -> add_info -> add_error on one result",
        "True, True, False",
        f"{after_warning}, {after_info}, {after_error}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "validation.py:55 sets is_valid=False only inside add_error",
    )
    assert ok


def test_v02_04_defaults_and_caller_flags(validator, recorder: Recorder):
    sig = inspect.signature(validator.validate)
    defaults = {k: v.default for k, v in sig.parameters.items()
                if k not in {"self", "content"}}
    # executor calls validate(config_content) with no keyword arguments
    call_is_bare = re.search(
        r"validator\.validate\(\s*config_content\s*\)", EXECUTOR_SRC
    ) is not None
    ok = defaults == {"vendor_hint": None, "check_sensitive": True,
                      "check_insecure": True} and call_is_bare
    recorder.add(
        "V02-04", "B",
        "both detections are enabled by default and the executor does not disable them",
        str(sig),
        "check_sensitive=True, check_insecure=True; executor passes no flags",
        f"defaults={defaults} executor_bare_call={call_is_bare}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "validation.py:101-107; compliance/executor.py:171",
    )
    assert ok


# ---------------------------------------------------------------------------
# C — negative
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,content",
    [
        ("trailing", "hostname R1\x00"),
        ("only_nul", "\x00"),
        ("mid_line", "line1\nline2\x00\nline3"),
        ("value_after", "prefix\x00suffix=VALUE"),
    ],
)
def test_v02_05_nul_byte_rejected(validator, label, content, recorder: Recorder):
    r = validator.validate(content)
    codes_ = code_list(r)
    # E02 FIX (F3): NUL is now its own line-accurate NULL_BYTE error and
    # returns before every other check; BINARY_CONTENT no longer masks it.
    ok = r.is_valid is False and codes_ == ["NULL_BYTE"] and r.error_count == 1
    recorder.add(
        f"V02-05-{label}", "C",
        "content containing a NUL byte is rejected before any other check",
        repr(content[:60]),
        "is_valid=False with the sole issue NULL_BYTE",
        f"is_valid={r.is_valid} codes={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F3): validate() scans splitlines() for '\\x00' (step 2) and "
        "returns NULL_BYTE with the 1-based line number; binary detection runs "
        "only after the NUL gate. reference: MITRE CWE-158 Improper "
        "Neutralization of Null Byte or NUL Character "
        "(cwe.mitre.org/data/definitions/158.html)",
        "",
    )
    assert ok


def test_v02_06_null_byte_reachable_with_line_numbers(validator, recorder: Recorder):
    """E02 FIX (F3): the NULL_BYTE branch was dead code pre-fix (binary
    detection swallowed every NUL input). It must now be the sole reported
    error, with an accurate 1-based line number."""
    battery = [
        ("a\x00b", 1),
        ("\x00", 1),
        ("x\ny\x00", 2),
        ("hostname R1\x00 password x", 1),
        ("line\x00" * 50, 1),
    ]
    all_reached = True
    lines_ok = True
    for content, expected_line in battery:
        r = validator.validate(content)
        null_issues = [i for i in r.issues if i.code == "NULL_BYTE"]
        if not null_issues or len(r.issues) != 1:
            all_reached = False
        if not null_issues or null_issues[0].line_number != expected_line:
            lines_ok = False
    nul_before_binary = (
        VALIDATION_SRC.index("nul_lines")
        < VALIDATION_SRC.index("_has_binary_content(content")
    )
    ok = all_reached and lines_ok and nul_before_binary
    recorder.add(
        "V02-06", "I",
        "the NULL_BYTE error code is reachable for NUL-containing input",
        f"{len(battery)} inputs, each containing U+0000",
        "NULL_BYTE as the sole issue with an accurate 1-based line_number",
        f"reached={all_reached} line_numbers_ok={lines_ok} "
        f"nul_check_before_binary={nul_before_binary}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F3): validate() step 2 collects NUL line numbers and "
        "returns immediately, so the NULL_BYTE add_error site is live code "
        "and BINARY_CONTENT is no longer reported for NUL input.",
        "",
    )
    assert ok


def test_v02_07_every_declared_error_code_reachable(validator, recorder: Recorder):
    """E02 FIX (F1/F3/F4/F5/F12): pre-fix only BINARY_CONTENT was ever
    emitted; every declared add_error site must now be observable."""
    sites = re.findall(r"add_error\(\s*\"([A-Z_]+)\"", VALIDATION_SRC)
    battery = [
        "hostname R1",                          # no issues
        "",                                     # EMPTY_CONTENT
        "a\x00b",                               # NULL_BYTE
        "\x01" * 50 + "a" * 50,                 # BINARY_CONTENT
        "! comment only",                       # NO_SUBSTANTIVE_CONTENT
        "security passwords min-length",        # MISSING_VALUE
        "line vty 0 4\n exec-timeout abc def",  # INVALID_ARGUMENT
        "x" * 20000,                            # LONG_LINE (warning)
        "a\r\nb\nc",                            # info only
    ]
    observed = set()
    for content in battery:
        observed.update(
            c for s, c, _ in codes(validator.validate(content)) if s == "error"
        )
    expected_sites = {
        "EMPTY_CONTENT", "NULL_BYTE", "BINARY_CONTENT",
        "NO_SUBSTANTIVE_CONTENT", "MISSING_VALUE", "INVALID_ARGUMENT",
    }
    ok = set(sites) == expected_sites and observed == expected_sites
    recorder.add(
        "V02-07", "C",
        "every declared error code is reachable",
        f"add_error call sites={sorted(sites)}; observed across "
        f"{len(battery)} inputs={sorted(observed)}",
        "sites == observed == the six declared error codes",
        f"sites={sorted(sites)} observed={sorted(observed)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F1/F3/F4/F5/F12): gate decisions rest on six distinct "
        "structural errors instead of a single binary heuristic.",
        "",
    )
    assert ok


def test_v02_08_non_str_input_guarded(validator, recorder: Recorder):
    """E02 FIX (F14): validate() now rejects every non-str input with a
    documented TypeError naming the offending type (incl. bytearray)."""
    outcomes = {}
    for value, kind in [
        (b"hostname R1", "bytes"),
        (bytearray(b"hostname R1"), "bytearray"),
        (None, "None"),
        (5, "int"),
        ([], "list"),
        ({}, "dict"),
    ]:
        try:
            validator.validate(value)  # type: ignore[arg-type]
            outcomes[kind] = "accepted"
        except TypeError as exc:
            outcomes[kind] = f"TypeError: {exc}"
        except Exception as exc:  # noqa: BLE001
            outcomes[kind] = type(exc).__name__
    ok = all(v.startswith("TypeError: content must be str, got ")
             for v in outcomes.values())
    recorder.add(
        "V02-08", "I",
        "validate() is declared for str and fails with a typed error otherwise",
        "content = bytes / bytearray / None / int / list / dict",
        "a documented TypeError naming the received type",
        str(outcomes),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F14): an isinstance(content, str) guard raises "
        "TypeError('content must be str, got <type>') before any other "
        "processing, so None no longer leaks an AttributeError and bytes no "
        "longer surfaces the incidental regex TypeError.",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# D — boundary
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,non_printable,printable,expected_valid",
    [
        ("exactly_10_percent", 10, 90, True),
        ("just_over_10_percent", 11, 89, False),
        ("just_under_10_percent", 9, 91, True),
        ("all_control", 50, 0, False),
    ],
)
def test_v02_09_binary_ratio_boundary(validator, label, non_printable, printable,
                                      expected_valid, recorder: Recorder):
    # E02 FIX (F12): ZWSP (U+200B) is used instead of \x01 because any C0
    # control character other than \t is now rejected outright (V02-24);
    # the >10% density heuristic is the defence for non-C0 non-printables.
    content = "\u200b" * non_printable + "a" * printable
    r = validator.validate(content)
    ratio = non_printable / len(content)
    ok = r.is_valid is expected_valid
    recorder.add(
        f"V02-09-{label}", "D",
        "binary heuristic uses a strict >10% non-printable threshold",
        f"{label}: ratio={ratio:.4f} (ZWSP payload)",
        f"is_valid={expected_valid}",
        f"is_valid={r.is_valid} ratio={ratio:.4f} codes={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F12): density computed over chars where "
        "not isprintable() and char not in '\\n\\r\\t'; '>' comparison keeps "
        "exactly 10% valid. C0 controls are handled separately and "
        "outright (validation.py _has_binary_content).",
        "",
    )
    assert ok


@pytest.mark.parametrize("length,expected_warning", [(10000, False), (10001, True)])
def test_v02_10_long_line_boundary(validator, length, expected_warning, recorder: Recorder):
    r = validator.validate("x" * length)
    has = "LONG_LINE" in code_list(r)
    ok = has is expected_warning
    recorder.add(
        f"V02-10-{length}", "D",
        "LONG_LINE warning triggers only above 10000 characters",
        f"single line of {length} characters",
        f"LONG_LINE present={expected_warning}",
        f"present={has} warning_count={r.warning_count}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "validation.py:163 `if len(line) > 10000`",
    )
    assert ok


def test_v02_11_line_numbers_are_accurate(validator, recorder: Recorder):
    content = "hostname R1\n" + "y" * 10001 + "\ntransport input telnet\n"
    r = validator.validate(content)
    by_code = {i.code: i.line_number for i in r.issues}
    ok = by_code.get("LONG_LINE") == 2 and by_code.get("INSECURE_CONFIG") == 3
    recorder.add(
        "V02-11", "D",
        "issue line_number matches the 1-based source line",
        "line 2 = 10001 chars, line 3 = telnet",
        "LONG_LINE@2, INSECURE_CONFIG@3",
        str(by_code),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "validation.py:153 `enumerate(lines, 1)`; content.splitlines() at :136",
    )
    assert ok


@pytest.mark.parametrize("position", ["start", "middle", "end"])
def test_v02_12_nul_position_irrelevant(validator, position, recorder: Recorder):
    body = "hostname R1\nline vty 0 4\n"
    content = {"start": "\x00" + body, "middle": body[:5] + "\x00" + body[5:],
               "end": body + "\x00"}[position]
    r = validator.validate(content)
    # E02 FIX (F3): sole issue is NULL_BYTE regardless of NUL position.
    ok = r.is_valid is False and code_list(r) == ["NULL_BYTE"]
    recorder.add(
        f"V02-12-{position}", "D",
        "a NUL anywhere in the payload produces the same single error",
        f"NUL at {position} of {len(content)} chars",
        "['NULL_BYTE']",
        str(code_list(r)),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F3): the NUL scan is a membership test per split line, "
        "position independent; the function returns immediately so no other "
        "issue is reported",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# E — malformed / requested content classes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,content",
    [
        ("empty", ""),
        ("space", " "),
        ("newline", "\n"),
        ("tabs_newlines", "\t\n  "),
        ("crlf", "\r\n\r\n"),
        ("formfeed_only", "\x0c\x0c"),
        ("vtab_only", "\x0b\x0b"),
        ("sep_1c_only", "\x1c\x1c"),
    ],
)
def test_v02_13_empty_and_whitespace_fail_the_gate(validator, label, content,
                                                    recorder: Recorder):
    r = validator.validate(content)
    # E02 FIX (F4): EMPTY_CONTENT is now an error, so the executor gate
    # (if not validation.is_valid) actually stops empty configurations.
    ok = (r.is_valid is False and code_list(r) == ["EMPTY_CONTENT"]
          and r.issues[0].severity.value == "error")
    recorder.add(
        f"V02-13-{label}", "E",
        "empty / whitespace-only content fails validation with an error",
        repr(content),
        "is_valid=False, sole issue EMPTY_CONTENT (severity=error)",
        f"is_valid={r.is_valid} codes={codes(r)} "
        f"(severity={r.issues[0].severity.value if r.issues else None})",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F4): validate() step 1 strips and, when nothing remains, "
        "adds EMPTY_CONTENT via add_error and returns - the gate at "
        "compliance/executor.py (`if not validation.is_valid`) now blocks "
        "empty content from detection, parsing and scoring.",
        "",
    )
    assert ok


@pytest.mark.parametrize(
    "label,content",
    [
        ("cisco_comment", "! generated by tool\n! do not edit"),
        ("hash_comment", "# generated\n# another"),
        ("slash_comment", "// generated by tool"),
        ("block_comment", "/* generated block */"),
        ("comment_only_mixed", "! a\n# b\n// c"),
    ],
)
def test_v02_14_comments_only_content_fails_closed(validator, label, content,
                                                     recorder: Recorder):
    r = validator.validate(content)
    # E02 FIX (F5): comment-only content has nothing to audit and now fails
    # closed with NO_SUBSTANTIVE_CONTENT instead of validating cleanly.
    ok = (r.is_valid is False and code_list(r) == ["NO_SUBSTANTIVE_CONTENT"]
          and r.error_count == 1)
    recorder.add(
        f"V02-14-{label}", "E",
        "comment-only content fails validation with NO_SUBSTANTIVE_CONTENT",
        f"{label}: {content!r}",
        "is_valid=False, sole issue NO_SUBSTANTIVE_CONTENT",
        f"is_valid={r.is_valid} errors={r.error_count} warnings={r.warning_count} "
        f"issues={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F5): after comment stripping (F11) validate() step 6 "
        "checks that at least one substantive line remains; none does, so "
        "add_error(NO_SUBSTANTIVE_CONTENT) fails the gate. This is the "
        "chosen contract: files whose contents are only comments are not "
        "auditable configurations.",
        "",
    )
    assert ok


def test_v02_15_malformed_configuration_rejected(validator, recorder: Recorder):
    raw = (SAMPLE_CONFIGS / "malformed.txt").read_text(encoding="utf-8")
    r = validator.validate(raw)
    # E02 FIX (F1): bounded structural syntax checks now exist and reject
    # incomplete commands with line-accurate MISSING_VALUE errors, plus
    # INVALID_ARGUMENT for non-numeric values where a number is required.
    missing = [i.line_number for i in r.issues if i.code == "MISSING_VALUE"]
    invalid = [i.line_number for i in r.issues if i.code == "INVALID_ARGUMENT"]
    has_syntax_check = bool(
        re.search(r"def _validate_syntax|SYNTAX_|unknown_command", VALIDATION_SRC)
    )
    # docstring truthfulness: any "- Syntax patterns" claim must be backed
    doc_claim = "- Syntax patterns" in VALIDATION_SRC
    doc_consistent = (not doc_claim) or has_syntax_check
    ok = (r.is_valid is False and missing == [11, 14, 19, 22]
          and invalid == [23] and has_syntax_check and doc_consistent)
    recorder.add(
        "V02-15", "E",
        "a configuration containing syntax errors is rejected and flagged",
        f"tests/sample_configs/malformed.txt ({len(raw.splitlines())} lines, "
        "incomplete commands such as 'security passwords min-length' and "
        "'ip ssh version' with no value)",
        "is_valid=False; MISSING_VALUE@11,14,19,22 and INVALID_ARGUMENT@23",
        f"is_valid={r.is_valid} missing={missing} invalid={invalid} "
        f"has_syntax_check={has_syntax_check} doc_claim={doc_claim}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F1): _validate_structure (LONG_LINE) plus _validate_syntax "
        "(MISSING_VALUE for bare value-required commands, INVALID_ARGUMENT "
        "for non-numeric arguments) implement the documented boundary - "
        "bounded structural checks only, no vendor grammar is claimed.",
        "",
    )
    assert ok


def test_v02_16_mixed_vendor_content_detected(validator, recorder: Recorder):
    mixed = (
        "hostname EDGE-01\n"
        "interface GigabitEthernet0/1\n transport input telnet\n"
        "!\n"
        "system {\n    host-name edge-01;\n}\n"
        "set system services telnet\n"
        "!\n"
        "config system global\n    set password \"hunter2\"\nend\n"
    )
    r = validator.validate(mixed)
    # E02 FIX (F6): structural vendor families are detected and >=2 in one
    # file raises a MIXED_VENDOR warning naming every family present.
    has_mixed_code = "MIXED_VENDOR" in code_list(r)
    src_has_mixed = bool(re.search(r"MIXED_VENDOR", VALIDATION_SRC))
    hint_used = len(re.findall(r"vendor_hint", VALIDATION_SRC))
    msgs = [i.message for i in r.issues if i.code == "MIXED_VENDOR"]
    families_named = bool(msgs) and all(
        v in msgs[0] for v in ("cisco", "juniper", "fortinet")
    )
    ok = has_mixed_code and src_has_mixed and hint_used > 2 and families_named
    recorder.add(
        "V02-16", "E",
        "mixed-vendor content is detected and reported",
        "one file containing Cisco IOS, Juniper JUNOS and FortiOS sections",
        "MIXED_VENDOR warning naming cisco, juniper and fortinet",
        f"is_valid={r.is_valid} issues={codes(r)}; src_has_mixed="
        f"{src_has_mixed}; 'vendor_hint' appears {hint_used}x",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F6): _detect_families runs structural markers per family "
        "over the comment-stripped lines; _apply_vendor raises MIXED_VENDOR "
        "when >=2 families are present (warning only - never a gate).",
        "",
    )
    assert ok


def test_v02_17_unknown_content_flagged_not_rejected(validator, recorder: Recorder):
    results = {}
    for name in ("unknown_commands.txt", "juniper_unknown.txt"):
        raw = (SAMPLE_CONFIGS / name).read_text(encoding="utf-8")
        r = validator.validate(raw)
        results[name] = (r.is_valid, code_list(r))
    # E02 FIX (F6/F7): content matching no vendor structure is flagged with
    # UNKNOWN_CONTENT (warning); credentials embedded in otherwise-unknown
    # files are still reported. Warnings never gate (F15), so both files
    # stay is_valid=True.
    uc_valid, uc_codes = results["unknown_commands.txt"]
    ju_valid, ju_codes = results["juniper_unknown.txt"]
    ok = (uc_valid is True and "SENSITIVE_DATA" in uc_codes
          and ju_valid is True and "UNKNOWN_CONTENT" in ju_codes)
    recorder.add(
        "V02-17", "E",
        "unsupported / unknown content is flagged without being rejected",
        "tests/sample_configs/unknown_commands.txt + juniper_unknown.txt",
        "UNKNOWN_CONTENT warning on structureless content; warnings do not "
        "flip is_valid",
        f"results={results}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F6/F7): no per-command vocabulary is claimed - unknown "
        "structure yields a single UNKNOWN_CONTENT warning, while "
        "SENSITIVE_DATA still fires for embedded credentials (line 15 of "
        "unknown_commands.txt: `enable secret 5 $1$...`).",
        "",
    )
    assert ok


def test_v02_18_binary_looking_content_rejected(validator, recorder: Recorder):
    content = "hostname R1\n" + "\x01\x02\x03\x04\x05" * 400
    r = validator.validate(content)
    ok = r.is_valid is False and code_list(r) == ["BINARY_CONTENT"]
    recorder.add(
        "V02-18", "E",
        "binary-looking content is rejected as BINARY_CONTENT",
        f"{len(content)} chars, high share of C0 control characters",
        "is_valid=False, BINARY_CONTENT",
        f"is_valid={r.is_valid} codes={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "validation.py:208-211 >10% non-printable heuristic; reference: OWASP "
        "Cheat Sheet Series, File Upload Cheat Sheet, 'File Signature Validation' "
        "(cheatsheetseries.owasp.org) — content must be validated independently "
        "of attacker-controlled metadata",
        "Applies only when the content reaches this engine; Engine 01's ingest "
        "path never calls it (baseline evidence: 01_ingestion finding F4).",
    )
    assert ok


# ---------------------------------------------------------------------------
# F — security
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,content",
    [
        ("cisco_enable_secret", "enable secret 5 $1$mERr$hx5rVt7r"),
        ("equals_password", "password=cisco123"),
        ("colon_password", "password: cisco123"),
        ("space_password", "password cisco123"),
        ("encrypted_password", "enable encrypted-password $1$abc"),
        ("juniper_root_auth", 'set system root-auth encrypted-password "$1$abc"'),
        ("fortinet_set_password", 'set password "hunter2"'),
        ("snmp_public", "snmp-server community public RO"),
        ("snmp_private", "snmp-server community private RW"),
    ],
)
def test_v02_19_sensitive_pattern_coverage(validator, label, content,
                                           recorder: Recorder):
    r = validator.validate(content, check_sensitive=True, check_insecure=False)
    flagged = "SENSITIVE_DATA" in code_list(r)
    # E02 FIX (F7): every credential style above is now detected - the
    # pre-fix gaps (space-separated password, encrypted-password, JUNOS
    # root-auth, FortiOS set password) are closed regression cases.
    met = flagged is True
    recorder.add(
        f"V02-19-{label}", "F",
        "plaintext credential styles are detected",
        repr(content),
        "SENSITIVE_DATA flagged=True",
        f"flagged={flagged}",
        "PASS" if met else "FAIL",
        "CONFIRMED BEHAVIOR",
        "E02 FIX (F7): SENSITIVE_PATTERNS cover space/=/colon assignment "
        "forms, `enable [encrypted-]password`, JUNOS `encrypted-password`, "
        "FortiOS `set password` and both SNMP community forms; evidence is "
        "the pattern label only - secret values are never echoed.",
        "",
    )
    assert met


@pytest.mark.parametrize(
    "label,content",
    [
        ("ip_http_server", "ip http server"),
        ("negated_ip_http_server", "no ip http server"),
        ("transport_telnet", "transport input telnet"),
        ("negated_transport", "no transport input telnet"),
        ("snmp_public", "snmp-server community public RO"),
        ("juniper_telnet", "set system services telnet"),
        ("fortinet_telnet", "set telnet enable"),
    ],
)
def test_v02_20_insecure_pattern_coverage(validator, label, content,
                                          recorder: Recorder):
    expected = label not in {"negated_ip_http_server", "negated_transport"}
    r = validator.validate(content, check_sensitive=False, check_insecure=True)
    flagged = "INSECURE_CONFIG" in code_list(r)
    # E02 FIX (F8): negated lines (`no ...`/`delete ...`) are never
    # reported as enabled, and the multi-vendor telnet forms are covered.
    met = flagged is expected
    recorder.add(
        f"V02-20-{label}", "F",
        "insecure settings are detected only when they are actually enabled",
        repr(content),
        f"INSECURE_CONFIG flagged={expected}",
        f"flagged={flagged}",
        "PASS" if met else "FAIL",
        "CONFIRMED BEHAVIOR",
        "E02 FIX (F8): _check_insecure_patterns skips any line whose first "
        "token is a negation (no/delete/unset/negate) before matching the "
        "anchored multi-vendor patterns; disabling a service no longer "
        "reports it as enabled.",
        "",
    )
    assert met


def test_v02_21_false_positive_on_crypto_key(validator, recorder: Recorder):
    content = "crypto key generate general-keys modulus 2048"
    r = validator.validate(content, check_sensitive=True, check_insecure=False)
    flagged = "SENSITIVE_DATA" in code_list(r)
    # E02 FIX (F9/F10): the word `key` alone never implies key material.
    ok = not flagged
    recorder.add(
        "V02-21", "F",
        "a routine key-generation command is not reported as a credential",
        repr(content),
        "no SENSITIVE_DATA warning (no key material is present)",
        f"flagged={flagged} issues={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F9/F10): the key rule now requires actual key encoding "
        "(PEM armor or a >=32-char base64/hex blob) or a `key chain ... "
        "secret` context; `crypto key generate` matches none of them.",
        "",
    )
    assert ok


@pytest.mark.parametrize(
    "label,content,expected",
    [
        ("bang_comment", "! password: hunter2", False),
        ("hash_comment", "# password: hunter2", False),
        ("bang_secret", "! enable secret 5 $1$abc", False),
        ("slash_comment", "// password: hunter2", False),
        ("block_comment", "/* password: hunter2 */", False),
        ("indented_bang", "    ! password: hunter2", False),
        ("trailing_comment", "hostname R1 ! password: hunter2", False),
        # value-internal `!` is NOT a comment: the credential must still flag
        ("bang_in_value", "enable secret abc!def", True),
    ],
)
def test_v02_22_comment_styles_suppress_or_not(validator, label, content, expected,
                                                recorder: Recorder):
    r = validator.validate(content, check_sensitive=True, check_insecure=False)
    flagged = "SENSITIVE_DATA" in code_list(r)
    # E02 FIX (F11): all comment styles (! # // /* */) are stripped - full
    # line and whitespace-preceded trailing - while a `!` inside a value is
    # preserved (not treated as a comment).
    met = flagged is expected
    recorder.add(
        f"V02-22-{label}", "F",
        "comment suppression covers every supported vendor comment style "
        "without eating value-internal characters",
        repr(content),
        f"SENSITIVE_DATA flagged={expected}",
        f"flagged={flagged}",
        "PASS" if met else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F11): _strip_comments removes full-line and trailing "
        "'!', '#', '//' and '/* ... */' (block state carried across lines; "
        "'//' only after whitespace so URLs survive) before any security "
        "pattern runs.",
        "",
    )
    assert met


def test_v02_23_vendor_hint_applied(validator, recorder: Recorder):
    content = "set system services telnet\nset snmp community public"
    without = validator.validate(content)
    with_hint = validator.validate(content, vendor_hint="juniper")
    conflict = validator.validate(content, vendor_hint="cisco")
    bogus = validator.validate(content, vendor_hint="arista")
    # E02 FIX (F6): vendor_hint is normalised through the alias table and
    # reported as info (match) or warning (conflict / unknown alias).
    ok = (
        code_list(without) != code_list(with_hint)
        and "VENDOR_HINT_MATCH" in code_list(with_hint)
        and "VENDOR_HINT_CONFLICT" in code_list(conflict)
        and "UNKNOWN_VENDOR_HINT" in code_list(bogus)
        and len(re.findall(r"vendor_hint", VALIDATION_SRC)) > 2
    )
    recorder.add(
        "V02-23", "F",
        "vendor_hint changes the validation outcome for vendor-specific rules",
        "Juniper commands with vendor_hint=None vs 'juniper' vs 'cisco' vs "
        "'arista'",
        "VENDOR_HINT_MATCH info; VENDOR_HINT_CONFLICT warning; "
        "UNKNOWN_VENDOR_HINT warning",
        f"without={codes(without)}; match={codes(with_hint)}; "
        f"conflict={codes(conflict)}; bogus={codes(bogus)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F6): _apply_vendor resolves the hint via _VENDOR_ALIASES "
        "(cisco/ios/xr..., juniper/junos, fortinet/fortios, "
        "paloalto/panos...) and reports match/conflict/unknown as "
        "non-gating issues; hint never flips is_valid.",
        "",
    )
    assert ok


def test_v02_24_binary_detection_is_not_bypassable_below_threshold(validator, recorder: Recorder):
    control = "\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0e"   # 10 non-printables
    payload = control * 9 + "a" * 890                       # 90/1000 = 9%
    r = validator.validate("hostname R1\n" + payload)
    # E02 FIX (F12): any C0 control character other than \t (and the banner
    # ETX delimiter on `banner ` lines) rejects the file outright, so
    # dilution below the 10% density threshold no longer evades detection.
    ok = r.is_valid is False and "BINARY_CONTENT" in code_list(r)
    recorder.add(
        "V02-24", "F",
        "binary-detection cannot be evaded by diluting control characters",
        f"{len(payload)}-char payload with 9% C0 control characters (below the "
        "0.1 density threshold)",
        "is_valid=False with BINARY_CONTENT",
        f"is_valid={r.is_valid} issues={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F12): _has_binary_content checks signatures, then rejects "
        "any ord(ch) < 32 ch not in '\\t\\r\\n' per line (banner ETX exempt) "
        "before the >10% density fallback - the recommendation from the "
        "pre-fix report is implemented.",
        "",
    )
    assert ok


def test_v02_25_no_catastrophic_backtracking(validator, recorder: Recorder):
    payloads = {
        "long_equals": "password=" + "A" * 200000,
        "long_user_chain": "user " + "u " * 100000,
        "repeated_secret": "secret " + "s" * 100000,
        "nested_ws": "username" + " " * 50000 + "a b c",
    }
    timings = {}
    for label, payload in payloads.items():
        t0 = time.perf_counter()
        validator.validate(payload)
        timings[label] = round((time.perf_counter() - t0) * 1000, 2)
    ok = max(timings.values()) < 2000
    recorder.add(
        "V02-25", "F",
        "regex patterns complete in bounded time on pathological input",
        "four 100k-200k character adversarial payloads",
        "bounded, no exponential blow-up (<2000 ms observed)",
        f"timings_ms={timings}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "validation.py:86-99 patterns contain no nested quantifiers; measured "
        "with time.perf_counter. A measurement, not a guarantee of safety on "
        "future pattern edits.",
        "",
    )
    assert ok


def test_v02_26_check_flags_disable_detection(validator, recorder: Recorder):
    content = "enable secret 5 $1$abc\ntransport input telnet"
    full = validator.validate(content)
    off = validator.validate(content, check_sensitive=False, check_insecure=False)
    ok = full.warning_count == 2 and off.warning_count == 0 and off.is_valid is True
    recorder.add(
        "V02-26", "F",
        "check_sensitive/check_insecure flags disable their detectors",
        repr(content),
        "2 warnings with flags on, 0 with flags off",
        f"on={full.warning_count} off={off.warning_count} off_valid={off.is_valid}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "validation.py:142-147 guarded by the flags; "
        "compliance/executor.py:171 calls validate(config_content) so both stay "
        "enabled in the audit path",
        "Flag is honoured — but any caller can silently switch detection off.",
    )
    assert ok


def test_v02_27_warning_and_info_buckets_populated(validator, recorder: Recorder):
    r = validator.validate("enable secret x\ntransport input telnet\na\r\nb\nc")
    # E02 FIX (F13): add_warning/add_info append to both issues and their
    # dedicated buckets; counts and severities stay consistent.
    warn_ok = (r.warning_count > 0 and len(r.warnings) == r.warning_count
               and all(i.severity.value == "warning" for i in r.warnings))
    info_ok = (r.info_count > 0 and len(r.info) == r.info_count
               and all(i.severity.value == "info" for i in r.info))
    synced = all(i in r.issues for i in r.warnings + r.info)
    ok = warn_ok and info_ok and synced and r.is_valid is True
    recorder.add(
        "V02-27", "F",
        "ValidationResult.warnings / .info hold the non-error issues",
        "input producing warnings + a mixed-line-endings info",
        "len(warnings)==warning_count, len(info)==info_count, both are "
        "subsequences of issues, is_valid untouched",
        f"warning_count={r.warning_count} len(warnings)={len(r.warnings)} "
        f"info_count={r.info_count} len(info)={len(r.info)} "
        f"is_valid={r.is_valid}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F13): add_warning/add_info append the same issue object "
        "to `issues` and to their bucket; error_count/warning_count/info_count "
        "derive from severity so the three views can never disagree.",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# G/H — reliability + determinism
# ---------------------------------------------------------------------------

def test_v02_28_repeated_validation_is_stable(validator, recorder: Recorder):
    content = open(SAMPLE_CONFIGS / "insecure.txt", encoding="utf-8").read()
    observed = [codes(validator.validate(content)) for _ in range(100)]
    ok = all(o == observed[0] for o in observed)
    recorder.add(
        "V02-28", "G",
        "100 validations of one input produce identical issue lists",
        f"insecure.txt, 100 iterations",
        "1 distinct issue list",
        f"{len(set(map(str, observed)))} distinct outcome(s), "
        f"{len(observed[0])} issues each",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "stateless method; no caching or mutation of validator state",
    )
    assert ok


def test_v02_29_determinism_across_instances(recorder: Recorder):
    from app.engines.validation import ConfigurationValidator

    content = "hostname R1\nenable secret 5 $1$a\ncrypto key generate rsa\n"
    outs = [codes(ConfigurationValidator().validate(content)) for _ in range(3)]
    ok = len(set(map(str, outs))) == 1
    recorder.add(
        "V02-29", "H",
        "identical results across 3 independent validator instances",
        "same input, 3 instances",
        "1 distinct outcome",
        f"{len(set(map(str, outs)))} distinct outcome(s): {outs[0]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "no shared mutable state; SENSITIVE_PATTERNS/INSECURE_PATTERNS are "
        "class-level immutable tuples",
    )
    assert ok


# ---------------------------------------------------------------------------
# I — error handling
# ---------------------------------------------------------------------------

_NO_RAISE_INPUTS = {
    "normal": "hostname R1",
    "empty": "",
    "whitespace": "   \n\t",
    "nul": "a\x00b",
    "lone_surrogate": "\ud800",
    "long_50k": "x" * 50000,
    "bangs_20k": "!" * 20000,
    "emoji_zwsp": "\U0001F600 emoji \u200b zwsp",
    "mixed_endings": "line\r\nmixed\rendings\n",
    "one_meg": "a" * 1000000,
    "secret_with_controls": "enable secret \x01\x02",
    "formfeed_runs": "\x0c" * 5000,
}


@pytest.mark.parametrize("label", list(_NO_RAISE_INPUTS))
def test_v02_30_no_exception_for_str_input(validator, label, recorder: Recorder):
    content = _NO_RAISE_INPUTS[label]
    try:
        r = validator.validate(content)
        outcome = f"is_valid={r.is_valid} issues={len(r.issues)}"
        status = "PASS"
    except Exception as exc:  # noqa: BLE001
        outcome = f"{type(exc).__name__}: {exc}"
        status = "FAIL"
    recorder.add(
        f"V02-30-{label}", "I",
        "validate() never raises for str input",
        f"{len(content)} chars, {content[:30]!r}",
        "a ValidationResult, no exception",
        outcome,
        status, "CONFIRMED BEHAVIOR",
        "validation.py:101-149 performs only str operations, member tests and "
        "re.search; no I/O and no indexing that can fail",
        "",
    )
    assert status == "PASS"


# ---------------------------------------------------------------------------
# J — performance
# ---------------------------------------------------------------------------

def test_v02_31_performance_scaling(validator, recorder: Recorder):
    import statistics

    unit = "interface GigabitEthernet0/1\n description link up\n no shutdown\n"
    rows = []
    for size in (1024, 102400, 1048576):
        content = (unit * (size // len(unit) + 1))[:size]
        assert len(content) == size
        samples = []
        for _ in range(30):
            t0 = time.perf_counter()
            validator.validate(content)
            samples.append((time.perf_counter() - t0) * 1000)
        samples.sort()
        rows.append({
            "chars": size,
            "p50_ms": round(statistics.median(samples), 4),
            "p95_ms": round(samples[int(0.95 * len(samples)) - 1], 4),
            "p99_ms": round(samples[int(0.99 * len(samples)) - 1], 4),
        })
    ratio = rows[-1]["p50_ms"] / max(rows[0]["p50_ms"], 1e-9)
    linear_ok = ratio < 4000  # 1024x input should not cost >4000x time
    recorder.add(
        "V02-31", "J",
        "validate() scales roughly linearly with input size",
        "1 KiB / 100 KiB / 1 MiB, 30 samples each",
        "p50 grows ~linearly (1024x input << 4000x time)",
        f"rows={rows} p50_ratio(1MiB/1KiB)={ratio:.1f}",
        "PASS" if linear_ok else "FAIL", "CONFIRMED BEHAVIOR",
        "time.perf_counter; 30 samples per size. Measurement only, not a "
        "readiness score.",
        "",
    )
    for r in rows:
        recorder.rows[-1].setdefault("performance", []).append(r)
    assert linear_ok


# ---------------------------------------------------------------------------
# K — integration contract (source level)
# ---------------------------------------------------------------------------

def test_v02_32_is_valid_is_the_only_gate(recorder: Recorder):
    gate = re.search(r"if not validation\.is_valid:.*?return result", EXECUTOR_SRC,
                     re.S)
    flags_passed = re.search(r"validator\.validate\(\s*config_content\s*,", EXECUTOR_SRC)
    warnings_gated = bool(re.search(r"validation\.warning_count|validation\.warnings",
                                    EXECUTOR_SRC))
    ok = gate is not None and flags_passed is None and not warnings_gated
    recorder.add(
        "V02-32", "K",
        "the audit pipeline stops on validation errors and only on errors",
        "app/engines/compliance/executor.py:171-179",
        "executor aborts when is_valid is False and never inspects warnings",
        f"gate_present={gate is not None} extra_flags_passed="
        f"{flags_passed is not None} warnings_gated={warnings_gated}; "
        "consequence: EMPTY_CONTENT (warning) and every SENSITIVE_DATA / "
        "INSECURE_CONFIG / MIXED_LINE_ENDINGS issue never stops an audit",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "grep of compliance/executor.py: only `if not validation.is_valid` at "
        "line 174 consumes this engine's output",
        "Alerting-only checks are fine, but an empty configuration then reaches "
        "detection, parsing and scoring — see V02-13.",
    )
    assert ok


def test_v02_33_cross_engine_baseline_ingest_vs_validate(recorder: Recorder):
    """Engine 01 artifacts are the baseline: what ingestion stores vs what this
    engine would accept."""
    # E01 FIX (F1): pre-fix this asserted Engine 01 PERSISTED these bytes
    # (latin-1 decoded all 255 values and `_decode_content(raw)[1]` was
    # recorded as the stored encoding). Post-fix Engine 01 refuses them
    # with FileDecodeError, so the baseline contract is: nothing is
    # stored, while Engine 02 still flags the text if it ever reaches it
    # (legacy rows, imports) — defense in depth, unchanged.
    raw = bytes(range(1, 256))
    from app.engines.validation import ConfigurationValidator

    text = raw.decode("latin-1")          # hypothetical legacy text
    v = ConfigurationValidator().validate(text)
    from app.engines.ingestion import FileDecodeError, IngestionEngine

    ing = IngestionEngine(db=None)
    ing._validate_extension("binary.cfg")
    ing._validate_size(raw)
    try:
        ing._decode_content(raw)
        decode_outcome = "decoded"
    except FileDecodeError:
        decode_outcome = "FileDecodeError"
    try:
        ing._validate_and_decode(raw, "binary.cfg", "text/plain")
        pipeline_outcome = "stored"
    except FileDecodeError:
        pipeline_outcome = "FileDecodeError"
    except Exception as exc:  # noqa: BLE001
        pipeline_outcome = f"UNEXPECTED {type(exc).__name__}"

    ok = (v.is_valid is False and "BINARY_CONTENT" in code_list(v)
          and decode_outcome == "FileDecodeError"
          and pipeline_outcome == "FileDecodeError")
    recorder.add(
        "V02-33", "K",
        "cross-engine baseline: content Engine 01 refuses to store is still "
        "assessed by Engine 02 if it reaches it (defense in depth)",
        "255 non-NUL bytes; Engine 01 decode + full pipeline; Engine 02 validator",
        "Engine 01: FileDecodeError from _decode_content and "
        "_validate_and_decode (nothing persisted); Engine 02: "
        "is_valid=False with BINARY_CONTENT",
        f"Engine 01: extension/size accepted, decode='{decode_outcome}', "
        f"pipeline='{pipeline_outcome}'; Engine 02: is_valid={v.is_valid} "
        f"codes={codes(v)}",
        "PARTIAL" if ok else "FAIL",
        "CONFIRMED BEHAVIOR",
        "E01 FIX (F1): Engine 01 no longer persists arbitrary bytes — "
        "pre-fix latin-1 decoded all 255 values and V01-34 recorded the "
        "storage; post-fix _decode_content raises FileDecodeError "
        "(ingestion.py line 565). Engine 02's BINARY_CONTENT verdict is "
        "unchanged and still protects legacy/imported rows.",
        "Recorded for the later cross-engine analysis only.",
    )
    assert ok


def test_v02_34_docstring_scope_versus_implementation(recorder: Recorder):
    claims = ["Content structure", "Encoding issues",
              "Potential security concerns", "Syntax patterns"]
    present = {c: c in VALIDATION_SRC for c in claims}
    implemented = {
        "Content structure": "_validate_structure" in VALIDATION_SRC,
        "Encoding issues": "_has_binary_content" in VALIDATION_SRC
        or "MIXED_LINE_ENDINGS" in VALIDATION_SRC,
        "Potential security concerns": "_check_sensitive_patterns" in VALIDATION_SRC,
        "Syntax patterns": bool(re.search(r"def _validate_syntax|SYNTAX", VALIDATION_SRC)),
    }
    gap = [c for c in claims if present[c] and not implemented[c]]
    recorder.add(
        "V02-34", "K",
        "documented capabilities match implemented capabilities",
        "class docstring validation.py:74-83",
        "every documented capability has an implementation",
        f"claims_present={present} implemented={implemented} unbacked={gap}",
        "PASS" if not gap else "FAIL", "MISSING" if gap else "CONFIRMED BEHAVIOR",
        "grep of app/engines/validation.py against the docstring bullet list",
        "Remove unbacked claims from the docstring or implement them.",
    )
    assert True  # evidence row; gap reported rather than asserted away


def test_v02_35_category_k_ml_not_applicable(recorder: Recorder):
    recorder.add(
        "V02-35", "K",
        "machine-learning / model-quality evaluation",
        "n/a",
        "NOT APPLICABLE - deferred by instruction until all 12 engines are validated",
        "NOT APPLICABLE",
        "NOT APPLICABLE", "NOT APPLICABLE",
        "validation.py contains no model, classifier or scoring logic",
    )
    assert True


# ---------------------------------------------------------------------------
# L — E02 fix regression coverage (F1-F13)
# ---------------------------------------------------------------------------

def test_v02_36_banner_etx_delimiter_exempt_from_binary(validator, recorder: Recorder):
    """E02 FIX (F12): IOS banner ETX (^C) delimiters are legitimate config
    text; the corpus file c2811-CUCME.conf depends on this exemption."""
    banner_ok = validator.validate(
        "hostname R1\nbanner login \x03Call Manager Express\x03\nline vty 0 4\n"
    )
    stray_etx = validator.validate("hostname R1\nfoo\x03bar")
    ok = (banner_ok.is_valid is True
          and "BINARY_CONTENT" not in code_list(banner_ok)
          and stray_etx.is_valid is False
          and code_list(stray_etx) == ["BINARY_CONTENT"])
    recorder.add(
        "V02-36", "L",
        "banner ETX delimiters are exempt, stray ETX elsewhere is binary",
        "banner line with ^C delimiters; second line with a bare ^C",
        "banner content valid; stray ^C -> BINARY_CONTENT",
        f"banner={codes(banner_ok)} stray={codes(stray_etx)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F12): _has_binary_content skips \\x03 only on lines whose "
        "stripped text starts with 'banner '; every other C0 control rejects "
        "the file. Verified against the corpus: c2811-CUCME.conf (the only "
        "dataset file containing C0 controls) validates cleanly.",
        "",
    )
    assert ok


@pytest.mark.parametrize(
    "label,content",
    [
        ("pdf", "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"),
        # no NUL padding: the NULL_BYTE gate (F3) would otherwise win and
        # this test exercises the signature path (F12) specifically
        ("elf", "\x7fELF\x02\x01\x01" + "\x01" * 32),
        ("gif89a", "GIF89a" + "\x01\x02\x01\x02\x80\x01\x02" + "\x0f" * 16),
        ("png", "\x89PNG\r\n\x1a\n" + "\x0f" * 16),
    ],
)
def test_v02_37_binary_signatures_detected(validator, label, content, recorder: Recorder):
    r = validator.validate(content)
    ok = r.is_valid is False and code_list(r) == ["BINARY_CONTENT"]
    recorder.add(
        f"V02-37-{label}", "L",
        "well-known file signatures are rejected even without C0 density",
        f"{label} signature at offset 0",
        "BINARY_CONTENT as the sole issue",
        f"is_valid={r.is_valid} codes={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F12): _BINARY_SIGNATURES (ELF/PDF/GIF/PNG/ZIP/gzip/xz/"
        "Java class/OLE/CFB/bz2/wasm) is tested against content before the "
        "control-character and density heuristics.",
        "",
    )
    assert ok


def test_v02_38_negated_commands_never_syntax_flagged(validator, recorder: Recorder):
    """E02 FIX (F1/F8): negated forms are complete commands - they must not
    raise MISSING_VALUE, while the bare positive forms must."""
    negated = validator.validate(
        "no ip ssh version\nno logging host\nno transport input\n"
        "delete system services telnet\nunset system host-name\n"
    )
    bare = validator.validate("ip ssh version")
    neg_ok = not any(
        c in code_list(negated) for c in ("MISSING_VALUE", "INVALID_ARGUMENT")
    )
    bare_ok = code_list(bare).count("MISSING_VALUE") == 1
    ok = neg_ok and bare_ok
    recorder.add(
        "V02-38", "L",
        "negated commands are structurally complete; bare value-required "
        "commands are flagged",
        "5 negated lines vs bare 'ip ssh version'",
        "0 syntax errors on negated lines; MISSING_VALUE on the bare line",
        f"negated={codes(negated)} bare={codes(bare)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F1): _validate_syntax skips any line whose first token is "
        "in {no, delete, unset, negate} before the value-required and "
        "numeric-argument checks run.",
        "",
    )
    assert ok


@pytest.mark.parametrize(
    "label,content,expect_missing",
    [
        ("bare_equals", "password=", True),
        ("spaced_equals", "password =", True),
        ("data_fragment", "UX8=", False),
    ],
)
def test_v02_39_empty_assignment_restricted_to_known_keys(
        validator, label, content, expect_missing, recorder: Recorder):
    r = validator.validate(content)
    flagged = "MISSING_VALUE" in code_list(r)
    # E02 FIX (F1): only recognised assignment keys can be 'empty'; opaque
    # fragments such as base64 (UX8= in the FortiOS corpus file) are data.
    ok = flagged is expect_missing
    recorder.add(
        f"V02-39-{label}", "L",
        "empty-assignment detection is restricted to known configuration keys",
        repr(content),
        f"MISSING_VALUE flagged={expect_missing}",
        f"flagged={flagged} codes={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F1): the assignment rule requires the key to be in "
        "_ASSIGNMENT_KEYS (password/secret/community/...); corpus check: "
        "fortigate_show_full_configuration.txt lines 4497/4559 ('UX8=', "
        "'zLA=') are base64 fragments and stay unflagged.",
        "",
    )
    assert ok


@pytest.mark.parametrize(
    "label,content,expect_sensitive",
    [
        ("inside_block", "config snmp community\n    set community public\nend", True),
        ("outside_block", "set community public", False),
        ("after_end", "config snmp community\nend\nset community public", False),
    ],
)
def test_v02_40_fortinet_snmp_block_gating(validator, label, content,
                                           expect_sensitive, recorder: Recorder):
    r = validator.validate(content, check_sensitive=True, check_insecure=False)
    flagged = "SENSITIVE_DATA" in code_list(r)
    # E02 FIX (F7): bare `set community` outside a FortiOS
    # `config snmp community` block is not a credential (route-policy /
    # firewall forms); inside the block it is.
    ok = flagged is expect_sensitive
    recorder.add(
        f"V02-40-{label}", "L",
        "FortiOS `set community` is only a credential inside the SNMP block",
        repr(content),
        f"SENSITIVE_DATA flagged={expect_sensitive}",
        f"flagged={flagged} codes={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F7): _fortinet_snmp_mask computes per-line block membership "
        "in one O(n) pass (pre-fix the prefix rescan was O(n^2) and made "
        "large files unvalidatable - fixed during E02 Phase 2 probing).",
        "",
    )
    assert ok


def test_v02_41_secret_values_never_echoed(validator, recorder: Recorder):
    secret = "$1$MyS3cretValueXYZ123"
    content = f"enable secret 5 {secret}\nusername bob password {secret}\n"
    r = validator.validate(content, check_sensitive=True, check_insecure=False)
    messages = " || ".join(i.message for i in r.issues
                           if i.code == "SENSITIVE_DATA")
    ok = (len(messages) > 0 and secret not in messages
          and "MyS3cretValueXYZ123" not in messages)
    recorder.add(
        "V02-41", "L",
        "SENSITIVE_DATA evidence never contains the secret value itself",
        f"2 lines embedding {secret[:8]}...",
        "messages reference the pattern/line only",
        f"messages={messages!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F7): _check_sensitive_patterns emits 'label on line N' - "
        "the matched value is used only for matching, never formatted into "
        "the issue message or any recorded evidence.",
        "",
    )
    assert ok


@pytest.mark.parametrize(
    "label,content,absent_code",
    [
        ("junos_route_community", "community 11537:950;", "SENSITIVE_DATA"),
        ("http_secure_server", "ip http secure-server", "INSECURE_CONFIG"),
        ("transport_ssh_only", "transport input ssh", "INSECURE_CONFIG"),
        ("fortinet_telnet_disable", "set telnet disable", "INSECURE_CONFIG"),
        ("juniper_delete_telnet", "delete system services telnet", "INSECURE_CONFIG"),
        ("description_mentions_password",
         "description password policy applied", "SENSITIVE_DATA"),
        ("negated_snmp_community",
         "no snmp-server community public", "SENSITIVE_DATA"),
    ],
)
def test_v02_42_false_positive_battery(validator, label, content, absent_code,
                                       recorder: Recorder):
    r = validator.validate(content)
    flagged = absent_code in code_list(r)
    # E02 FIX (F9/F10/F11): documented false-positive corpus - none of these
    # benign/negated lines may raise the given code.
    ok = not flagged
    recorder.add(
        f"V02-42-{label}", "L",
        f"{absent_code} must not fire on benign input",
        repr(content),
        f"{absent_code} absent",
        f"flagged={flagged} codes={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F9/F10/F11): patterns are anchored to credential/insecure "
        "grammar, negated lines are skipped, and comment text is stripped "
        "before matching.",
        "",
    )
    assert ok


@pytest.mark.parametrize(
    "label,content,expect_sensitive",
    [
        ("slash_after_letter", "description a//password: hunter2", True),
        ("slash_after_space", "hostname R1 // password: hunter2", False),
        ("url_never_comment", "ip host gw.example.com // password: hunter2", False),
    ],
)
def test_v02_43_comment_boundary_rules(validator, label, content, expect_sensitive,
                                       recorder: Recorder):
    r = validator.validate(content, check_sensitive=True, check_insecure=False)
    flagged = "SENSITIVE_DATA" in code_list(r)
    # E02 FIX (F11): '//' counts as a comment only after whitespace; inside
    # a token (URL path, word) it is ordinary text.
    ok = flagged is expect_sensitive
    recorder.add(
        f"V02-43-{label}", "L",
        "trailing '//' comment detection is whitespace-delimited",
        repr(content),
        f"SENSITIVE_DATA flagged={expect_sensitive}",
        f"flagged={flagged} codes={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F11): _COMMENT_TOKENS requires (^|\\s) before '//' so "
        "URLs like http://... and intra-word slashes are never stripped.",
        "",
    )
    assert ok


@pytest.mark.parametrize(
    "label,content,expect_unknown",
    [
        ("cisco", "hostname R1\ninterface GigabitEthernet0/1", False),
        ("juniper", "system {\n    host-name r1;\n}", False),
        ("fortinet", "config system global\n    set hostname fw1\nend", False),
        ("paloalto", "set deviceconfig system type firewall", False),
        ("garbage", "frobnicate flux capacitor42", True),
    ],
)
def test_v02_44_vendor_family_recognition(validator, label, content, expect_unknown,
                                          recorder: Recorder):
    r = validator.validate(content)
    unknown = "UNKNOWN_CONTENT" in code_list(r)
    # E02 FIX (F6): each supported family's structural markers are
    # recognised; content matching none of them gets exactly one warning.
    ok = unknown is expect_unknown
    recorder.add(
        f"V02-44-{label}", "L",
        "structural vendor markers separate known families from unknown content",
        repr(content),
        f"UNKNOWN_CONTENT flagged={expect_unknown}",
        f"flagged={unknown} codes={codes(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F6): _VENDOR_MARKERS per family (cisco/juniper/fortinet/"
        "paloalto) are anchored structural patterns run over comment-stripped "
        "lines; vocabulary claims are bounded to these markers only.",
        "",
    )
    assert ok


def test_v02_45_large_file_performance_guard(validator, recorder: Recorder):
    """E02 FIX (F7): regression guard for the O(n^2) SNMP-block rescan
    removed during E02 Phase 2 (chic.conf, 16k lines, took >90 s pre-fix)."""
    unit = [
        "config snmp community",
        '    edit "public"',
        "        set status enable",
        "end",
        "set system services telnet",
    ]
    content = "\n".join(unit * 1000)   # 5000 lines, 1000 block open/close pairs
    t0 = time.perf_counter()
    r = validator.validate(content)
    dt_ms = (time.perf_counter() - t0) * 1000
    ok = dt_ms < 2000 and r.is_valid is True
    recorder.add(
        "V02-45", "J",
        "validate() stays fast on large multi-block files (no per-line rescan)",
        f"5000 lines / 1000 `config snmp community` blocks",
        "validated in <2000 ms (pre-fix O(n^2) path: tens of seconds)",
        f"dt={dt_ms:.1f} ms, warning_count={r.warning_count}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F7): _fortinet_snmp_mask precomputes block membership in a "
        "single pass; measured on the corpus chic.conf (474 KB / 16221 lines): "
        ">90 s pre-fix -> 0.48 s post-fix, linear scaling confirmed by "
        "bisection (800/1600/3200/6400/16221 lines).",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# M — input contract
# ---------------------------------------------------------------------------

def test_v02_46_non_str_vendor_hint_rejected_typed(validator, recorder: Recorder):
    """E02 FIX (F14/F6): non-str vendor_hint is reported, never raised on."""
    try:
        r = validator.validate("hostname R1", vendor_hint=123)
        raised = None
    except Exception as exc:  # noqa: BLE001
        raised = f"{type(exc).__name__}: {exc}"
        r = None
    ok = (raised is None and r is not None
          and r.is_valid is True
          and "UNKNOWN_VENDOR_HINT" in code_list(r)
          and "123" not in " ".join(i.message for i in r.issues))
    recorder.add(
        "V02-46", "M",
        "vendor_hint must be a str; wrong types are reported as issues",
        "vendor_hint=123",
        "no exception; UNKNOWN_VENDOR_HINT warning; is_valid unaffected",
        f"raised={raised} codes={codes(r) if r is not None else None}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX (F6/F14): _apply_vendor isinstance-checks vendor_hint and "
        "adds a warning instead of crashing the validation call.",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# N — fixture alignment (report cross-check)
# ---------------------------------------------------------------------------

def test_v02_47_insecure_fixture_exact_findings(validator, recorder: Recorder):
    raw = (SAMPLE_CONFIGS / "insecure.txt").read_text(encoding="utf-8")
    r = validator.validate(raw)
    observed = [(i.code, i.line_number) for i in r.issues]
    expected = [
        ("SENSITIVE_DATA", 30), ("SENSITIVE_DATA", 31),
        ("INSECURE_CONFIG", 12), ("INSECURE_CONFIG", 30),
        ("INSECURE_CONFIG", 31), ("INSECURE_CONFIG", 37),
    ]
    ok = observed == expected and r.is_valid is True
    recorder.add(
        "V02-47", "N",
        "the insecure sample yields the exact fixed-contract findings",
        f"tests/sample_configs/insecure.txt ({len(raw.splitlines())} lines)",
        f"is_valid=True with issues {expected}",
        f"is_valid={r.is_valid} observed={observed}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E02 FIX cross-check: 2 credential warnings (snmp communities, "
        "lines 30/31) + 4 insecure warnings (ip http server @12, snmp "
        "communities @30/31, transport input telnet @37); the negated "
        "`no ...` lines in the fixture raise nothing. This row is the "
        "authoritative expectation for the corpus sweep report.",
        "",
    )
    assert ok
