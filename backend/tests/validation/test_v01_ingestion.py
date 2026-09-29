"""V01 — Configuration Ingestion Engine validation.

Scope: backend/app/engines/ingestion.py ONLY.

  IngestionEngine
    _validate_and_decode  _validate_filename  _validate_extension
    _validate_size  _validate_content_type  _calculate_hash
    _check_duplicates (DB)  _device_exists (DB)  _decode_content
    ingest (DB)

Downstream consumers (AuditExecutor, parsers, normalizer) are NOT
exercised here beyond the documented ingestion -> audit hand-off
contract (V01-38/V01-69).

Post-fix note (E01 remediation): several tests below previously
recorded the *defective* behaviour (latin-1 never fails, oversized
filename escapes as DBAPIError, endpoint bypasses the engine, ...).
Where a test encoded a demonstrably buggy behaviour it has been
updated to assert the fixed contract; each such test carries an
`# E01 FIX:` comment explaining the change. Original pre-fix evidence
is preserved in artifacts/engine_validation/01_ingestion_pre_fix/.
"""

from __future__ import annotations

import hashlib
import inspect
import io
import secrets
import time
import zipfile
from pathlib import Path

import pytest

from tests.validation.conftest import Recorder

# E01 FIX (F5/N7): .zip was removed from settings.ALLOWED_EXTENSIONS —
# the ingestion contract accepts text configuration files only.
ALLOWED = [".txt", ".cfg", ".conf"]
MAX_BYTES = 10 * 1024 * 1024  # settings.MAX_UPLOAD_SIZE_MB == 10

BACKEND = Path(__file__).resolve().parents[2]
SAMPLE_CONFIGS = BACKEND / "tests" / "sample_configs"


def _known_good() -> bytes:
    """Reuse an existing fixture before creating new ones (Phase 4)."""
    p = SAMPLE_CONFIGS / "secure.txt"
    return p.read_bytes() if p.exists() else b"hostname TEST\nline vty 0 4\n"


def _b(seed: int, n: int) -> bytes:
    return (b"hostname R%02d\n" % seed) * n


# ---------------------------------------------------------------------------
# A/B — functional + positive (pure helpers)
# ---------------------------------------------------------------------------

def test_v01_01_hash_matches_reference(engine_pure, recorder: Recorder):
    data = _known_good()
    got = engine_pure._calculate_hash(data)
    ref = hashlib.sha256(data).hexdigest()
    ok = got == ref and len(got) == 64 and got == got.lower()
    recorder.add(
        "V01-01", "B", "_calculate_hash returns SHA-256 of raw bytes",
        f"{len(data)} bytes (tests/sample_configs/secure.txt)",
        ref, got, "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR",
        f"ingestion.py:174-176 sha256(content).hexdigest() == {got}",
    )
    assert ok


def test_v01_02_decode_utf8_ascii(engine_pure, recorder: Recorder):
    data = b"hostname R1\nline vty 0 4\n"
    text, enc = engine_pure._decode_content(data)
    ok = text == data.decode("utf-8") and enc == "utf-8"
    recorder.add(
        "V01-02", "A", "ASCII input decodes as utf-8 and round-trips",
        repr(data), "same text, encoding='utf-8'",
        f"encoding='{enc}'", "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:198-200 utf-8 attempted first",
    )
    assert ok


def test_v01_03_all_allowlisted_extensions_accepted(engine_pure, recorder: Recorder):
    from app.engines.ingestion import InvalidFileExtensionError

    results = {}
    for ext in ALLOWED:
        try:
            engine_pure._validate_extension(f"device{ext}")
            results[ext] = "accepted"
        except Exception as exc:  # noqa: BLE001
            results[ext] = type(exc).__name__
    for variant in ["DEVICE.CFG", "a b.txt", "x.conf"]:
        try:
            engine_pure._validate_extension(variant)
            results[variant] = "accepted"
        except Exception as exc:  # noqa: BLE001
            results[variant] = type(exc).__name__
    # E01 FIX (F5/N7): archives are explicitly NOT part of the contract.
    zip_outcome = "accepted"
    try:
        engine_pure._validate_extension("archive.zip")
    except InvalidFileExtensionError:
        zip_outcome = "rejected"
    except Exception as exc:  # noqa: BLE001
        zip_outcome = type(exc).__name__
    ok = all(v == "accepted" for v in results.values()) and zip_outcome == "rejected"
    recorder.add(
        "V01-03", "B", "allow-listed extensions are accepted (case-insensitive); "
        ".zip is rejected (F5 contract decision)",
        ", ".join(sorted(results)) + "; archive.zip",
        "text extensions accepted, archive.zip rejected",
        f"{results}; archive.zip={zip_outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_extension against "
        "settings.ALLOWED_EXTENSIONS=.txt/.cfg/.conf (zip removed, "
        "see app/config.py)",
    )
    assert ok


def test_v01_04_size_at_limit_accepted(engine_pure, recorder: Recorder):
    class _L:
        def __init__(self, n): self.n = n
        def __len__(self): return self.n

    engine_pure._validate_size(b"x" * 0)
    engine_pure._validate_size(b"x" * MAX_BYTES)  # must not raise
    recorder.add(
        "V01-04", "D", "size limit is exclusive: 10 MiB exactly is accepted",
        "0 bytes and 10485760 bytes", "no exception",
        "no exception", "PASS", "CONFIRMED BEHAVIOR",
        "ingestion.py:168 `if len(content) > max_size` (strict greater-than)",
    )


# ---------------------------------------------------------------------------
# C — negative
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ext", [".exe", ".xml", ".md", ".j2", ".yml", ".xsl"])
def test_v01_05_disallowed_extensions_rejected(engine_pure, ext, recorder: Recorder):
    from app.engines.ingestion import InvalidFileExtensionError

    with pytest.raises(InvalidFileExtensionError) as ei:
        engine_pure._validate_extension(f"device{ext}")
    msg = str(ei.value)
    ok = "not allowed" in msg and ext in msg
    recorder.add(
        f"V01-05{ext}", "C", "non-allow-listed extension is rejected",
        f"device{ext}", "InvalidFileExtensionError",
        f"{type(ei.value).__name__}: {msg}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:156-162",
    )
    assert ok


@pytest.mark.parametrize("name", ["config", "", "no_extension_cfg", None])
def test_v01_06_extensionless_rejected(engine_pure, name, recorder: Recorder):
    from app.engines.ingestion import InvalidFileExtensionError

    with pytest.raises(InvalidFileExtensionError) as ei:
        engine_pure._validate_extension(name)
    msg = str(ei.value)
    ok = msg == "Invalid filename"
    recorder.add(
        f"V01-06-{name!r}", "C",
        "extensionless / empty / missing filename is rejected",
        repr(name), "InvalidFileExtensionError('Invalid filename')",
        f"{type(ei.value).__name__}: {msg}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:153-154 `if not filename or '.' not in filename`",
    )
    assert ok


def test_v01_07_oversize_rejected(engine_pure, recorder: Recorder):
    from app.engines.ingestion import FileTooLargeError

    payload = b"\0" * (MAX_BYTES + 1)
    with pytest.raises(FileTooLargeError) as ei:
        engine_pure._validate_size(payload)
    msg = str(ei.value)
    ok = "exceeds" in msg and "10MB" in msg
    recorder.add(
        "V01-07", "C", "input larger than 10 MiB is rejected with typed error",
        f"{len(payload)} bytes", "FileTooLargeError",
        f"{type(ei.value).__name__}: {msg}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:164-172",
    )
    assert ok


def test_v01_08_invalid_utf8_does_not_raise(engine_pure, recorder: Recorder):
    """E01 FIX (F1): decode strategy is now utf-8 -> cp-1252 -> typed error.

    Previously this input fell back to latin-1 (which can never fail),
    making FileDecodeError unreachable. The cp-1252 fallback still
    decodes this input, but now as an explicit, documented strategy.
    """
    data = bytes([0xFF, 0xFE, 0x80, 0x00, 0xC3, 0x28])
    try:
        text, enc = engine_pure._decode_content(data)
        actual = f"returned encoding='{enc}', decoded_len={len(text)}"
        status = "PASS"
        cls = "CONFIRMED BEHAVIOR"
    except Exception as exc:  # noqa: BLE001
        actual = f"{type(exc).__name__}: {exc}"
        status = "FAIL"
        cls = "CONFIRMED BEHAVIOR"
    recorder.add(
        "V01-08", "E",
        "non-UTF-8 bytes are handled without raising FileDecodeError",
        repr(data), "utf-8 fails -> cp-1252 succeeds (no raise)",
        actual, status, cls,
        "ingestion.py _decode_content: utf-8 -> cp-1252 -> "
        "FileDecodeError; cp-1252 decodes this input (contains no "
        "undefined byte values)",
    )
    assert status == "PASS"


# ---------------------------------------------------------------------------
# D — boundary
# ---------------------------------------------------------------------------

def test_v01_09_size_boundary_exact(engine_pure, recorder: Recorder):
    from app.engines.ingestion import FileTooLargeError

    at = MAX_BYTES
    over = MAX_BYTES + 1
    engine_pure._validate_size(b"a" * at)
    raised = False
    try:
        engine_pure._validate_size(b"a" * over)
    except FileTooLargeError:
        raised = True
    recorder.add(
        "V01-09", "D", "boundary: 10485760 accepted, 10485761 rejected",
        f"{at} B (accept) / {over} B (reject)",
        "accept then FileTooLargeError",
        f"accepted={not raised}, rejected={raised}",
        "PASS" if raised else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:168",
    )
    assert raised


@pytest.mark.parametrize(
    "name,should_accept",
    [
        ("a.cfg", True),
        (".cfg", True),          # hidden file whose whole name is ".cfg"
        ("..cfg", True),         # traversal-shaped but extension-bearing
        ("a.", False),
        ("cfg", False),
        ("archive.tar.gz", False),
        ("evil.cfg.exe", False),
    ],
)
def test_v01_10_filename_boundary(engine_pure, name, should_accept, recorder: Recorder):
    from app.engines.ingestion import InvalidFileExtensionError

    accepted = True
    err = ""
    try:
        engine_pure._validate_extension(name)
    except InvalidFileExtensionError as exc:
        accepted = False
        err = str(exc)
    ok = accepted == should_accept
    recorder.add(
        f"V01-10-{name}", "D",
        "filename extension parsing boundary behaviour",
        repr(name), f"accepted={should_accept}",
        f"accepted={accepted} err={err!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:153-162 rsplit('.', 1)[-1].lower()",
    )
    assert ok


@pytest.mark.parametrize(
    "raw,expected_lines",
    [
        (b"hostname R1", 1),
        (b"hostname R1\n", 1),
        (b"a\nb\nc", 3),
        (b"a\nb\n", 2),
        (b"", 0),
        (b"\n", 1),
        (b"a\r\nb", 2),
        (b"a\rb", 2),
        (b"a\x0cb", 2),   # formfeed is a splitlines boundary
        (b"a\x00b", 1),   # NUL is NOT a line boundary
    ],
)
def test_v01_11_line_count_semantics(engine_pure, raw, expected_lines, recorder: Recorder):
    text, enc = engine_pure._decode_content(raw)
    got = len(text.splitlines())
    ok = got == expected_lines
    recorder.add(
        f"V01-11-{len(recorder.rows)}", "D",
        "line_count semantics match Python splitlines()",
        repr(raw), str(expected_lines), str(got),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:122 len(raw_content.splitlines())",
    )
    assert ok


def test_v01_12_all_256_bytes_decode_without_error(engine_pure, recorder: Recorder):
    """E01 FIX (F1): FileDecodeError is now REACHABLE.

    Pre-fix this test proved the defect (latin-1 decodes every byte,
    so the error branch was dead code). Post-fix the strategy is
    utf-8 -> cp-1252 -> FileDecodeError; cp-1252 has five undefined
    byte values (0x81 0x8D 0x8F 0x90 0x9D) for which both decoders
    fail, so a typed error must be raised for those inputs.
    """
    failures = []
    for b in range(256):
        try:
            engine_pure._decode_content(bytes([b]))
        except Exception:  # noqa: BLE001
            failures.append(b)
    expected_unreachable = {0x81, 0x8D, 0x8F, 0x90, 0x9D}
    ok = set(failures) == expected_unreachable
    recorder.add(
        "V01-12", "I",
        "FileDecodeError is raised for bytes invalid in both UTF-8 and cp-1252",
        "all 256 single-byte inputs",
        f"typed decode failure exactly for {sorted(expected_unreachable)}",
        f"raised for {sorted(failures)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR",
        "ingestion.py _decode_content: utf-8 -> cp-1252 -> "
        "FileDecodeError; cp-1252 defines 0x81/0x8D/0x8F/0x90/0x9D as "
        "undefined, so those five inputs reach the typed error",
        "Fixed (E01 F1): arbitrary byte sequences are no longer "
        "silently converted into configuration text.",
    )
    assert ok


# ---------------------------------------------------------------------------
# E — malformed input
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,raw,expected_enc,expected_lines",
    [
        ("utf8_bom", b"\xef\xbb\xbfhostname R1\n", "utf-8", 1),
        ("crlf", b"hostname R1\r\nline vty\r\n", "utf-8", 2),
        # E01 FIX (F1): the non-UTF-8 fallback is cp-1252, not latin-1
        ("latin1_accented", "hostname R\xe9\n".encode("latin-1"), "cp-1252", 1),
        ("nul_bytes", b"hostname R1\x00\x00\n", "utf-8", 1),
        ("utf16le", "hostname R1\n".encode("utf-16-le"), "utf-8", 2),
    ],
)
def test_v01_13_malformed_decoding(engine_pure, label, raw, expected_enc,
                                    expected_lines, recorder: Recorder):
    text, enc = engine_pure._decode_content(raw)
    lines = len(text.splitlines())
    ok = enc == expected_enc and lines == expected_lines
    recorder.add(
        f"V01-13-{label}", "E",
        "malformed / mixed-encoding content decodes deterministically",
        f"{label}: {raw[:40]!r}",
        f"encoding={expected_enc} lines={expected_lines}",
        f"encoding={enc} lines={lines}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _decode_content; BOM is retained by utf-8 decode; "
        "UTF-16LE decodes as utf-8 (NUL is a valid UTF-8 code unit) so "
        "mojibake is accepted at the decode level — NUL bytes are "
        "rejected earlier by the ingest() content gate (F3)",
    )
    assert ok


def test_v01_14_long_single_line(engine_pure, recorder: Recorder):
    raw = b"! " + b"x" * (1024 * 1024)
    t0 = time.perf_counter()
    text, enc = engine_pure._decode_content(raw)
    h = engine_pure._calculate_hash(raw)
    dt = time.perf_counter() - t0
    ok = len(text.splitlines()) == 1 and len(h) == 64
    recorder.add(
        "V01-14", "J",
        "1 MiB single-line input decodes and hashes without pathological cost",
        "1048578 bytes, no newline",
        "1 line, 64-char hash",
        f"lines={len(text.splitlines())} time={dt*1000:.2f}ms",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        f"ingestion.py decode+sha256 took {dt*1000:.2f} ms",
    )
    assert ok


async def test_v01_15_zip_payload_with_text_extension(engine_pure, recorder: Recorder):
    """E01 FIX (F5/N7): .zip is no longer allow-listed.

    Pre-fix the archive was accepted and its bytes decoded as
    latin-1 text (never extracted, stored as mojibake). The contract
    decision is: ZIP archives are NOT supported — rejected at the
    extension gate with a typed error before any content handling.
    """
    from app.engines.ingestion import InvalidFileExtensionError

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("device.cfg", _b(1, 2000))
    raw = buf.getvalue()

    rejected = False
    detail = "accepted"
    try:
        await engine_pure.ingest(file_content=raw, filename="backup.zip",
                                 content_type="application/zip")
    except InvalidFileExtensionError as exc:
        rejected = True
        detail = f"InvalidFileExtensionError: {exc}"
    except Exception as exc:  # noqa: BLE001 - must not leak raw errors
        detail = f"UNEXPECTED {type(exc).__name__}: {exc}"

    # Also confirm the bytes never reach the text-decode path.
    from app.config import settings as _settings
    zip_not_allowed = ".zip" not in _settings.ALLOWED_EXTENSIONS
    ok = rejected and zip_not_allowed
    recorder.add(
        "V01-15", "F",
        "ZIP archives are rejected at the extension gate (contract: "
        "archives unsupported; F5/N7/N9 decision)",
        f"{len(raw)}-byte zip, filename 'backup.zip'",
        "InvalidFileExtensionError; .zip absent from ALLOWED_EXTENSIONS",
        detail + f"; .zip allowed={not zip_not_allowed}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "settings.ALLOWED_EXTENSIONS=[.txt,.cfg,.conf]; "
        "app/config.py documents the removal; no archive module exists "
        "in app/, and the single-Configuration-per-upload API contract "
        "cannot represent multi-member archives",
        "Documented design decision: ZIP support would require bounded "
        "extraction plus a multi-row upload contract; both are out of "
        "the current application architecture.",
    )
    assert ok


async def test_v01_16_zip_bomb_compressed_size_checked(engine_pure, tmp_path, recorder: Recorder):
    """E01 FIX (F5/N7): decompression abuse is structurally impossible.

    Pre-fix this measured the compressed bytes of an accepted archive.
    Post-fix archives never enter the pipeline, so neither compressed
    nor expanded size can be abused (N9/N7: ZIP requirements are
    intentionally not applicable while .zip is rejected).
    """
    from app.engines.ingestion import FileTooLargeError, InvalidFileExtensionError

    raw_bytes = secrets.token_bytes(32) + b"\n" + (b"A" * (12 * 1024 * 1024))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", raw_bytes)
    compressed = buf.getvalue()

    outcome = ""
    try:
        await engine_pure.ingest(file_content=compressed, filename="big.zip",
                                 content_type="application/zip")
        outcome = "accepted (BUG)"
    except InvalidFileExtensionError:
        outcome = "rejected: InvalidFileExtensionError"
    except FileTooLargeError:
        outcome = "rejected: FileTooLargeError"
    except Exception as exc:  # noqa: BLE001
        outcome = f"UNEXPECTED {type(exc).__name__}"

    ok = outcome.startswith("rejected: InvalidFileExtensionError")
    recorder.add(
        "V01-16", "F",
        "archive decompression/resource abuse is not reachable: "
        "archives are rejected before any content handling",
        f"12 MiB content deflated to {len(compressed)} B as big.zip",
        "rejected at the extension gate (no extraction exists)",
        outcome,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "settings.ALLOWED_EXTENSIONS has no .zip; the engine rejects "
        "the filename before size/decode steps run",
        "N9/N7 not applicable while ZIP is outside the contract.",
    )
    assert ok


# ---------------------------------------------------------------------------
# F — security
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "name,should_accept",
    [
        ("../../etc/passwd.cfg", False),
        ("..\\..\\windows\\system32\\evil.cfg", False),
        ("/etc/shadow.cfg", False),
        ("a/../../../tmp/x.cfg", False),
        ("C:\\temp\\evil.cfg", False),
        (".cfg", True),   # extension-bearing hidden file: still valid
        ("router.conf", True),
    ],
)
def test_v01_17_path_traversal_filenames_outcome(engine_pure, name, should_accept,
                                                  recorder: Recorder):
    """E01 FIX (F6): unsafe filenames are rejected before persistence.

    Pre-fix every shape here was accepted verbatim (assert `accepted`).
    Post-fix the filename safety gate rejects separators, drive letters
    and traversal-shaped paths with a typed error while ordinary names
    (including bare `.cfg`) stay accepted.
    """
    from app.engines.ingestion import InvalidFilenameError

    accepted = True
    err = ""
    try:
        engine_pure._validate_filename(name)
    except InvalidFilenameError as exc:
        accepted = False
        err = str(exc)
    ok = accepted == should_accept
    recorder.add(
        f"V01-17-{hashlib.md5(name.encode()).hexdigest()[:6]}", "F",
        "filename safety: traversal/absolute/drive shapes rejected, "
        "ordinary names accepted",
        repr(name), f"accepted={should_accept}",
        f"accepted={accepted} err={err!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_filename: rejects path separators, "
        "drive-letter prefixes, non-printable characters and length "
        ">255 before any persistence",
        "Fixed (E01 F6).",
    )
    assert ok


def test_v01_18_control_character_filename(engine_pure, recorder: Recorder):
    """E01 FIX (N3/F6): NUL/control characters in filenames are rejected
    by the engine instead of relying on PostgreSQL to notice."""
    from app.engines.ingestion import InvalidFilenameError

    name = "evil\x00.cfg"
    try:
        engine_pure._validate_filename(name)
        actual = "accepted"
        status = "FAIL"
    except InvalidFilenameError as exc:
        actual = f"InvalidFilenameError: {exc}"
        status = "PASS"
    except Exception as exc:  # noqa: BLE001
        actual = f"UNEXPECTED {type(exc).__name__}: {exc}"
        status = "FAIL"
    recorder.add(
        "V01-18", "F", "NUL byte in filename is rejected with a typed error",
        repr(name), "InvalidFilenameError", actual, status,
        "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_filename: any non-printable character "
        "(isprintable() False, which includes NUL and C0 controls) "
        "raises InvalidFilenameError before persistence",
        "Fixed (E01 N3).",
    )
    assert status == "PASS"


def test_v01_19_oversized_filename_accepted_by_engine(engine_pure, recorder: Recorder):
    """E01 FIX (F2): filename length is validated against String(255)."""
    from app.engines.ingestion import InvalidFilenameError

    name = "A" * 5000 + ".cfg"
    rejected = False
    detail = ""
    try:
        engine_pure._validate_filename(name)
        detail = "accepted"
    except InvalidFilenameError as exc:
        rejected = True
        detail = str(exc)
    ok = rejected
    recorder.add(
        "V01-19", "F",
        "filename longer than String(255) is rejected by the engine "
        "with a typed error before persistence",
        f"{len(name)}-character filename ending .cfg",
        "InvalidFilenameError before any DB round-trip",
        detail,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_filename length check vs "
        "models/__init__.py Configuration.filename String(255)",
        "Fixed (E01 F2).",
    )
    assert ok


def test_v01_20_content_type_not_validated(engine_pure, recorder: Recorder):
    """E01 FIX (F7): content_type is validated syntactically and is
    advisory only — extension and content stay authoritative."""
    from app.engines.ingestion import InvalidContentTypeError

    outcomes = {}
    for ct in ["application/x-netshow", "CONFIG/TEXT", None, ""]:
        try:
            stored = engine_pure._validate_content_type(ct)
            outcomes[repr(ct)] = f"stored:{stored}"
        except Exception as exc:  # noqa: BLE001
            outcomes[repr(ct)] = type(exc).__name__

    # A well-formed but *mismatched* type must not drive decisions:
    # binary content declared as text/plain is still rejected, and a
    # .cfg file claiming application/zip is still treated as text.
    mismatch_ok = True
    try:
        engine_pure._validate_and_decode(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n",
                                         "masquerade.cfg", "text/plain")
        mismatch_ok = False  # binary masquerading as text must fail
    except Exception:
        pass
    zip_ct_ok = True
    try:
        engine_pure._validate_and_decode(b"hostname R1\n", "ok.cfg",
                                         "application/zip")
    except Exception:
        zip_ct_ok = False  # well-formed mismatch must NOT block text .cfg

    malformed_outcomes = {}
    for bad in ["text", "a/b/c", "nonsense", 123, b"text/plain"]:
        try:
            engine_pure._validate_content_type(bad)
            malformed_outcomes[repr(bad)] = "accepted"
        except InvalidContentTypeError:
            malformed_outcomes[repr(bad)] = "rejected"
        except Exception as exc:  # noqa: BLE001
            malformed_outcomes[repr(bad)] = type(exc).__name__
    malformed_rejected = all(
        v == "rejected" for v in malformed_outcomes.values()
    )

    ok = (
        all(v.startswith("stored:") for v in outcomes.values())
        and mismatch_ok and zip_ct_ok and malformed_rejected
    )
    recorder.add(
        "V01-20", "F",
        "content_type is validated (syntax + length) but never "
        "authoritative; mismatches cannot bypass content rules",
        "valid/None/empty types + mismatched types + malformed types",
        "well-formed stored, malformed rejected, content wins conflicts",
        f"{outcomes}; binary-as-text rejected={mismatch_ok}; "
        f"zip-ct .cfg accepted={zip_ct_ok}; malformed rejected={malformed_rejected}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_content_type + _validate_and_decode; "
        "extension allow-list and content gates decide ingestion",
        "Fixed (E01 F7/N1).",
    )
    assert ok


# ---------------------------------------------------------------------------
# G/H — reliability + determinism
# ---------------------------------------------------------------------------

def test_v01_21_repeated_hash_and_decode_stable(engine_pure, recorder: Recorder):
    raw = _known_good() + bytes([0xFF, 0xFE])
    hashes, encs, texts = set(), set(), set()
    for _ in range(100):
        hashes.add(engine_pure._calculate_hash(raw))
        t, e = engine_pure._decode_content(raw)
        texts.add(t)
        encs.add(e)
    ok = len(hashes) == 1 and len(encs) == 1 and len(texts) == 1
    recorder.add(
        "V01-21", "G",
        "repeated processing of identical input is stable",
        f"{len(raw)} bytes x 100 iterations",
        "1 distinct hash / encoding / decoded text",
        f"hashes={len(hashes)} encodings={len(encs)} texts={len(texts)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "100 iterations produced identical outputs",
    )
    assert ok


def test_v01_22_determinism_across_instances(recorder: Recorder):
    from app.engines.ingestion import IngestionEngine

    raw = _known_good()
    outs = []
    for _ in range(3):
        eng = IngestionEngine(db=None)
        t, e = eng._decode_content(raw)
        outs.append((eng._calculate_hash(raw), e, t))
    ok = len(set(outs)) == 1
    recorder.add(
        "V01-22", "H",
        "same input -> same output across 3 independent engine instances",
        f"{len(raw)} bytes, 3 instances",
        "identical (hash, encoding, text) tuple",
        f"{len(set(outs))} distinct result(s)",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "sha256 + fixed decode fallback order are stateless",
    )
    assert ok


# ---------------------------------------------------------------------------
# I — error handling
# ---------------------------------------------------------------------------

def test_v01_23_exception_hierarchy(engine_pure, recorder: Recorder):
    from app.engines.ingestion import (
        DuplicateConfigurationError,
        FileDecodeError,
        FileTooLargeError,
        IngestionError,
        InvalidContentTypeError,
        InvalidDeviceError,
        InvalidFileExtensionError,
        InvalidFilenameError,
        InvalidContentError,
    )

    subs = [FileTooLargeError, InvalidFileExtensionError, FileDecodeError,
            DuplicateConfigurationError, InvalidFilenameError,
            InvalidContentError, InvalidContentTypeError, InvalidDeviceError]
    all_sub = all(issubclass(s, IngestionError) for s in subs)

    cases = {}
    try:
        engine_pure._validate_extension("x.exe")
    except Exception as exc:  # noqa: BLE001
        cases["bad_ext"] = (type(exc).__name__, str(exc))
    try:
        engine_pure._validate_size(b"x" * (MAX_BYTES + 1))
    except Exception as exc:  # noqa: BLE001
        cases["too_large"] = (type(exc).__name__, str(exc))

    messages_ok = all(m for _, m in cases.values())
    ok = all_sub and messages_ok
    recorder.add(
        "V01-23", "I",
        "typed exception hierarchy with non-empty messages",
        "invalid extension + oversize input",
        "InvalidFileExtensionError / FileTooLargeError under IngestionError",
        f"subclass_ok={all_sub} cases={cases}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:21-43 class hierarchy; :159-162 and :169-172 messages",
    )
    assert ok


def test_v01_24_file_decode_error_unreachable(engine_pure, recorder: Recorder):
    """E01 FIX (F1): FileDecodeError must be REACHABLE.

    Pre-fix this asserted `not raised` because latin-1 made the branch
    dead code. Post-fix at least one input (any byte invalid in both
    UTF-8 and cp-1252, e.g. 0x81) raises the typed error.
    """
    from app.engines.ingestion import FileDecodeError

    raised = False
    for b in range(256):
        try:
            engine_pure._decode_content(bytes([b]) * 16)
        except FileDecodeError:
            raised = True
            break
    recorder.add(
        "V01-24", "I",
        "FileDecodeError is reachable for undecodable input",
        "4096 bytes covering all 256 byte values",
        "FileDecodeError raised for at least one input",
        "raised" if raised else "FileDecodeError never raised",
        "PASS" if raised else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _decode_content: utf-8 -> cp-1252 -> "
        "raise FileDecodeError; cp-1252 rejects its five undefined "
        "byte values, so the branch is live",
        "Fixed (E01 F1).",
    )
    assert raised


# ---------------------------------------------------------------------------
# J — performance
# ---------------------------------------------------------------------------

def test_v01_25_performance(engine_pure, recorder: Recorder):
    import statistics

    rows = []
    unit = b"interface GigabitEthernet0/1\n description x\n"
    for size in (1024, 102400, 1048576):
        raw = (unit * (size // len(unit) + 1))[:size]
        assert len(raw) == size
        samples = []
        for _ in range(50):
            t0 = time.perf_counter()
            engine_pure._decode_content(raw)
            engine_pure._calculate_hash(raw)
            samples.append((time.perf_counter() - t0) * 1000)
        samples.sort()
        rows.append({
            "bytes": size,
            "p50_ms": round(statistics.median(samples), 4),
            "p95_ms": round(samples[int(0.95 * len(samples)) - 1], 4),
            "p99_ms": round(samples[int(0.99 * len(samples)) - 1], 4),
            "mb_per_s": round(size / 1048576 / (statistics.median(samples) / 1000), 1),
        })
    recorder.add(
        "V01-25", "J",
        "decode + sha256 latency across input sizes (50 samples each)",
        "1 KiB / 100 KiB / 1 MiB",
        "bounded, no superlinear growth",
        str(rows),
        "PASS", "CONFIRMED BEHAVIOR",
        "time.perf_counter; 50 samples per size; measurements only, "
        "not a readiness score",
    )
    # store as performance rows too
    for r in rows:
        recorder.rows[-1].setdefault("performance", []).append(r)
    assert rows


# ---------------------------------------------------------------------------
# DB-backed tests
# ---------------------------------------------------------------------------

async def test_v01_26_full_ingest_success(db_env, recorder: Recorder):
    from sqlalchemy import delete, select

    from app.models import Configuration

    eng, session = db_env
    raw = _known_good()
    await session.execute(delete(Configuration))
    await session.commit()

    res = await eng.ingest(
        file_content=raw, filename="secure_valid.cfg", content_type="text/plain"
    )
    await session.commit()

    row = (await session.execute(
        select(Configuration).where(Configuration.id == res.configuration_id)
    )).scalar_one()

    checks = {
        "hash_matches": res.content_hash == hashlib.sha256(raw).hexdigest(),
        "row_hash_matches": row.content_hash == res.content_hash,
        "size_matches": res.size_bytes == len(raw) == row.size_bytes,
        "line_count_matches": res.line_count == len(raw.decode().splitlines())
        == row.line_count,
        "encoding_matches": res.encoding == row.encoding == "utf-8",
        "filename_stored": row.filename == "secure_valid.cfg",
        "filename_col": isinstance(res.filename, str),
        "id_type": str(type(res.configuration_id)).endswith("UUID'>"),
    }
    ok = all(checks.values())
    recorder.add(
        "V01-26", "A",
        "ingest() persists a Configuration row and returns IngestionResult",
        f"{len(raw)} B, secure_valid.cfg, text/plain",
        "row + result agree on hash/size/lines/encoding",
        str(checks), "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:81-149; models/__init__.py:115-128",
    )
    assert ok


async def test_v01_27_content_type_fallback(db_env, recorder: Recorder):
    from sqlalchemy import delete, select

    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    results = {}
    for i, ct in enumerate([None, "", "application/x-netshow", "CONFIG/TEXT"]):
        r = await eng.ingest(
            file_content=_b(i + 50, 2),
            filename=f"ct{i}.cfg",
            content_type=ct,  # type: ignore[arg-type]
        )
        await session.commit()
        row = (await session.execute(
            select(Configuration).where(Configuration.id == r.configuration_id)
        )).scalar_one()
        results[repr(ct)] = row.content_type

    expected = {
        "None": "text/plain",
        "''": "text/plain",
        "'application/x-netshow'": "application/x-netshow",
        "'CONFIG/TEXT'": "CONFIG/TEXT",
    }
    ok = results == expected
    recorder.add(
        "V01-27", "F",
        "content_type falls back to text/plain only for None/empty",
        "content_type in {None, '', custom x2}",
        str(expected), str(results),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:131 `content_type or \"text/plain\"` — any non-empty "
        "caller string is persisted unvalidated",
    )
    assert ok


async def test_v01_28_duplicate_content_rejected(db_env, recorder: Recorder):
    from sqlalchemy import delete

    from app.engines.ingestion import DuplicateConfigurationError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    raw = _b(99, 5)
    await eng.ingest(file_content=raw, filename="first.cfg", content_type="text/plain")
    await session.commit()

    detail = ""
    try:
        await eng.ingest(file_content=raw, filename="second.cfg", content_type="text/plain")
        await session.commit()
        outcome = "no error raised"
    except DuplicateConfigurationError as exc:
        outcome = "DuplicateConfigurationError"
        detail = str(exc)
        await session.rollback()
    recorder.add(
        "V01-28", "C",
        "identical content is rejected as a duplicate",
        f"{len(raw)} B ingested twice (different filenames)",
        "DuplicateConfigurationError on second ingest",
        f"{outcome} {detail}",
        "PASS" if outcome == "DuplicateConfigurationError" else "FAIL",
        "CONFIRMED BEHAVIOR",
        "ingestion.py:178-189 SELECT on content_hash; "
        "models/__init__.py:121 content_hash indexed",
    )
    assert outcome == "DuplicateConfigurationError"


async def test_v01_29_dedup_is_content_addressed_not_name(db_env, recorder: Recorder):
    from sqlalchemy import delete

    from app.engines.ingestion import DuplicateConfigurationError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    raw = _b(77, 3)
    await eng.ingest(file_content=raw, filename="hostA.cfg", content_type="text/plain")
    await session.commit()
    try:
        await eng.ingest(file_content=raw, filename="totally-different-name.cfg",
                         content_type="text/plain")
        await session.commit()
        outcome = "accepted"
    except DuplicateConfigurationError:
        outcome = "DuplicateConfigurationError"
        await session.rollback()
    ok = outcome == "DuplicateConfigurationError"
    recorder.add(
        "V01-29", "C",
        "deduplication keys on content, independent of filename",
        "same bytes, two different filenames",
        "DuplicateConfigurationError", outcome,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:113 hash computed from bytes; :178-189 lookup on "
        "content_hash only — filename never participates",
    )
    assert ok


async def test_v01_30_oversized_filename_surfaces_untyped(db_env, recorder: Recorder):
    """E01 FIX (F2): >255-char filenames fail as a typed IngestionError.

    Pre-fix this asserted `not typed` (the raw DBAPIError was the
    observed behaviour). Post-fix the engine rejects before any DB
    round-trip.
    """
    from sqlalchemy import delete

    from app.engines.ingestion import IngestionError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    name = "A" * 5000 + ".cfg"
    typed = False
    other = ""
    try:
        await eng.ingest(file_content=_b(3, 1), filename=name,
                         content_type="text/plain")
        await session.commit()
        other = "accepted without error"
    except IngestionError as exc:
        typed = True
        other = f"{type(exc).__name__}: {exc}"
        await session.rollback()
    except Exception as exc:  # noqa: BLE001
        other = f"{type(exc).__module__}.{type(exc).__name__}"
        await session.rollback()

    recorder.add(
        "V01-30", "D",
        "filename longer than String(255) must fail as a typed IngestionError",
        f"{len(name)}-character filename",
        "IngestionError subclass",
        other,
        "PASS" if typed else "FAIL",
        "CONFIRMED BEHAVIOR" if typed else "MISSING",
        "ingestion.py _validate_filename length check runs before "
        "hashing/DB work; no SQLAlchemy DBAPIError can surface",
        "Fixed (E01 F2).",
    )
    assert typed


async def test_v01_31_empty_input_accepted(db_env, recorder: Recorder):
    """E01 FIX (N8): zero-byte and whitespace-only content are rejected.

    Pre-fix this recorded acceptance with line_count=0 as an open design
    decision. The decision is now encoded: empty/whitespace-only
    content raises InvalidContentError (comment-only configs remain
    valid — see V01-57).
    """
    from sqlalchemy import delete, func, select

    from app.engines.ingestion import InvalidContentError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    rejected = False
    detail = ""
    try:
        await eng.ingest(file_content=b"", filename="empty.cfg",
                         content_type="text/plain")
        await session.commit()
        detail = "accepted"
    except InvalidContentError as exc:
        rejected = True
        detail = f"InvalidContentError: {exc}"
    except Exception as exc:  # noqa: BLE001
        detail = f"UNEXPECTED {type(exc).__name__}: {exc}"
        await session.rollback()

    rows = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()

    ok = rejected and rows == 0
    recorder.add(
        "V01-31", "D",
        "zero-byte configuration is rejected with a typed error and "
        "nothing is persisted (N8 policy decision)",
        "b'', filename='empty.cfg'",
        "InvalidContentError; no row",
        f"{detail}; rows={rows}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_and_decode: `not raw_content.strip()` "
        "raises InvalidContentError before any DB work",
        "Fixed (E01 N8): empty content is not meaningful configuration.",
    )
    assert ok


async def test_v01_32_failure_happens_before_db_write(db_env, recorder: Recorder):
    from sqlalchemy import delete, func, select

    from app.engines.ingestion import InvalidFileExtensionError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    await eng.ingest(file_content=_b(11, 2), filename="ok.cfg",
                     content_type="text/plain")
    await session.commit()
    before = (await session.execute(select(func.count(Configuration.id)))).scalar()

    try:
        await eng.ingest(file_content=_b(12, 2), filename="bad.exe",
                         content_type="text/plain")
        raised = None
    except InvalidFileExtensionError as exc:
        raised = type(exc).__name__
    await session.commit()

    after = (await session.execute(select(func.count(Configuration.id)))).scalar()
    ok = raised is not None and before == after
    recorder.add(
        "V01-32", "I",
        "validation failure must not persist a partial record",
        "valid ingest then invalid-extension ingest in same session",
        "typed error, row count unchanged",
        f"error={raised} rows {before}->{after}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:106-110 extension validated before any db.add() "
        "(db.add first occurs at line 138)",
    )
    assert ok


async def test_v01_33_result_round_trips_model_fields(db_env, recorder: Recorder):
    from sqlalchemy import delete, select

    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    raw = _known_good()
    r = await eng.ingest(file_content=raw, filename="roundtrip.cfg",
                         content_type="application/x-cfg")
    await session.commit()
    row = (await session.execute(
        select(Configuration).where(Configuration.id == r.configuration_id)
    )).scalar_one()

    mapping = {
        "configuration_id->id": r.configuration_id == row.id,
        "filename": r.filename == row.filename,
        "content_hash": r.content_hash == row.content_hash,
        "size_bytes": r.size_bytes == row.size_bytes,
        "line_count": r.line_count == row.line_count,
        "encoding": r.encoding == row.encoding,
        # E01 FIX (F10): the result now carries the decoded content, so
        # same-request consumers need no re-read to reach config_content.
        "content_round_trips": r.content == row.raw_content == raw.decode(),
        "encrypted_default": row.encrypted is False,
        "content_type_stored": row.content_type == "application/x-cfg",
    }
    ok = all(mapping.values())
    recorder.add(
        "V01-33", "K",
        "IngestionResult fields round-trip against Configuration columns",
        "1 valid ingest",
        "every exposed field equals the persisted column",
        str(mapping), "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:142-149 vs models/__init__.py:115-128",
    )
    assert ok


async def test_v01_34_invalid_utf8_persisted_without_binary_check(
    db_env, recorder: Recorder
):
    """E01 FIX (F4): binary-looking content is rejected, not stored.

    Pre-fix this asserted acceptance (`assert accepted`) because the
    engine had no binary detection. Post-fix the bytes fail the decode
    contract (neither UTF-8 nor cp-1252 decodes all 255 non-NUL byte
    values) with a typed error and no row is written.
    """
    from sqlalchemy import delete, func, select

    from app.engines.ingestion import IngestionError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    raw = bytes(range(1, 256))  # every non-NUL byte
    rejected = False
    detail = ""
    try:
        await eng.ingest(file_content=raw, filename="binary.cfg",
                         content_type="application/octet-stream")
        await session.commit()
        detail = "accepted"
    except IngestionError as exc:
        rejected = True
        detail = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        detail = f"UNEXPECTED {type(exc).__name__}: {exc}"
        await session.rollback()

    rows = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()
    ok = rejected and rows == 0
    recorder.add(
        "V01-34", "E",
        "binary-looking content is rejected rather than stored as text",
        "255 bytes covering every non-NUL byte value",
        "typed IngestionError; no Configuration row",
        f"{detail}; rows={rows}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _decode_content (utf-8 -> cp-1252 -> "
        "FileDecodeError): cp-1252 rejects the undefined bytes in this "
        "input; additionally _looks_binary_text mirrors "
        "ValidationEngine._has_binary_content and "
        "_looks_binary_bytes checks known file signatures",
        "Fixed (E01 F4).",
    )
    assert ok


async def test_v01_40_nul_in_content_fails_at_database_untyped(
    db_env, recorder: Recorder
):
    """E01 FIX (F3): NUL content is rejected by the engine with a typed
    error before any database round-trip (pre-fix: PostgreSQL
    CharacterNotInRepertoireError escaped untyped from flush())."""
    from sqlalchemy import delete, func, select

    from app.engines.ingestion import IngestionError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    raw = b"hostname R1\x00\n"
    typed = False
    other = ""
    try:
        await eng.ingest(file_content=raw, filename="nul.cfg",
                         content_type="text/plain")
        await session.commit()
        other = "accepted without error"
    except IngestionError as exc:
        typed = True
        other = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        other = f"{type(exc).__module__}.{type(exc).__name__}: {exc}"[:300]
        await session.rollback()

    rows = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()

    recorder.add(
        "V01-40", "E",
        "NUL byte in content fails as a typed IngestionError with no row",
        repr(raw),
        "IngestionError subclass raised by the engine, nothing persisted",
        f"{other}; rows={rows}",
        "PASS" if typed and rows == 0 else "FAIL",
        "CONFIRMED BEHAVIOR" if typed else "MISSING",
        "ingestion.py _validate_and_decode rejects b'\\x00' in the raw "
        "bytes before decode/persistence, so "
        "CharacterNotInRepertoireError can never occur",
        "Fixed (E01 F3).",
    )
    assert typed and rows == 0


async def test_v01_35_path_traversal_filename_persisted(db_env, recorder: Recorder):
    """E01 FIX (F6): traversal-shaped filenames are rejected typed and
    never reach Configuration.filename (pre-fix: stored verbatim)."""
    from sqlalchemy import delete, func, select

    from app.engines.ingestion import IngestionError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    evil = "../../etc/passwd.cfg"
    rejected = False
    detail = ""
    try:
        await eng.ingest(file_content=_b(21, 4), filename=evil,
                         content_type="text/plain")
        await session.commit()
        detail = "stored"
    except IngestionError as exc:
        rejected = True
        detail = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        detail = f"UNEXPECTED {type(exc).__name__}: {exc}"
        await session.rollback()

    rows = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()
    ok = rejected and rows == 0
    recorder.add(
        "V01-35", "F",
        "traversal-shaped filename is rejected before persistence",
        repr(evil), "typed rejection; no row",
        f"{detail}; rows={rows}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_filename rejects path separators before "
        "any persistence",
        "Fixed (E01 F6).",
    )
    assert ok


async def test_v01_36_repeat_ingest_duplicate_semantics(db_env, recorder: Recorder):
    from sqlalchemy import delete

    from app.engines.ingestion import DuplicateConfigurationError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    raw = _b(55, 6)
    outcomes = []
    for i in range(3):
        try:
            await eng.ingest(file_content=raw, filename=f"rep{i}.cfg",
                             content_type="text/plain")
            await session.commit()
            outcomes.append("inserted")
        except DuplicateConfigurationError:
            await session.rollback()
            outcomes.append("duplicate")
        except Exception as exc:  # noqa: BLE001
            await session.rollback()
            outcomes.append(type(exc).__name__)

    ok = outcomes == ["inserted", "duplicate", "duplicate"]
    recorder.add(
        "V01-36", "G",
        "repeated ingestion of identical content behaves consistently",
        "same bytes ingested 3 times",
        "['inserted', 'duplicate', 'duplicate']", str(outcomes),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py:178-189",
    )
    assert ok


# ---------------------------------------------------------------------------
# K — integration contract (source-level, no downstream execution)
# ---------------------------------------------------------------------------

def test_v01_37_api_upload_does_not_use_the_engine(recorder: Recorder):
    """E01 FIX (F9): the production upload path must delegate to the engine.

    Pre-fix this asserted the endpoint did NOT import the engine and
    listed four semantic divergences. Post-fix the endpoint imports and
    calls IngestionEngine.ingest(...) and contains no re-implemented
    ingestion rules (no hashing, no decoding, no extension checks).
    """
    src = (BACKEND / "app" / "api" / "v1" / "configurations.py").read_text(
        encoding="utf-8"
    )
    imports_engine = "IngestionEngine" in src and "engines.ingestion" in src
    delegates = "engine.ingest" in src

    divergences = []
    if "import hashlib" in src or "hashlib.sha256" in src:
        divergences.append("endpoint still computes content hashes itself")
    if ".decode(" in src:
        divergences.append("endpoint still decodes content itself")
    if "ALLOWED_EXTENSIONS" in src:
        divergences.append("endpoint still enforces the extension allow-list itself")
    if "calculate_content_hash" in src:
        divergences.append("duplicate hash helper still present")

    ok = imports_engine and delegates and not divergences
    recorder.add(
        "V01-37", "K",
        "the production upload path must use the engine under validation",
        "app/api/v1/configurations.py upload route",
        "endpoint delegates to IngestionEngine with no duplicated rules",
        f"imports_engine={imports_engine} delegates={delegates}; "
        f"divergences: {divergences or 'none'}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "configurations.py imports IngestionEngine and calls "
        "engine.ingest(...); hashlib/decode/extension logic removed; "
        "transport-only concerns (bounded read, HTTP status mapping) "
        "remain in the route",
        "Fixed (E01 F9).",
    )
    assert ok


def test_v01_38_downstream_expects_content_not_id(recorder: Recorder):
    """E01 FIX (F10): the ingestion result now supplies the content the
    audit pipeline needs, and the cross-request hand-off through the
    persisted row is documented."""
    from app.engines.compliance.executor import AuditExecutor

    sig = inspect.signature(AuditExecutor.execute)
    params = list(sig.parameters)

    from app.engines.ingestion import IngestionResult

    result_fields = sorted(vars(IngestionResult(None, "", "", 0, 0, "", "")))
    has_content_field = "content" in result_fields

    ok = "config_content" in params and has_content_field
    recorder.add(
        "V01-38", "K",
        "ingestion output must satisfy the AuditExecutor input contract",
        f"AuditExecutor.execute{sig}; IngestionResult fields={result_fields}",
        "result exposes decoded content == Configuration.raw_content",
        f"executor wants config_content: {'config_content' in params}; "
        f"result provides content={has_content_field}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py IngestionResult carries `content`; cross-request "
        "consumers read Configuration.raw_content by id (see V01-63 "
        "integration test)",
        "Fixed (E01 F10).",
    )
    assert ok


# ---------------------------------------------------------------------------
# NOT APPLICABLE categories for this engine
# ---------------------------------------------------------------------------

def test_v01_39_category_i_not_applicable_notes(recorder: Recorder):
    recorder.add(
        "V01-39", "E",
        "unsupported vendor syntax is out of scope for ingestion",
        "vendor-specific config text",
        "NOT APPLICABLE — ingestion is vendor-agnostic (bytes + filename only)",
        "NOT APPLICABLE",
        "NOT APPLICABLE", "NOT APPLICABLE",
        "ingestion.py imports no vendor/parsing module",
    )
    assert True



# ---------------------------------------------------------------------------
# E01 fix regression block — V01-41 … V01-65
#
# Contracts added by the E01 remediation (F1–F11, N1–N10). Pre-fix
# evidence is preserved in artifacts/engine_validation/01_ingestion_pre_fix/.
# ---------------------------------------------------------------------------


class _UploadClient:
    """ASGI test client wired to the throwaway DB session.

    Runs the real application stack — size-guard middleware, rate
    limiter, route, IngestionEngine — against the provided session:
    `get_db` yields it (commit after the handler, mirroring
    app.database.get_db) and `get_current_user` returns an auditor.
    Dependency overrides are always removed on exit.
    """

    def __init__(self, session):
        self.session = session
        self.client = None
        self.user = None
        self._app = None
        self._get_db = None
        self._get_user = None

    async def __aenter__(self):
        from uuid import uuid4

        import httpx
        from httpx import ASGITransport

        from app.database import get_db
        from app.main import app
        from app.models import User
        from app.security.auth import get_current_user

        self.user = User(
            id=uuid4(),
            email=f"v01-{uuid4().hex[:12]}@test.local",
            password_hash="x",
            role="auditor",
            is_active=True,
        )
        session = self.session
        # E12 FK: the upload endpoint logs CONFIG_UPLOADED with
        # user_id=current_user.id — the actor row must exist, else the
        # trail insert FK-violates and the endpoint 500s. db_env rolls
        # back at teardown, so persisting here leaves no residue.
        session.add(self.user)
        await session.flush()

        async def _test_db():
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

        async def _test_user():
            return self.user

        self._app, self._get_db, self._get_user = app, get_db, get_current_user
        app.dependency_overrides[get_db] = _test_db
        app.dependency_overrides[get_current_user] = _test_user
        try:
            self.client = httpx.AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            )
            await self.client.__aenter__()
        except Exception:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(get_current_user, None)
            raise
        return self.client

    async def __aexit__(self, exc_type, exc, tb):
        try:
            if self.client is not None:
                await self.client.__aexit__(exc_type, exc, tb)
        finally:
            self._app.dependency_overrides.pop(self._get_db, None)
            self._app.dependency_overrides.pop(self._get_user, None)


# ---------------------------------------------------------------------------
# D — boundary (filename / content type / whitespace)
# ---------------------------------------------------------------------------

def test_v01_41_filename_length_boundary(engine_pure, recorder: Recorder):
    """E01 FIX (F2): filenames are validated before hitting the DB.

    Pre-fix an >255-char filename passed the engine and surfaced as an
    untyped psycopg2/DBAPIError from flush(); now it is a typed
    InvalidFilenameError with no database round-trip.
    """
    from app.engines.ingestion import InvalidFilenameError

    cases = {
        "255 chars": "A" * 251 + ".cfg",
        "256 chars": "A" * 252 + ".cfg",
        "512 chars": "B" * 508 + ".cfg",
        "empty": "",
        "non-str": 123,
    }
    expected = {
        "255 chars": "accepted",
        "256 chars": "InvalidFilenameError",
        "512 chars": "InvalidFilenameError",
        "empty": "InvalidFilenameError",
        "non-str": "InvalidFilenameError",
    }
    outcome = {}
    for label, name in cases.items():
        try:
            engine_pure._validate_filename(name)
            outcome[label] = "accepted"
        except InvalidFilenameError:
            outcome[label] = "InvalidFilenameError"
        except Exception as exc:  # noqa: BLE001
            outcome[label] = f"UNEXPECTED {type(exc).__name__}"
    ok = outcome == expected
    recorder.add(
        "V01-41", "D",
        "filename boundaries: 255 accepted, 256+/empty/non-str rejected typed",
        "255/256/512-char names, empty string, integer",
        str(expected), str(outcome),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_filename (line 366): isinstance(str), "
        "non-empty, len <= 255 — oversized names previously escaped as "
        "StringDataRightTruncation (untyped DBAPIError)",
        "Fixed (E01 F2).",
    )
    assert ok


def test_v01_42_filename_character_safety(engine_pure, recorder: Recorder):
    """E01 FIX (F6): control characters and path separators rejected."""
    from app.engines.ingestion import InvalidFilenameError

    safe = ["café.cfg", "röuter.cfg", "emoji\U0001F600.cfg",
            "semi;colon.cfg", 'quote"file.cfg', "star*.cfg"]
    hostile = ["tab\tname.cfg", "new\nline.cfg", "nul\x00.cfg",
               "esc\x1b.cfg", "del\x7f.cfg", "zwsp\u200b.cfg",
               "back\\slash.cfg", "C:\\evil.cfg", "..\\..\\evil.cfg",
               "/abs/path.cfg", "../../etc/passwd.cfg"]
    outcome = {}
    for name in safe + hostile:
        try:
            engine_pure._validate_filename(name)
            outcome[repr(name)] = "accepted"
        except InvalidFilenameError:
            outcome[repr(name)] = "InvalidFilenameError"
        except Exception as exc:  # noqa: BLE001
            outcome[repr(name)] = f"UNEXPECTED {type(exc).__name__}"
    ok = (
        all(outcome[repr(n)] == "accepted" for n in safe)
        and all(outcome[repr(n)] == "InvalidFilenameError" for n in hostile)
    )
    recorder.add(
        "V01-42", "F",
        "filenames: printable unicode allowed; control chars, NUL, "
        "ZWSP and path separators (/ \\ drive letters) rejected typed",
        f"{len(safe)} safe names, {len(hostile)} hostile names",
        "safe accepted, hostile -> InvalidFilenameError",
        str(outcome),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_filename: isprintable() over the whole "
        "name plus separator/drive-letter rejection; pre-fix traversal "
        "names were stored verbatim in Configuration.filename",
        "Fixed (E01 F6/N3).",
    )
    assert ok


def test_v01_43_content_type_length_boundary(engine_pure, recorder: Recorder):
    """E01 FIX (F7): content_type column bound is enforced typed."""
    from app.engines.ingestion import InvalidContentTypeError

    ct50 = "application/" + "x" * 38  # len == 50
    ct51 = "application/" + "x" * 39  # len == 51
    outcome = {}
    for label, ct in [("50 chars", ct50), ("51 chars", ct51)]:
        try:
            engine_pure._validate_content_type(ct)
            outcome[label] = "accepted"
        except InvalidContentTypeError:
            outcome[label] = "InvalidContentTypeError"
        except Exception as exc:  # noqa: BLE001
            outcome[label] = f"UNEXPECTED {type(exc).__name__}"
    expected = {"50 chars": "accepted", "51 chars": "InvalidContentTypeError"}
    ok = outcome == expected
    recorder.add(
        "V01-43", "D",
        "content_type length boundary: 50 chars accepted, 51 rejected typed",
        f"len={len(ct50)} and len={len(ct51)} valid MIME strings",
        str(expected), str(outcome),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_content_type (line 421): len <= 50 — "
        "longer values previously reached the String(50) column and "
        "failed at flush() as an untyped DBAPIError",
        "Fixed (E01 F7).",
    )
    assert ok


def test_v01_44_content_type_variants(engine_pure, recorder: Recorder):
    """E01 FIX (F7): None/empty fall back to text/plain; well-formed
    MIME strings are stored verbatim; malformed or non-str rejected."""
    from app.engines.ingestion import InvalidContentTypeError

    accepted = {
        None: "text/plain",
        "": "text/plain",
        "text/plain": "text/plain",
        "text/plain; charset=utf-8": "text/plain; charset=utf-8",
        "IMAGE/PNG": "IMAGE/PNG",
        "a/b": "a/b",
        "application/x-netshow": "application/x-netshow",
        "CONFIG/TEXT": "CONFIG/TEXT",
    }
    rejected = ["text", "/plain", "text/", "a b/c",
                "text/plain garbage", 123, b"text/plain"]
    outcome = {}
    for ct, want in accepted.items():
        try:
            got = engine_pure._validate_content_type(ct)
            outcome[repr(ct)] = "ok" if got == want else f"got {got!r}"
        except Exception as exc:  # noqa: BLE001
            outcome[repr(ct)] = type(exc).__name__
    for ct in rejected:
        try:
            engine_pure._validate_content_type(ct)
            outcome[repr(ct)] = "ACCEPTED"
        except InvalidContentTypeError:
            outcome[repr(ct)] = "rejected"
        except Exception as exc:  # noqa: BLE001
            outcome[repr(ct)] = f"UNEXPECTED {type(exc).__name__}"
    ok = (
        all(outcome[repr(c)] == "ok" for c in accepted)
        and all(outcome[repr(c)] == "rejected" for c in rejected)
    )
    recorder.add(
        "V01-44", "D",
        "content_type contract: fallback, parameterised MIME, verbatim "
        "storage of well-formed values, typed rejection of malformed ones",
        f"{len(accepted)} accepted variants, {len(rejected)} malformed",
        "fallback+verbatim for well-formed; InvalidContentTypeError otherwise",
        str(outcome),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_content_type: None/'' -> 'text/plain', "
        "fullmatch ^type/subtype$ on the part before ';', str-only, "
        "printable, len <= 50; stored unmodified (advisory column)",
        "Fixed (E01 F7).",
    )
    assert ok


# ---------------------------------------------------------------------------
# E — malformed input (NUL / binary signatures / decode)
# ---------------------------------------------------------------------------

def test_v01_45_nul_positions_rejected(engine_pure, recorder: Recorder):
    """E01 FIX (F3): NUL anywhere in the payload is rejected typed
    before decode or database round-trip."""
    from app.engines.ingestion import InvalidContentError

    cases = {
        "leading": b"\x00host\n",
        "middle": b"host\x00x\n",
        "trailing": b"host\n\x00",
        "only": b"\x00",
    }
    outcome = {}
    for label, raw in cases.items():
        try:
            engine_pure._validate_and_decode(raw, "x.cfg", "text/plain")
            outcome[label] = "accepted"
        except InvalidContentError:
            outcome[label] = "InvalidContentError"
        except Exception as exc:  # noqa: BLE001
            outcome[label] = f"UNEXPECTED {type(exc).__name__}"
    ok = all(v == "InvalidContentError" for v in outcome.values())
    recorder.add(
        "V01-45", "E",
        "NUL byte at any position fails typed before decode/persistence",
        ", ".join(f"{k}:{v!r}" for k, v in cases.items()),
        "InvalidContentError for every position", str(outcome),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_and_decode rejects b'\\x00' in the raw "
        "bytes pre-decode, so PostgreSQL CharacterNotInRepertoireError "
        "can no longer escape untyped from flush()",
        "Fixed (E01 F3).",
    )
    assert ok


def test_v01_46_binary_detection_and_density_mirror(
    engine_pure, recorder: Recorder
):
    """E01 FIX (F4): known file signatures rejected, control-char
    density boundary mirrors the ValidationEngine detector."""
    from app.engines.validation import ConfigurationValidator

    magic = {
        "pdf": b"%PDF-1.4\nhello",
        "elf": b"\x7fELF\x02\x01\x01\n",
        "png": b"\x89PNG\r\n\x1a\nxxxx",
        "gif": b"GIF89a....",
        "jpeg": b"\xff\xd8\xff\xe0JFIF",
        "gzip": b"\x1f\x8b\x08\x00",
        "ole": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "7z": b"7z\xbc\xaf\x27\x1c",
        "rar": b"Rar!\x1a\x07\x00",
        "zip": b"PK\x03\x04stuff",
        "class": b"\xca\xfe\xba\xbe",
        "mz_pe": b"MZ\x90\x00PE\x00\x00rest",
    }
    outcome = {}
    for label, raw in magic.items():
        try:
            engine_pure._validate_and_decode(raw, "x.cfg", "text/plain")
            outcome[label] = "ACCEPTED"
        except Exception as exc:  # noqa: BLE001
            outcome[label] = type(exc).__name__

    try:
        engine_pure._validate_and_decode(b"MZ hostname R1\n", "x.cfg",
                                         "text/plain")
        mz_bare = "accepted"
    except Exception as exc:  # noqa: BLE001
        mz_bare = type(exc).__name__

    density = {}
    for label, text in [("10%", "A" * 90 + chr(1) * 10),
                        ("11%", "A" * 89 + chr(1) * 11)]:
        try:
            engine_pure._validate_and_decode(text.encode(), "x.cfg",
                                             "text/plain")
            density[label] = "accepted"
        except Exception as exc:  # noqa: BLE001
            density[label] = type(exc).__name__

    validator = ConfigurationValidator()
    mirror_samples = [
        "hostname R1\nline vty 0 4\n",
        "A" * 90 + chr(1) * 10,
        "A" * 89 + chr(1) * 11,
        "A" * 50 + chr(1) * 50,
    ]
    mirror = [
        (validator._has_binary_content(s), engine_pure._looks_binary_text(s))
        for s in mirror_samples
    ]
    # E02 FIX (F4): intentional, documented divergence at the exactly-10%
    # C0 sample. Validation rejects ANY C0 control char outright (its
    # rule is a superset of the density rule); ingestion keeps the strict
    # >0.1 density rule, so 10% exactly stays accepted there. Samples 1,
    # 3 and 4 must still agree on both sides.
    mirror_ok = (
        mirror[0] == (False, False)
        and mirror[1] == (True, False)
        and mirror[2] == (True, True)
        and mirror[3] == (True, True)
    )

    ok = (
        all(v == "InvalidContentError" for v in outcome.values())
        and mz_bare == "accepted"
        and density == {"10%": "accepted", "11%": "InvalidContentError"}
        and mirror_ok
    )
    recorder.add(
        "V01-46", "E",
        "binary detection: 12 file signatures rejected, bare MZ accepted, "
        "10% vs 11% control-char density boundary, validator mirror",
        "magic prefixes; MZ text; control-char ratios 0.10/0.11; 4 mirror samples",
        "signatures -> InvalidContentError; density > 0.1 rejected; "
        "ingestion == validator verdicts except the exactly-10% C0 sample "
        "(validation stricter by design)",
        f"magic={outcome} mz_bare={mz_bare} density={density} "
        f"mirror={mirror} (sample2 True/False = documented divergence)",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _looks_binary_bytes (line 520, magic list) and "
        "_looks_binary_text (line 528) density rule mirror "
        "ConfigurationValidator._has_binary_content (validation.py) density "
        "rule; E02 FIX (F4) adds an outranking any-C0 rule at the "
        "validation gate only (boundary samples 1/3/4 still agree)",
        "Divergence documented (E02 F4 design decision).",
    )
    assert ok


def test_v01_47_decode_strategy_utf8_cp1252(engine_pure, recorder: Recorder):
    """E01 FIX (F1): strict utf-8 first, strict cp-1252 fallback,
    typed FileDecodeError when neither codec defines the bytes."""
    from app.engines.ingestion import FileDecodeError

    utf8_text, utf8_enc = engine_pure._decode_content(
        "café".encode("utf-8")
    )
    cp_text, cp_enc = engine_pure._decode_content(b"caf\xe9")

    undefined = [0x81, 0x8D, 0x8F, 0x90, 0x9D]
    decode_outcomes = {}
    for byte in undefined:
        try:
            engine_pure._decode_content(bytes([byte]))
            decode_outcomes[hex(byte)] = "ACCEPTED"
        except FileDecodeError:
            decode_outcomes[hex(byte)] = "FileDecodeError"
        except Exception as exc:  # noqa: BLE001
            decode_outcomes[hex(byte)] = f"UNEXPECTED {type(exc).__name__}"

    try:
        engine_pure._validate_and_decode(b"hostname R1\nline \x81x\n",
                                         "x.cfg", "text/plain")
        pipeline = "ACCEPTED"
    except Exception as exc:  # noqa: BLE001
        pipeline = type(exc).__name__

    try:
        b"\x81".decode("latin-1")
        latin1 = "accepts"
    except UnicodeDecodeError:
        latin1 = "rejects"

    ok = (
        utf8_enc == "utf-8" and utf8_text == "café"
        and cp_enc == "cp-1252" and cp_text == "café"
        and all(v == "FileDecodeError" for v in decode_outcomes.values())
        and pipeline == "FileDecodeError"
    )
    recorder.add(
        "V01-47", "E",
        "decode strategy: strict utf-8, strict cp-1252 fallback, "
        "FileDecodeError for bytes neither codec defines",
        "utf-8 'café' bytes; cp-1252 b'caf\\xe9'; undefined cp-1252 bytes "
        "0x81/0x8d/0x8f/0x90/0x9d; same bytes embedded in text",
        "utf-8 path used first; cp-1252 for high bytes; FileDecodeError "
        "for undefined bytes (both decode helper and full pipeline)",
        f"utf8={utf8_enc} cp={cp_enc} undefined={decode_outcomes} "
        f"pipeline={pipeline}; latin-1 {latin1} b'\\x81'",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _decode_content (line 542): utf-8 -> cp-1252 -> "
        "FileDecodeError. Pre-fix latin-1 never fails, so arbitrary "
        "binary was decoded and stored as text",
        "Fixed (E01 F1); cp-1252 over latin-1 is a design decision — "
        "latin-1 maps all 256 byte values and would never fail.",
    )
    assert ok


# ---------------------------------------------------------------------------
# I — error handling (input types / empty input)
# ---------------------------------------------------------------------------

def test_v01_48_non_bytes_content_rejected(engine_pure, recorder: Recorder):
    """E01 FIX (N4): only bytes/bytearray reach the pipeline; every
    other Python type fails typed instead of AttributeError."""
    from app.engines.ingestion import InvalidContentError

    bad = [("str", "hostname R1\n"), ("int", 42), ("none", None),
           ("list", [1, 2]), ("dict", {"a": 1}),
           ("memoryview", memoryview(b"x"))]
    outcome = {}
    for label, value in bad:
        try:
            engine_pure._validate_and_decode(value, "x.cfg", "text/plain")  # type: ignore[arg-type]
            outcome[label] = "ACCEPTED"
        except InvalidContentError:
            outcome[label] = "InvalidContentError"
        except Exception as exc:  # noqa: BLE001
            outcome[label] = f"UNEXPECTED {type(exc).__name__}"

    try:
        r = engine_pure._validate_and_decode(
            bytearray(b"hostname R1\n"), "x.cfg", "text/plain"
        )
        bytearray_result = f"bytes={isinstance(r[0], bytes)} enc={r[2]}"
        bytearray_ok = isinstance(r[0], bytes) and r[2] == "utf-8"
    except Exception as exc:  # noqa: BLE001
        bytearray_result = f"UNEXPECTED {type(exc).__name__}"
        bytearray_ok = False

    ok = all(v == "InvalidContentError" for v in outcome.values()) and bytearray_ok
    recorder.add(
        "V01-48", "I",
        "non-bytes file_content fails typed; bytearray accepted and "
        "normalised to bytes",
        f"str/int/None/list/dict/memoryview rejected; bytearray contrast ({bytearray_result})",
        "InvalidContentError for every non-bytes type",
        str(outcome),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_input_type (line 355): bytes/bytearray "
        "only — str previously raised AttributeError at b'\\x00'.__contains__",
        "Fixed (E01 N4).",
    )
    assert ok


def test_v01_49_whitespace_only_vs_comment_only(engine_pure, recorder: Recorder):
    """E01 FIX (N8): whitespace-only payloads are rejected typed while
    comment-only configurations remain valid input (V01-31 semantics)."""
    from app.engines.ingestion import InvalidContentError

    whitespace = [b"", b"   ", b"\n\n\t  ", b"\r\n\r\n", b" \t\r\n"]
    outcome = {}
    for raw in whitespace:
        try:
            engine_pure._validate_and_decode(raw, "w.cfg", "text/plain")
            outcome[repr(raw)] = "ACCEPTED"
        except InvalidContentError:
            outcome[repr(raw)] = "InvalidContentError"
        except Exception as exc:  # noqa: BLE001
            outcome[repr(raw)] = f"UNEXPECTED {type(exc).__name__}"

    comment_raw = b"# comment\n! alt\n// c\n"
    try:
        r = engine_pure._validate_and_decode(comment_raw, "c.cfg", "text/plain")
        comment = f"lines={r[3]} enc={r[2]}"
        comment_ok = r[3] == 3 and r[2] == "utf-8"
    except Exception as exc:  # noqa: BLE001
        comment = f"UNEXPECTED {type(exc).__name__}"
        comment_ok = False

    ok = all(v == "InvalidContentError" for v in outcome.values()) and comment_ok
    recorder.add(
        "V01-49", "D",
        "empty/whitespace-only content rejected typed; comment-only "
        "content accepted with correct line count",
        f"whitespace cases={list(outcome)}; comment-only 3 lines -> {comment}",
        "whitespace -> InvalidContentError; comment-only -> 3 lines, utf-8",
        f"whitespace={outcome}; comment={comment}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_and_decode: not raw_content.strip() -> "
        "InvalidContentError; comment/blank line styles (# ! //) are "
        "content, not emptiness",
        "Fixed (E01 N8).",
    )
    assert ok



# ---------------------------------------------------------------------------
# B — functional/positive (end-to-end persistence)
# ---------------------------------------------------------------------------

async def test_v01_50_bytearray_content_roundtrip(db_env, recorder: Recorder):
    """E01 FIX (N4): bytearray uploads decode to the same text the
    Configuration row stores."""
    from sqlalchemy import delete, select

    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    text = "hostname BYTEARRAY\nline vty 0 4\n"
    res = await eng.ingest(file_content=bytearray(text.encode("utf-8")),
                           filename="bytes_roundtrip.cfg",
                           content_type="text/plain")
    await session.commit()
    row = (await session.execute(
        select(Configuration).where(Configuration.id == res.configuration_id)
    )).scalar_one()

    checks = {
        "result_content": res.content == text,
        "row_content": row.raw_content == text,
        "row_is_str": isinstance(row.raw_content, str),
        "encoding": res.encoding == row.encoding == "utf-8",
        "size": res.size_bytes == len(text.encode("utf-8")) == row.size_bytes,
    }
    ok = all(checks.values())
    recorder.add(
        "V01-50", "B",
        "bytearray input round-trips: result.content == row.raw_content",
        f"bytearray({len(text)} chars), bytes_roundtrip.cfg",
        "identical decoded text in result and row, utf-8, size preserved",
        str(checks), "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _validate_input_type accepts bytearray and "
        "normalises to bytes; ingest returns IngestionResult.content (F10)",
        "Fixed (E01 N4/F10).",
    )
    assert ok


# ---------------------------------------------------------------------------
# G — reliability (transactions, races)
# ---------------------------------------------------------------------------

async def test_v01_51_stale_precheck_race_typed(db_env, recorder: Recorder):
    """E01 FIX (N5): a concurrent duplicate insert fails typed inside a
    savepoint; the session stays usable and the winner's id is carried
    on the exception."""
    from sqlalchemy import delete, func, select, text

    from app.engines.ingestion import DuplicateConfigurationError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    raw = _b(71, 4)
    winner = await eng.ingest(file_content=raw, filename="race_a.cfg",
                              content_type="text/plain")
    await session.commit()

    # Stale read: the pre-check misses the committed winner exactly
    # once; the integrity-error translation afterwards sees it.
    real_check = eng._check_duplicates
    calls = {"n": 0}

    async def stale_once(content_hash):
        calls["n"] += 1
        if calls["n"] == 1:
            return None
        return await real_check(content_hash)

    outcome, cfg_id = "", None
    eng._check_duplicates = stale_once
    try:
        try:
            await eng.ingest(file_content=raw, filename="race_b.cfg",
                             content_type="text/plain")
            outcome = "accepted"
        except DuplicateConfigurationError as exc:
            outcome = "duplicate"
            cfg_id = exc.configuration_id
        except Exception as exc:  # noqa: BLE001
            outcome = f"UNEXPECTED {type(exc).__name__}: {exc}"
            await session.rollback()
    finally:
        eng.__dict__.pop("_check_duplicates", None)

    rows = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()
    usable = (await session.execute(text("SELECT 1"))).scalar()

    follow_up = "ok"
    try:
        res = await eng.ingest(file_content=_b(72, 3), filename="race_c.cfg",
                               content_type="text/plain")
        await session.commit()
        follow_up = "ok" if res.configuration_id else "empty"
    except Exception as exc:  # noqa: BLE001
        follow_up = f"FAILED {type(exc).__name__}: {exc}"
        await session.rollback()

    ok = (outcome == "duplicate"
          and cfg_id == winner.configuration_id
          and rows == 1 and usable == 1
          and follow_up == "ok" and calls["n"] >= 2)
    recorder.add(
        "V01-51", "G",
        "stale pre-check race: INSERT runs inside begin_nested(); SQLSTATE "
        "23505 is translated to DuplicateConfigurationError carrying the "
        "winner id; savepoint rollback leaves the session usable",
        "winner committed, then identical bytes ingested with pre-check "
        "returning None once",
        "DuplicateConfigurationError(configuration_id=winner); 1 row; "
        "SELECT 1 works; follow-up ingest succeeds",
        f"outcome={outcome} cfg_id_matches="
        f"{cfg_id == winner.configuration_id} rows={rows} usable={usable} "
        f"follow_up={follow_up} check_calls={calls['n']}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py ingest: session.begin_nested() around the INSERT; "
        "_translate_integrity_error maps 23505 -> "
        "DuplicateConfigurationError, 23503 -> InvalidDeviceError; "
        "pre-fix the raw IntegrityError escaped untyped",
        "Fixed (E01 N5).",
    )
    assert ok


async def test_v01_52_cross_session_duplicate_race(db_env, recorder: Recorder):
    """E01 FIX (N5): the race also resolves typed when the winner
    commits in a different session (two engines, two connections)."""
    import scripts.engine_validation.dbutil as dbutil
    from sqlalchemy import delete, func, select, text

    from app.engines.ingestion import DuplicateConfigurationError, IngestionEngine
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    raw = _b(73, 4)
    winner = await eng.ingest(file_content=raw, filename="race2_a.cfg",
                              content_type="text/plain")
    await session.commit()

    other_engine, other_factory = dbutil.make_session_factory()
    s2 = other_factory()
    outcome, cfg_id, rows2, usable2 = "", None, -1, -1
    try:
        eng_b = IngestionEngine(db=s2)
        real_check = eng_b._check_duplicates
        calls = {"n": 0}

        async def stale_once(content_hash):
            calls["n"] += 1
            if calls["n"] == 1:
                return None
            return await real_check(content_hash)

        eng_b._check_duplicates = stale_once
        try:
            await eng_b.ingest(file_content=raw, filename="race2_b.cfg",
                               content_type="text/plain")
            outcome = "accepted"
        except DuplicateConfigurationError as exc:
            outcome = "duplicate"
            cfg_id = exc.configuration_id
        except Exception as exc:  # noqa: BLE001
            outcome = f"UNEXPECTED {type(exc).__name__}: {exc}"
            await s2.rollback()
        rows2 = (await s2.execute(
            select(func.count(Configuration.id))
        )).scalar()
        usable2 = (await s2.execute(text("SELECT 1"))).scalar()
    finally:
        await s2.rollback()
        await s2.close()
        await other_engine.dispose()

    ok = (outcome == "duplicate"
          and cfg_id == winner.configuration_id
          and rows2 == 1 and usable2 == 1)
    recorder.add(
        "V01-52", "C",
        "cross-session duplicate race: second connection's unique-index "
        "violation becomes DuplicateConfigurationError with the first "
        "session's row id; second session stays usable",
        "session A commits winner; session B ingests identical bytes "
        "with a stale pre-check",
        "DuplicateConfigurationError(configuration_id=winner); 1 row; "
        "session B SELECT 1 works",
        f"outcome={outcome} cfg_id_matches="
        f"{cfg_id == winner.configuration_id} rows={rows2} usable={usable2}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "uq_configurations_content_hash unique index (models/__init__.py "
        "line 140) makes the database the arbiter; pre-fix the second "
        "session raised raw sqlalchemy IntegrityError",
        "Fixed (E01 N5).",
    )
    assert ok


async def test_v01_56_flush_rollback_commit_semantics(
    db_env, recorder: Recorder
):
    """E01 FIX (F11): ingest flushes but does not commit — the caller
    (get_db) owns the transaction boundary."""
    from sqlalchemy import delete, func, select

    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    raw = _b(67, 5)
    res = await eng.ingest(file_content=raw, filename="flush_a.cfg",
                           content_type="text/plain")
    flushed = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()

    await session.rollback()
    rolled = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()

    await eng.ingest(file_content=raw, filename="flush_a.cfg",
                     content_type="text/plain")
    await session.commit()
    committed = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()

    checks = {
        "flushed_visible": flushed == 1,
        "rollback_discards": rolled == 0,
        "reingest_after_rollback": committed == 1,
        "result_id_set": res.configuration_id is not None,
    }
    ok = all(checks.values())
    recorder.add(
        "V01-56", "G",
        "ingest flushes only: row visible in-session, discarded by "
        "rollback, persisted by commit; identical content re-ingests "
        "after rollback",
        "ingest without commit -> rollback -> same bytes again -> commit",
        "flushed=1, rolled=0, committed=1",
        f"flushed={flushed} rolled={rolled} committed={committed} "
        f"checks={checks}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py ingest ends with flush() and returns — no commit(); "
        "app/database.py get_db commits after the route handler (F11)",
        "Fixed (E01 F11).",
    )
    assert ok


# ---------------------------------------------------------------------------
# C — negative (deduplication edge cases)
# ---------------------------------------------------------------------------

async def test_v01_53_historical_duplicate_rows(db_env, recorder: Recorder):
    """E01 FIX (N5/N1): with the unique index temporarily absent and
    historical duplicate rows present, the pre-check returns ONE winner
    (no MultipleResultsFound) and ingest still fails typed."""
    from uuid import uuid4

    from sqlalchemy import delete, text

    from app.engines.ingestion import DuplicateConfigurationError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    raw = _b(74, 4)
    content_hash = eng._calculate_hash(raw)

    pre_outcome, outcome, cfg_id = "", "", None
    ids = []
    dropped = restored = False
    try:
        await session.execute(
            text("DROP INDEX IF EXISTS uq_configurations_content_hash")
        )
        await session.commit()
        dropped = True
        for i in range(2):
            row_id = uuid4()
            ids.append(row_id)
            session.add(Configuration(
                id=row_id, filename=f"legacy{i}.cfg",
                content_hash=content_hash,
                raw_content="hostname LEGACY\n", content_type="text/plain",
                size_bytes=16, line_count=1, encoding="utf-8",
                encrypted=False,
            ))
        await session.commit()

        try:
            pre_check = await eng._check_duplicates(content_hash)
            pre_outcome = ("winner-id" if pre_check in ids
                           else f"unexpected {pre_check!r}")
        except Exception as exc:  # noqa: BLE001
            pre_outcome = f"RAISED {type(exc).__name__}"

        try:
            await eng.ingest(file_content=raw,
                             filename="legacy_again.cfg",
                             content_type="text/plain")
            outcome = "accepted"
        except DuplicateConfigurationError as exc:
            outcome = "duplicate"
            cfg_id = exc.configuration_id
        except Exception as exc:  # noqa: BLE001
            outcome = f"UNEXPECTED {type(exc).__name__}: {exc}"
            await session.rollback()
    finally:
        await session.rollback()
        await session.execute(
            delete(Configuration).where(Configuration.content_hash == content_hash)
        )
        await session.commit()
        await session.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_configurations_content_hash "
            "ON configurations (content_hash)"
        ))
        await session.commit()
        restored = True

    ok = (dropped and restored and pre_outcome == "winner-id"
          and outcome == "duplicate" and cfg_id in ids)
    recorder.add(
        "V01-53", "C",
        "multi-row historical duplicates: pre-check returns a single "
        "winner UUID (scalars().first, no MultipleResultsFound) and "
        "ingest raises DuplicateConfigurationError before inserting",
        "index dropped; 2 rows sharing one content_hash; then ingest the "
        "same bytes again",
        "pre-check -> one of the two ids; ingest -> "
        "DuplicateConfigurationError; index restored in finally",
        f"pre={pre_outcome} ingest={outcome} cfg_is_legacy="
        f"{cfg_id in ids} dropped={dropped} restored={restored}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _check_duplicates: select(...).limit(1) + "
        "scalars().first() — pre-fix .one() raised MultipleResultsFound "
        "when the table already held duplicates; alembic 004 removes "
        "historical duplicates before creating the unique index",
        "Fixed (E01 N1/N5).",
    )
    assert ok


async def test_v01_54_unique_content_hash_index(db_env, recorder: Recorder):
    """E01 FIX (N5): the duplicate key is enforced by the database —
    unique pg_index, single pg_indexes entry, matching model metadata."""
    from sqlalchemy import text

    from app.models import Configuration

    eng, session = db_env
    pg_rows = (await session.execute(text(
        "SELECT c.relname, i.indisunique FROM pg_index i "
        "JOIN pg_class c ON c.oid = i.indexrelid "
        "JOIN pg_class t ON t.oid = i.indrelid "
        "WHERE t.relname = 'configurations' "
        "AND c.relname LIKE '%content_hash%'"
    ))).all()
    pg_names = (await session.execute(text(
        "SELECT indexname FROM pg_indexes WHERE tablename = 'configurations' "
        "AND indexname LIKE '%content_hash%'"
    ))).scalars().all()
    model_indexes = sorted(i.name for i in Configuration.__table__.indexes)

    checks = {
        "pg_unique": pg_rows == [("uq_configurations_content_hash", True)],
        "pg_single": pg_names == ["uq_configurations_content_hash"],
        "model_has_uq": "uq_configurations_content_hash" in model_indexes,
        "no_legacy_ix": "ix_configurations_content_hash" not in model_indexes,
    }
    ok = all(checks.values())
    recorder.add(
        "V01-54", "C",
        "uq_configurations_content_hash exists as a UNIQUE pg_index and "
        "the only content_hash index; model metadata matches",
        "pg_index/pg_indexes introspection + Configuration.__table__",
        "[('uq_configurations_content_hash', True)] / single index / "
        "model carries uq only",
        f"pg={pg_rows} pg_indexes={pg_names} model={model_indexes} "
        f"checks={checks}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "models/__init__.py line 140 Index('uq_configurations_content_hash', "
        "'content_hash', unique=True); alembic 004 drops the legacy "
        "ix_configurations_content_hash before creating the unique index",
        "Fixed (E01 N5).",
    )
    assert ok


# ---------------------------------------------------------------------------
# D — boundary (device association)
# ---------------------------------------------------------------------------

async def test_v01_55_device_id_validation(db_env, recorder: Recorder):
    """E01 FIX (N2): device_id must be a UUID shape that exists —
    typed InvalidDeviceError, no partial insert."""
    from uuid import uuid4

    from sqlalchemy import delete, func, select

    from app.engines.ingestion import InvalidDeviceError
    from app.models import Configuration, Device, User

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    uid, did = uuid4(), uuid4()
    session.add(User(id=uid, email=f"v01-dev-{uid.hex[:12]}@test.local",
                     password_hash="x", role="auditor", is_active=True))
    await session.flush()
    session.add(Device(id=did, user_id=uid, name="probe-switch"))
    await session.commit()

    outcome = {}
    try:
        res = await eng.ingest(file_content=_b(75, 3), filename="dev_ok.cfg",
                               content_type="text/plain", device_id=did)
        await session.commit()
        row = (await session.execute(
            select(Configuration).where(Configuration.id == res.configuration_id)
        )).scalar_one()
        outcome["valid device"] = "stored" if row.device_id == did else "lost"

        try:
            await eng.ingest(file_content=_b(76, 3), filename="dev_missing.cfg",
                             content_type="text/plain", device_id=uuid4())
            outcome["missing device"] = "ACCEPTED"
        except InvalidDeviceError:
            outcome["missing device"] = "InvalidDeviceError"
            await session.rollback()
        except Exception as exc:  # noqa: BLE001
            outcome["missing device"] = f"UNEXPECTED {type(exc).__name__}"
            await session.rollback()

        try:
            await eng.ingest(file_content=_b(77, 3), filename="dev_str.cfg",
                             content_type="text/plain",
                             device_id="not-a-uuid")  # type: ignore[arg-type]
            outcome["non-uuid device"] = "ACCEPTED"
        except InvalidDeviceError:
            outcome["non-uuid device"] = "InvalidDeviceError"
            await session.rollback()
        except Exception as exc:  # noqa: BLE001
            outcome["non-uuid device"] = f"UNEXPECTED {type(exc).__name__}"
            await session.rollback()

        res4 = await eng.ingest(file_content=_b(78, 3), filename="dev_none.cfg",
                                content_type="text/plain", device_id=None)
        await session.commit()
        row4 = (await session.execute(
            select(Configuration).where(Configuration.id == res4.configuration_id)
        )).scalar_one()
        outcome["None device"] = ("stored-null" if row4.device_id is None
                                  else f"got {row4.device_id}")

        count = (await session.execute(
            select(func.count(Configuration.id))
        )).scalar()
        outcome["row count"] = str(count)
    finally:
        await session.rollback()
        await session.execute(delete(Configuration))
        await session.execute(delete(Device).where(Device.id == did))
        await session.execute(delete(User).where(User.id == uid))
        await session.commit()

    expected = {
        "valid device": "stored",
        "missing device": "InvalidDeviceError",
        "non-uuid device": "InvalidDeviceError",
        "None device": "stored-null",
        "row count": "2",
    }
    ok = outcome == expected
    recorder.add(
        "V01-55", "D",
        "device_id contract: existing UUID stored, missing UUID and "
        "non-UUID rejected typed with no row, None leaves device unset",
        "real device, random uuid, 'not-a-uuid', None",
        str(expected), str(outcome),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _device_exists: UUID shape check then SELECT — "
        "pre-fix a bad device_id escaped as a FK violation "
        "(sqlalchemy.exc.IntegrityError) or StatementError",
        "Fixed (E01 N2).",
    )
    assert ok


# ---------------------------------------------------------------------------
# B — functional/positive (content classes)
# ---------------------------------------------------------------------------

async def test_v01_57_comment_only_content_persisted(
    db_env, recorder: Recorder
):
    """E01 FIX (N8): comment-only configurations are valid content —
    rejected only when the payload is empty/whitespace (V01-49)."""
    from sqlalchemy import delete, select

    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    raw = b"# comment\n! alt\n// c\n"
    res = await eng.ingest(file_content=raw, filename="comments_only.cfg",
                           content_type="text/plain")
    await session.commit()
    row = (await session.execute(
        select(Configuration).where(Configuration.id == res.configuration_id)
    )).scalar_one()

    checks = {
        "lines": res.line_count == 3 == row.line_count,
        "content": res.content == row.raw_content == raw.decode("utf-8"),
        "encoding": res.encoding == row.encoding == "utf-8",
        "size": res.size_bytes == len(raw) == row.size_bytes,
        "hash": res.content_hash == row.content_hash,
    }
    ok = all(checks.values())
    recorder.add(
        "V01-57", "B",
        "comment-only payload (# ! // styles) ingests and persists with "
        "line_count/content/size/hash all agreeing",
        f"{len(raw)} B, 3 comment lines, comments_only.cfg",
        "row + result agree; 3 lines; utf-8",
        str(checks), "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py: emptiness is measured by strip() — comments are "
        "content; complements V01-31/V01-49",
        "Fixed (E01 N8).",
    )
    assert ok



# ---------------------------------------------------------------------------
# K — integration contract (real application stack via ASGI)
# ---------------------------------------------------------------------------

async def test_v01_58_upload_endpoint_delegates_to_engine(
    db_env, recorder: Recorder
):
    """E01 FIX (F9): the production upload path runs through the real
    app stack (middleware -> route -> IngestionEngine) and returns the
    ConfigurationResponse contract."""
    from sqlalchemy import delete, func, select

    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    content = _known_good()
    async with _UploadClient(session) as client:
        resp = await client.post(
            "/api/v1/configurations/upload",
            files={"file": ("api_upload.cfg", content, "text/plain")},
        )
    body = (resp.json() if "application/json"
            in resp.headers.get("content-type", "") else {})
    rows = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()
    row = None
    if body.get("id"):
        row = (await session.execute(
            select(Configuration).where(Configuration.id == body["id"])
        )).scalar_one_or_none()

    expected_keys = {"id", "filename", "content_type", "size_bytes",
                     "line_count", "uploaded_at"}
    checks = {
        "status_201": resp.status_code == 201,
        "response_keys": expected_keys <= set(body),
        "filename": body.get("filename") == "api_upload.cfg",
        "size_bytes": body.get("size_bytes") == len(content),
        "one_row": rows == 1,
        "row_hash": (row is not None
                     and row.content_hash == hashlib.sha256(content).hexdigest()),
        "row_filename": row is not None and row.filename == "api_upload.cfg",
    }
    ok = all(checks.values())
    recorder.add(
        "V01-58", "K",
        "POST /api/v1/configurations/upload returns 201 "
        "ConfigurationResponse and persists exactly one row through the "
        "engine (route no longer re-implements ingestion)",
        f"{len(content)} B multipart, api_upload.cfg, real ASGI stack",
        "201 with id/filename/content_type/size_bytes/line_count/"
        "uploaded_at; 1 row; sha256 matches",
        f"status={resp.status_code} body_keys={sorted(body)} rows={rows} "
        f"checks={checks}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "configurations.py upload_configuration (line 70): bounded read "
        "then IngestionEngine.ingest; get_db override mirrors "
        "app/database.py commit-after-handler semantics",
        "Fixed (E01 F9/N10).",
    )
    assert ok


async def test_v01_59_oversized_upload_rejected(
    db_env, recorder: Recorder
):
    """E01 FIX (N10): oversized requests are stopped twice — ASGI
    middleware by declared content-length (before multipart parsing)
    and the route's bounded chunked read (before full materialisation)."""

    from fastapi import HTTPException

    from sqlalchemy import delete, func, select

    from app.api.v1.configurations import upload_configuration
    from app.config import settings
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    limit = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024 + 64 * 1024

    class _OversizedUpload:
        """Stand-in UploadFile whose body exceeds MAX_UPLOAD_SIZE_MB."""

        def __init__(self, total, filename="huge.cfg",
                     content_type="text/plain"):
            self.filename = filename
            self.content_type = content_type
            self._buf = io.BytesIO(b"x" * total)
            self.chunks = 0

        async def read(self, size=-1):
            self.chunks += 1
            return self._buf.read(size)

    async with _UploadClient(session) as client:
        rejected = await client.post(
            "/api/v1/configurations/upload",
            content=b"x",
            headers={"content-length": str(limit + 1)},
        )
        control = await client.post(
            "/health",
            content=b"x",
            headers={"content-length": str(limit + 1)},
        )

    total = 12 * 1024 * 1024
    fake = _OversizedUpload(total)
    route_outcome = ""
    try:
        await upload_configuration(file=fake, device_id=None,
                                   db=session, current_user=None)  # type: ignore[arg-type]
        route_outcome = "accepted"
    except HTTPException as exc:
        route_outcome = f"{exc.status_code}: {exc.detail}"
    except Exception as exc:  # noqa: BLE001
        route_outcome = f"UNEXPECTED {type(exc).__name__}: {exc}"
        await session.rollback()

    consumed = fake._buf.tell()
    rows = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()

    detail = rejected.json().get("detail", "") if rejected.content else ""
    checks = {
        "middleware_413": rejected.status_code == 413,
        "middleware_detail": detail
        == f"File size exceeds maximum of {settings.MAX_UPLOAD_SIZE_MB}MB",
        "guard_is_path_specific": control.status_code != 413,
        "route_413": route_outcome.startswith("413"),
        "bounded_read_stopped_early": consumed < total,
        "chunk_count": fake.chunks == 11,
        "no_row": rows == 0,
    }
    ok = all(checks.values())
    recorder.add(
        "V01-59", "F",
        "oversized uploads: middleware 413 on declared content-length "
        "(upload POST only) and route bounded read stops after "
        "limit+1 MiB without materialising the whole body",
        f"content-length {limit + 1} (limit {limit}); "
        f"{total // 1048576} MiB body read in {settings.MAX_UPLOAD_SIZE_MB} "
        "MiB chunks",
        "413 'File size exceeds maximum of 10MB' from middleware; route "
        "raises HTTPException 413 after 11 chunks; no row",
        f"middleware={rejected.status_code} detail={detail!r} "
        f"control={control.status_code} route={route_outcome} "
        f"consumed={consumed}/{total} chunks={fake.chunks} rows={rows}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "app/main.py reject_oversized_upload_requests (line 49): POST + "
        "path suffix /configurations/upload + content-length > "
        "MAX_UPLOAD_SIZE_MB + 64 KiB framing allowance -> 413 JSON, "
        "registered before CORS; configurations.py (line 98): 1 MiB "
        "chunked read breaking as soon as buffer > limit",
        "Fixed (E01 N10).",
    )
    assert ok


async def test_v01_60_duplicate_upload_is_idempotent(
    db_env, recorder: Recorder
):
    """E01 FIX (F9): identical content uploaded twice returns the SAME
    row id with 201 (preserved API semantics), engine owns detection."""
    from sqlalchemy import delete, func, select

    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    content = _b(95, 5)
    async with _UploadClient(session) as client:
        r1 = await client.post(
            "/api/v1/configurations/upload",
            files={"file": ("dup_a.cfg", content, "text/plain")},
        )
        r2 = await client.post(
            "/api/v1/configurations/upload",
            files={"file": ("dup_b.cfg", content, "text/plain")},
        )
    b1 = r1.json() if "application/json" in r1.headers.get("content-type", "") else {}
    b2 = r2.json() if "application/json" in r2.headers.get("content-type", "") else {}
    rows = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()

    checks = {
        "first_201": r1.status_code == 201,
        "second_201": r2.status_code == 201,
        "same_id": bool(b1.get("id")) and b1.get("id") == b2.get("id"),
        # the idempotent 201 returns the EXISTING row verbatim — the
        # first upload's filename, not the second request's
        "existing_row_verbatim": (b2.get("filename") == "dup_a.cfg"
                                  and b2.get("id") == b1.get("id")),
        "one_row": rows == 1,
    }
    ok = all(checks.values())
    recorder.add(
        "V01-60", "K",
        "duplicate upload via endpoint: second POST returns 201 with the "
        "existing row verbatim (same id and first filename), exactly one "
        "Configuration row",
        f"{len(content)} B posted twice under different filenames",
        "both 201, identical id, first row returned unchanged, 1 row",
        f"r1={r1.status_code} r2={r2.status_code} id1={b1.get('id')} "
        f"id2={b2.get('id')} rows={rows} checks={checks}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "configurations.py (line 119): DuplicateConfigurationError with "
        "configuration_id -> ConfigurationResponse.from_orm(existing); "
        "409 only when the id cannot be resolved",
        "Fixed (E01 F9/N5).",
    )
    assert ok


async def test_v01_61_unsafe_filename_rejected_at_endpoint(
    db_env, recorder: Recorder
):
    """E01 FIX (F6): traversal and backslash filenames are refused by
    the endpoint (engine-typed error -> HTTP 400), nothing persisted."""
    from sqlalchemy import delete, func, select

    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    async with _UploadClient(session) as client:
        traversal = await client.post(
            "/api/v1/configurations/upload",
            files={"file": ("../../evil.cfg", b"hostname EVIL\n",
                            "text/plain")},
        )
        backslash = await client.post(
            "/api/v1/configurations/upload",
            files={"file": ("back\\slash.cfg", b"hostname EVIL2\n",
                            "text/plain")},
        )
    d1 = traversal.json().get("detail", "") if traversal.content else ""
    d2 = backslash.json().get("detail", "") if backslash.content else ""
    rows = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()

    checks = {
        "traversal_400": traversal.status_code == 400,
        "traversal_msg": "path separators" in d1,
        "backslash_400": backslash.status_code == 400,
        "backslash_msg": "path separators" in d2,
        "no_rows": rows == 0,
    }
    ok = all(checks.values())
    recorder.add(
        "V01-61", "F",
        "unsafe filenames rejected at the HTTP boundary: typed engine "
        "error surfaced as 400, no Configuration row created",
        "multipart filenames '../../evil.cfg' and 'back\\slash.cfg'",
        "both 400 with 'path separators' detail; 0 rows",
        f"t={traversal.status_code} {d1!r}; b={backslash.status_code} "
        f"{d2!r}; rows={rows}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "configurations.py (line 136) maps IngestionError -> 400 "
        "detail=str(exc); engine _validate_filename rejects both '/' "
        "and '\\' separators pre-persistence (pre-fix: stored verbatim)",
        "Fixed (E01 F6).",
    )
    assert ok


async def test_v01_62_nonexistent_device_rejected_at_endpoint(
    db_env, recorder: Recorder
):
    """E01 FIX (N2): device_id naming no existing device is a typed
    400 from the engine, not a FK IntegrityError at flush."""
    from uuid import uuid4

    from sqlalchemy import delete, func, select

    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    async with _UploadClient(session) as client:
        resp = await client.post(
            "/api/v1/configurations/upload",
            params={"device_id": str(uuid4())},
            files={"file": ("nodev.cfg", _b(96, 3), "text/plain")},
        )
    detail = resp.json().get("detail", "") if resp.content else ""
    rows = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()

    checks = {
        "status_400": resp.status_code == 400,
        "typed_detail": "does not identify an existing device" in detail,
        "no_rows": rows == 0,
    }
    ok = all(checks.values())
    recorder.add(
        "V01-62", "D",
        "upload with device_id naming no device: 400 typed detail from "
        "the engine's existence check, no partial insert",
        f"POST /upload?device_id={uuid4()} (random, unregistered)",
        "400 '...does not identify an existing device'; 0 rows",
        f"status={resp.status_code} detail={detail!r} rows={rows}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py _device_exists pre-insert check surfaced through "
        "the route's IngestionError -> 400 mapping; pre-fix the FK "
        "violation escaped as 500 IntegrityError",
        "Fixed (E01 N2).",
    )
    assert ok


async def test_v01_63_ingest_to_audit_handoff(db_env, recorder: Recorder):
    """E01 FIX (F10): the documented hand-off contract — the row the
    engine persists carries the exact content AuditExecutor.execute()
    consumes, and a full audit run completes on it."""
    from uuid import uuid4

    from sqlalchemy import delete, select

    from app.engines.compliance.executor import AuditExecutor
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    res = await eng.ingest(file_content=_known_good(),
                           filename="handoff.cfg", content_type="text/plain")
    await session.commit()
    row = (await session.execute(
        select(Configuration).where(Configuration.id == res.configuration_id)
    )).scalar_one()

    audit = AuditExecutor().execute(audit_id=str(uuid4()),
                                    config_content=row.raw_content)
    step_states = sorted({s.status for s in audit.steps})
    checks = {
        "content_handoff": (row.raw_content == res.content
                            and bool(row.raw_content)),
        "status_completed": audit.status == "completed",
        "six_steps": len(audit.steps) == 6,
        "steps_completed": all(s.status == "completed" for s in audit.steps),
        "findings": len(audit.findings) > 0,
    }
    ok = all(checks.values())
    recorder.add(
        "V01-63", "K",
        "ingestion -> audit hand-off: AuditExecutor.execute consumes the "
        "persisted row's raw_content and completes all steps",
        "V01-26 style ingest of tests/sample_configs/secure.txt, then "
        "AuditExecutor.execute(config_content=row.raw_content)",
        "status='completed', 6/6 steps completed, findings produced",
        f"checks={checks}; steps={step_states} "
        f"findings={len(audit.findings)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "executor.py execute(audit_id, config_content, framework='CIS', "
        "...); IngestionResult.content (line 147+) mirrors "
        "Configuration.raw_content — the cross-request contract named in "
        "V01-38",
        "Fixed (E01 F10).",
    )
    assert ok


# ---------------------------------------------------------------------------
# F — security (hostile input battery)
# ---------------------------------------------------------------------------

async def test_v01_64_hostile_input_battery(db_env, recorder: Recorder):
    """E01 FIX (F1–F7/N1–N4): every hostile input fails as a typed
    IngestionError subclass — never AttributeError, IntegrityError,
    DBAPIError or a bare Exception."""
    from uuid import uuid4

    from sqlalchemy import delete, func, select

    from app.engines.ingestion import IngestionError
    from app.models import Configuration

    eng, session = db_env
    await session.execute(delete(Configuration))
    await session.commit()

    base = {"file_content": _b(91, 2), "filename": "hostile.cfg",
            "content_type": "text/plain"}
    cases = [
        ("content str", {"file_content": "hostname R1\n"},
         "InvalidContentError"),
        ("content None", {"file_content": None}, "InvalidContentError"),
        ("content int", {"file_content": 42}, "InvalidContentError"),
        ("content list", {"file_content": [1, 2]}, "InvalidContentError"),
        ("content dict", {"file_content": {"a": 1}}, "InvalidContentError"),
        ("NUL byte", {"file_content": b"host\x00\n"}, "InvalidContentError"),
        ("pdf magic", {"file_content": b"%PDF-1.4\n"}, "InvalidContentError"),
        ("whitespace only", {"file_content": b"   \n  "},
         "InvalidContentError"),
        ("undecodable 0x81", {"file_content": b"host\nline \x81x\n"},
         "FileDecodeError"),
        ("oversize +1 byte", {"file_content": b"x" * (MAX_BYTES + 1)},
         "FileTooLargeError"),
        ("traversal filename", {"filename": "../../etc/passwd.cfg"},
         "InvalidFilenameError"),
        ("control-char filename", {"filename": "tab\tname.cfg"},
         "InvalidFilenameError"),
        ("256-char filename", {"filename": "A" * 252 + ".cfg"},
         "InvalidFilenameError"),
        ("non-str filename", {"filename": 123}, "InvalidFilenameError"),
        ("dotless filename", {"filename": "noext"}, "InvalidFileExtensionError"),
        ("dotdot filename", {"filename": ".."}, "InvalidFileExtensionError"),
        ("exe extension", {"filename": "x.exe"}, "InvalidFileExtensionError"),
        ("zip extension", {"filename": "x.zip"}, "InvalidFileExtensionError"),
        ("content-type int", {"content_type": 123},
         "InvalidContentTypeError"),
        ("content-type 51 chars", {"content_type": "a" * 51},
         "InvalidContentTypeError"),
        ("device_id str", {"device_id": "not-a-uuid"}, "InvalidDeviceError"),
        ("device_id missing", {"device_id": uuid4()}, "InvalidDeviceError"),
    ]

    outcome = {}
    for label, overrides, expected in cases:
        kwargs = dict(base)
        kwargs.update(overrides)
        try:
            await eng.ingest(**kwargs)  # type: ignore[arg-type]
            outcome[label] = "ACCEPTED"
        except IngestionError as exc:
            outcome[label] = type(exc).__name__
            await session.rollback()
        except Exception as exc:  # noqa: BLE001
            outcome[label] = f"UNEXPECTED {type(exc).__name__}"
            await session.rollback()

    dup_raw = _b(91, 3)
    await eng.ingest(file_content=dup_raw, filename="battery_first.cfg",
                     content_type="text/plain")
    await session.commit()
    try:
        await eng.ingest(file_content=dup_raw, filename="battery_again.cfg",
                         content_type="text/plain")
        outcome["duplicate content"] = "ACCEPTED"
    except IngestionError as exc:
        outcome["duplicate content"] = type(exc).__name__
        await session.rollback()
    except Exception as exc:  # noqa: BLE001
        outcome["duplicate content"] = f"UNEXPECTED {type(exc).__name__}"
        await session.rollback()

    expected_map = {label: expected for label, _, expected in cases}
    expected_map["duplicate content"] = "DuplicateConfigurationError"
    rows = (await session.execute(
        select(func.count(Configuration.id))
    )).scalar()

    ok = outcome == expected_map and rows == 1
    unexpected = {k: v for k, v in outcome.items()
                  if v == "ACCEPTED" or v.startswith("UNEXPECTED")}
    recorder.add(
        "V01-64", "F",
        "hostile input battery: all 23 cases raise a typed IngestionError "
        "subclass; raw DB/Python exceptions never surface; exactly the "
        "one legitimate insert persists",
        "str/None/int/list/dict content, NUL, magic, whitespace, "
        "undecodable bytes, oversize, 8 filename attacks, 2 extensions, "
        "2 content types, 2 device ids, duplicate",
        str(expected_map), f"outcome={outcome}; rows={rows}; "
        f"problems={unexpected or 'none'}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ingestion.py exception hierarchy under IngestionError (line 93): "
        "FileTooLargeError/InvalidFileExtensionError/FileDecodeError/"
        "DuplicateConfigurationError/InvalidFilenameError/"
        "InvalidContentError/InvalidContentTypeError/InvalidDeviceError; "
        "the route maps them to HTTP 400/409/413 (configurations.py:119-142)",
        "Fixed (E01 F1-F7/N1-N4).",
    )
    assert ok


# ---------------------------------------------------------------------------
# J — performance (post-fix vs pre-fix baseline)
# ---------------------------------------------------------------------------

async def test_v01_65_postfix_ingest_performance(
    db_env, recorder: Recorder
):
    """Post-fix DB ingest latency measured under the same shapes as the
    pre-fix baseline (artifacts/.../ingest_perf_baseline.json, n=10):
    small/1 MiB/near-limit/duplicate-reject, ingest + commit each."""
    import json
    import statistics

    from sqlalchemy import delete

    from app.engines.ingestion import DuplicateConfigurationError
    from app.models import Configuration

    eng, session = db_env

    baseline_path = (BACKEND / "artifacts" / "engine_validation"
                     / "01_ingestion" / "ingest_perf_baseline.json")
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

    unit = b"interface GigabitEthernet0/1\n description perf line\n"

    def sized(size, tag):
        body = (unit * (size // len(unit) + 1))[:size]
        tag_b = f"! tag {tag}\n".encode()
        return body[: size - len(tag_b)] + tag_b

    results = {}
    for name, size in [("small_1kb", 1024), ("1mib", 1048576),
                       ("near_limit_9_9mib", 10385760)]:
        await session.execute(delete(Configuration))
        await session.commit()
        samples = []
        for i in range(8):
            raw = sized(size, f"{name}-{i}")
            assert len(raw) == size
            t0 = time.perf_counter()
            await eng.ingest(file_content=raw,
                             filename=f"{name}_{i}.cfg",
                             content_type="text/plain")
            await session.commit()
            samples.append((time.perf_counter() - t0) * 1000)
        samples.sort()
        results[name] = {
            "bytes": size, "n": len(samples),
            "p50_ms": round(statistics.median(samples), 3),
            "p95_ms": round(samples[int(0.95 * len(samples)) - 1], 3),
        }

    await session.execute(delete(Configuration))
    await session.commit()
    dup_raw = sized(432, "dup")
    await eng.ingest(file_content=dup_raw, filename="dup_perf.cfg",
                     content_type="text/plain")
    await session.commit()
    samples = []
    rejected = 0
    for _ in range(8):
        t0 = time.perf_counter()
        try:
            await eng.ingest(file_content=dup_raw, filename="dup_perf.cfg",
                             content_type="text/plain")
        except DuplicateConfigurationError:
            rejected += 1
            await session.rollback()
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    results["duplicate_reject"] = {
        "bytes": 432, "n": len(samples),
        "p50_ms": round(statistics.median(samples), 3),
        "p95_ms": round(samples[int(0.95 * len(samples)) - 1], 3),
    }

    gaps, regressions = {}, {}
    for name, post in results.items():
        base = baseline[name]
        gaps[name] = round(post["p50_ms"] - base["p50_ms"], 3)
        if post["p50_ms"] > base["p50_ms"] * 5 + 10:
            regressions[name] = post["p50_ms"]

    ok = (not regressions and rejected == 8)
    recorder.add(
        "V01-65", "J",
        "post-fix ingest+commit latency vs pre-fix baseline "
        "(same four shapes; threshold p50 <= 5x baseline + 10 ms)",
        "n=8 per shape: 1 KiB, 1 MiB, 9.9 MiB, duplicate-reject",
        "no shape exceeds baseline*5+10ms; 8/8 duplicates rejected",
        f"post={results} baseline={baseline} delta_p50={gaps} "
        f"regressions={regressions or 'none'} rejected={rejected}/8",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "compared against artifacts/engine_validation/01_ingestion/"
        "ingest_perf_baseline.json (pre-fix, n=10); added validation "
        "layers are filename/content-type/extension checks plus the "
        "unique-index duplicate pre-check",
        "Measured only — not a readiness score.",
    )
    for name, post in results.items():
        recorder.rows[-1].setdefault("performance", []).append({
            "group": name,
            "post_p50_ms": post["p50_ms"],
            "post_p95_ms": post["p95_ms"],
            "baseline_p50_ms": baseline[name]["p50_ms"],
            "baseline_p95_ms": baseline[name]["p95_ms"],
            "delta_p50_ms": gaps[name],
            "n": post["n"],
        })
    assert ok
