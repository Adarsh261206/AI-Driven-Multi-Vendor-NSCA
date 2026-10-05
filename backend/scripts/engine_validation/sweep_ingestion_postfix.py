"""Engine 01 dataset sweep — POST-FIX (E01 remediation).

Runs the real corpus through IngestionEngine._validate_and_decode, the
single source of truth for ingestion after E01 (F1–F7 / N1–N4): filename
safety, extension allow-list, size, NUL/binary detection, decode
strategy (utf-8 -> cp-1252 -> FileDecodeError) and content-type
validation are exercised together exactly as ingest() does them, minus
the database round-trip. Duplicate rejection is simulated from content
hashes (first eligible upload wins) — the real arbiter is the unique
index (N5), which the DB-backed tests cover.

Outputs (backend/artifacts/engine_validation/01_ingestion/):
    dataset_results_postfix.csv     one row per input file
    dataset_summary_postfix.json    aggregate counts, typed rejections,
                                    timings, delta vs pre-fix summary

The pre-fix outputs (dataset_results.csv, dataset_summary.json) and the
snapshot in 01_ingestion_pre_fix/ are left untouched.
"""

from __future__ import annotations

import csv
import hashlib
import json
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))

DATASET = Path(r"C:\Users\priye\Downloads\SIH Config\final-dataset")
OUT_DIR = BACKEND / "artifacts" / "engine_validation" / "01_ingestion"
ALLOWED = [".txt", ".cfg", ".conf"]  # .zip removed (E01 F5/N7)


def likely_binary(raw: bytes) -> bool:
    if not raw:
        return False
    sample = raw[:4096]
    if b"\x00" in sample:
        return True
    ctrl = sum(1 for b in sample if b < 9 or 13 < b < 32)
    return ctrl / len(sample) > 0.10


def classify_postfix(row: dict) -> str:
    """Same classification ladder as the pre-fix sweep so the class
    distribution is directly comparable; extension now uses the
    post-fix allow-list and typed content rejections map to Malformed."""
    if not row["ext_allowed"] or row["pipeline_outcome"] == "InvalidFileExtensionError":
        return "Unsupported"
    if row["pipeline_outcome"] != "accepted":
        return "Malformed"
    if row["would_be_duplicate_rejected"]:
        return "Duplicate"
    if (
        row["filename_len"] > 255
        or row["size_bytes"] == 0
        or row["traversal_shaped"]
        or row["duplicate_basename"]
    ):
        return "Edge"
    return "Known-good"


def pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 4)


def main() -> int:
    from app.engines.ingestion import IngestionEngine, IngestionError

    engine = IngestionEngine(db=None)
    files = sorted(p for p in DATASET.rglob("*") if p.is_file())

    rows: list[dict] = []
    hashes: dict[str, list[str]] = defaultdict(list)
    basenames: Counter[str] = Counter(p.name for p in files)
    pipeline_times: list[float] = []
    decode_times: list[float] = []
    hash_times: list[float] = []

    for path in files:
        raw = path.read_bytes()
        rel = str(path.relative_to(DATASET))

        # --- filename stage (isolated, for visibility) ---
        try:
            engine._validate_filename(path.name)
            filename_result = "accepted"
        except IngestionError as exc:
            filename_result = f"rejected: {type(exc).__name__}"

        # --- full pipeline: what ingest() would do without the DB ---
        t0 = time.perf_counter()
        try:
            _content, _text, enc, line_count, _extra = engine._validate_and_decode(
                raw, path.name, "text/plain"
            )
            pipeline_outcome = "accepted"
            note = ""
        except IngestionError as exc:
            enc, line_count = "", 0
            pipeline_outcome = type(exc).__name__
            note = str(exc)
        pipeline_ms = (time.perf_counter() - t0) * 1000
        pipeline_times.append(pipeline_ms)

        # --- isolated decode stage (continuity with pre-fix encoding
        # distribution: pre-fix ran decode independently of the
        # extension gate) ---
        t0 = time.perf_counter()
        try:
            text, dec_enc = engine._decode_content(raw)
            decode_outcome = "accepted"
        except IngestionError as exc:
            text, dec_enc = "", f"ERROR: {type(exc).__name__}"
            decode_outcome = type(exc).__name__
        decode_ms = (time.perf_counter() - t0) * 1000
        decode_times.append(decode_ms)

        t0 = time.perf_counter()
        digest = engine._calculate_hash(raw)
        hash_ms = (time.perf_counter() - t0) * 1000
        hash_times.append(hash_ms)
        hashes[digest].append(rel)

        rows.append(
            {
                "relpath": rel,
                "filename": path.name,
                "extension": path.suffix.lower(),
                "size_bytes": len(raw),
                "ext_allowed": path.suffix.lower() in ALLOWED,
                "filename_result": filename_result,
                "pipeline_outcome": pipeline_outcome,
                "decode_outcome": decode_outcome,
                "encoding": dec_enc,
                "line_count": line_count,
                "content_hash": digest,
                "filename_len": len(path.name),
                "has_nul": b"\x00" in raw,
                "likely_binary": likely_binary(raw),
                "traversal_shaped": ".." in path.name
                or path.name.startswith("/")
                or "\\" in path.name,
                "duplicate_basename": basenames[path.name] > 1,
                "duplicate_content": False,
                "would_be_duplicate_rejected": False,
                "pipeline_ms": round(pipeline_ms, 4),
                "decode_ms": round(decode_ms, 4),
                "hash_ms": round(hash_ms, 4),
                "note": note,
            }
        )

    dup_hashes = {h for h, paths in hashes.items() if len(paths) > 1}
    seen: set[str] = set()
    for row in rows:
        row["duplicate_content"] = row["content_hash"] in dup_hashes
        eligible = row["pipeline_outcome"] == "accepted"
        if eligible and row["content_hash"] in seen:
            row["would_be_duplicate_rejected"] = True
        if eligible:
            seen.add(row["content_hash"])
        row["fixture_class"] = classify_postfix(row)

    # determinism: a second full pass must reproduce every outcome,
    # encoding, line count and hash (isolated decode re-run alongside
    # the pipeline, mirroring how the columns were recorded)
    mismatch = 0
    by_rel = {r["relpath"]: r for r in rows}
    for path in files:
        raw = path.read_bytes()
        rel = str(path.relative_to(DATASET))
        try:
            _c, _t, _p_enc, p_lines, _x = engine._validate_and_decode(
                raw, path.name, "text/plain"
            )
            outcome2 = "accepted"
        except IngestionError as exc:
            p_lines, outcome2 = 0, type(exc).__name__
        try:
            _text2, enc2 = engine._decode_content(raw)
        except IngestionError:
            enc2 = ""
        row = by_rel[rel]
        if (
            outcome2 != row["pipeline_outcome"]
            or enc2 != row["encoding"]
            or p_lines != row["line_count"]
            or hashlib.sha256(raw).hexdigest() != row["content_hash"]
        ):
            mismatch += 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = OUT_DIR / "dataset_results_postfix.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    pre_fix = json.loads(
        (OUT_DIR / "dataset_summary.json").read_text(encoding="utf-8")
    )

    pipeline_counts = dict(Counter(r["pipeline_outcome"] for r in rows))
    decode_counts = dict(Counter(r["encoding"] for r in rows))
    fixture_counts = dict(Counter(r["fixture_class"] for r in rows))
    pre_fixture = pre_fix["by_fixture_class"]
    fixture_delta = {
        k: fixture_counts.get(k, 0) - pre_fixture.get(k, 0)
        for k in sorted(set(fixture_counts) | set(pre_fixture))
    }

    summary = {
        "engine": "01_configuration_ingestion",
        "phase": "post_fix (E01 F1-F11, N1-N10)",
        "dataset_root": str(DATASET),
        "allowed_extensions": ALLOWED,
        "files_total": len(rows),
        "bytes_total": sum(r["size_bytes"] for r in rows),
        "pipeline_outcome_counts": pipeline_counts,
        "filename_stage_rejected": sum(
            1 for r in rows if r["filename_result"] != "accepted"
        ),
        "by_fixture_class": fixture_counts,
        "pre_fix_by_fixture_class": pre_fixture,
        "fixture_class_delta_vs_pre_fix": fixture_delta,
        "would_be_accepted_by_ingest": sum(
            1
            for r in rows
            if r["pipeline_outcome"] == "accepted"
            and not r["would_be_duplicate_rejected"]
        ),
        "pre_fix_would_be_accepted": pre_fix["would_be_accepted_by_ingest"],
        "duplicate_rejected_by_ingest": sum(
            1 for r in rows if r["would_be_duplicate_rejected"]
        ),
        "extension_accepted": sum(1 for r in rows if r["ext_allowed"]),
        "extension_rejected": sum(1 for r in rows if not r["ext_allowed"]),
        "decode_only_distribution": decode_counts,
        "pre_fix_encoding_distribution": pre_fix["encoding_distribution"],
        "likely_binary_files": sum(1 for r in rows if r["likely_binary"]),
        "nul_containing_files": sum(1 for r in rows if r["has_nul"]),
        "filename_over_255": sum(1 for r in rows if r["filename_len"] > 255),
        "traversal_shaped_names": sum(1 for r in rows if r["traversal_shaped"]),
        "duplicate_basenames": sum(1 for r in rows if r["duplicate_basename"]),
        "duplicate_content_groups": len(dup_hashes),
        "duplicate_content_files": sum(1 for r in rows if r["duplicate_content"]),
        "empty_files": sum(1 for r in rows if r["size_bytes"] == 0),
        "max_size_bytes": max(r["size_bytes"] for r in rows),
        "determinism_mismatches": mismatch,
        "timing_ms": {
            "pipeline_p50": pct(pipeline_times, 0.50),
            "pipeline_p95": pct(pipeline_times, 0.95),
            "pipeline_p99": pct(pipeline_times, 0.99),
            "decode_p50": pct(decode_times, 0.50),
            "decode_p95": pct(decode_times, 0.95),
            "decode_p99": pct(decode_times, 0.99),
            "hash_p50": pct(hash_times, 0.50),
            "hash_p95": pct(hash_times, 0.95),
            "hash_p99": pct(hash_times, 0.99),
            "pipeline_mean": round(statistics.mean(pipeline_times), 4),
            "decode_mean": round(statistics.mean(decode_times), 4),
            "hash_mean": round(statistics.mean(hash_times), 4),
        },
        "notes": [
            "pipeline_outcome is what IngestionEngine._validate_and_decode "
            "(the ingest() validation path minus the DB) returns per file; "
            "every rejection is a typed IngestionError subclass.",
            "duplicate_rejected_by_ingest is hash-simulated (first eligible "
            "upload wins); in production the unique index uq_"
            "configurations_content_hash is the arbiter (E01 N5).",
            "encoding/decode columns run _decode_content in isolation so "
            "they stay comparable with the pre-fix sweep, which decoded "
            "independently of the extension gate.",
            "pre-fix values are read from dataset_summary.json "
            "(preserved in 01_ingestion_pre_fix/ as well).",
        ],
    }

    (OUT_DIR / "dataset_summary_postfix.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
