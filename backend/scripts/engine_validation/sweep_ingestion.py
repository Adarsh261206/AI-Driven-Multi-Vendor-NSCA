"""Engine 01 dataset sweep — reads the real corpus through IngestionEngine.

Pure helpers only (no database): every file in the dataset is pushed through
_validate_extension / _validate_size / _decode_content / _calculate_hash so
the report can state how much of the real corpus the engine would accept.

Outputs (backend/artifacts/engine_validation/01_ingestion/):
    dataset_results.csv      one row per input file
    dataset_summary.json     aggregate counts, duplicates, timings
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
MAX_BYTES = 10 * 1024 * 1024


def likely_binary(raw: bytes) -> bool:
    if not raw:
        return False
    sample = raw[:4096]
    if b"\x00" in sample:
        return True
    ctrl = sum(1 for b in sample if b < 9 or 13 < b < 32)
    return ctrl / len(sample) > 0.10


def classify(row: dict) -> str:
    if not row["ext_allowed"] or row["ext_result"] != "accepted":
        return "Unsupported"
    if row["size_result"] != "accepted":
        return "Oversize"
    if row.get("would_be_duplicate_rejected"):
        return "Duplicate"
    if row["has_nul"] or row["likely_binary"] or row["encoding"] != "utf-8":
        return "Malformed"
    if (
        row["filename_len"] > 255
        or row["size_bytes"] == 0
        or row["traversal_shaped"]
        or row["duplicate_basename"]
    ):
        return "Edge"
    return "Known-good"


def main() -> int:
    from app.engines.ingestion import (
        FileTooLargeError,
        IngestionEngine,
        IngestionError,
        InvalidFileExtensionError,
    )

    engine = IngestionEngine(db=None)
    files = sorted(p for p in DATASET.rglob("*") if p.is_file())

    rows: list[dict] = []
    hashes: dict[str, list[str]] = defaultdict(list)
    basenames: Counter[str] = Counter(p.name for p in files)
    decode_times: list[float] = []
    hash_times: list[float] = []

    for path in files:
        raw = path.read_bytes()
        ext_result, size_result, enc, _lines, note = "accepted", "accepted", "", 0, ""

        try:
            engine._validate_extension(path.name)
        except InvalidFileExtensionError as exc:
            ext_result = f"rejected: {exc}"

        try:
            engine._validate_size(raw)
        except FileTooLargeError as exc:
            size_result = f"rejected: {exc}"

        t0 = time.perf_counter()
        try:
            text, enc = engine._decode_content(raw)
        except IngestionError as exc:
            text, enc = "", f"ERROR: {type(exc).__name__}"
            note = str(exc)
        decode_ms = (time.perf_counter() - t0) * 1000
        decode_times.append(decode_ms)

        t0 = time.perf_counter()
        digest = engine._calculate_hash(raw)
        hash_times.append((time.perf_counter() - t0) * 1000)
        hashes[digest].append(str(path.relative_to(DATASET)))

        rel = str(path.relative_to(DATASET))
        rows.append(
            {
                "relpath": rel,
                "filename": path.name,
                "extension": path.suffix.lower(),
                "size_bytes": len(raw),
                "ext_allowed": path.suffix.lower() in {".txt", ".cfg", ".conf", ".zip"},
                "ext_result": ext_result,
                "size_result": size_result,
                "encoding": enc,
                "line_count": len(text.splitlines()),
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
                "decode_ms": round(decode_ms, 4),
                "hash_ms": round(hash_times[-1], 4),
                "note": note,
            }
        )

    dup_hashes = {h for h, paths in hashes.items() if len(paths) > 1}
    seen: set[str] = set()
    for row in rows:
        row["duplicate_content"] = row["content_hash"] in dup_hashes
        eligible = row["ext_result"] == "accepted" and row["size_result"] == "accepted"
        if eligible and row["content_hash"] in seen:
            row["would_be_duplicate_rejected"] = True
        if eligible:
            seen.add(row["content_hash"])
        row["fixture_class"] = classify(row)

    # determinism: a second full pass must reproduce every hash/encoding
    mismatch = 0
    for path in files:
        raw = path.read_bytes()
        _, enc2 = engine._decode_content(raw)
        if engine._calculate_hash(raw) != hashlib.sha256(raw).hexdigest():
            mismatch += 1
            continue
        row = next(r for r in rows if r["relpath"] == str(path.relative_to(DATASET)))
        if enc2 != row["encoding"]:
            mismatch += 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = OUT_DIR / "dataset_results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    def pct(values: list[float], q: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 4)

    summary = {
        "engine": "01_configuration_ingestion",
        "dataset_root": str(DATASET),
        "files_total": len(rows),
        "bytes_total": sum(r["size_bytes"] for r in rows),
        "by_fixture_class": dict(Counter(r["fixture_class"] for r in rows)),
        "by_extension": dict(Counter(r["extension"] or "<none>" for r in rows)),
        "extension_accepted": sum(1 for r in rows if r["ext_result"] == "accepted"),
        "extension_rejected": sum(1 for r in rows if r["ext_result"] != "accepted"),
        "size_accepted": sum(1 for r in rows if r["size_result"] == "accepted"),
        "size_rejected": sum(1 for r in rows if r["size_result"] != "accepted"),
        "eligible_after_extension_and_size": sum(
            1
            for r in rows
            if r["ext_result"] == "accepted" and r["size_result"] == "accepted"
        ),
        "duplicate_rejected_by_ingest": sum(
            1 for r in rows if r["would_be_duplicate_rejected"]
        ),
        "would_be_accepted_by_ingest": sum(
            1
            for r in rows
            if r["ext_result"] == "accepted"
            and r["size_result"] == "accepted"
            and not r["would_be_duplicate_rejected"]
        ),
        "encoding_distribution": dict(Counter(r["encoding"] for r in rows)),
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
            "decode_p50": pct(decode_times, 0.50),
            "decode_p95": pct(decode_times, 0.95),
            "decode_p99": pct(decode_times, 0.99),
            "hash_p50": pct(hash_times, 0.50),
            "hash_p95": pct(hash_times, 0.95),
            "hash_p99": pct(hash_times, 0.99),
            "decode_mean": round(statistics.mean(decode_times), 4),
            "hash_mean": round(statistics.mean(hash_times), 4),
        },
        "duplicate_groups_largest": [
            {"content_hash": h[:16], "files": len(paths), "examples": paths[:4]}
            for h, paths in sorted(
                ((h, p) for h, p in hashes.items() if len(p) > 1),
                key=lambda kv: -len(kv[1]),
            )[:10]
        ],
    }

    (OUT_DIR / "dataset_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
