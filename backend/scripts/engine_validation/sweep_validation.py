"""Engine 02 dataset sweep — runs ConfigurationValidator over the real corpus.

Outputs (backend/artifacts/engine_validation/02_validation/):
    dataset_results.csv      one row per input file
    dataset_summary.json     aggregate counts, code distribution, timings
"""

from __future__ import annotations

import csv
import json
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))

DATASET = Path(r"C:\Users\priye\Downloads\SIH Config\final-dataset")
OUT_DIR = BACKEND / "artifacts" / "engine_validation" / "02_validation"
E01_RESULTS = BACKEND / "artifacts" / "engine_validation" / "01_ingestion" / "dataset_results.csv"


def load_e01() -> dict[str, dict]:
    if not E01_RESULTS.exists():
        return {}
    with open(E01_RESULTS, newline="", encoding="utf-8") as fh:
        return {row["relpath"]: row for row in csv.DictReader(fh)}


def main() -> int:
    from app.engines.validation import ConfigurationValidator

    validator = ConfigurationValidator()
    e01 = load_e01()
    files = sorted(p for p in DATASET.rglob("*") if p.is_file())

    rows: list[dict] = []
    code_totals: Counter[str] = Counter()
    code_files: Counter[str] = Counter()
    per_ext: dict[str, Counter[str]] = defaultdict(Counter)
    timings: list[float] = []

    for path in files:
        raw = path.read_bytes()
        rel = str(path.relative_to(DATASET))
        decode_note = ""
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            text = raw.decode("latin-1")
            decode_note = f"utf-8 failed: {exc.reason}"

        t0 = time.perf_counter()
        result = validator.validate(text)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        timings.append(elapsed_ms)

        counts: Counter[str] = Counter(i.code for i in result.issues)
        code_totals.update(counts)
        ext_label = path.suffix.lower() or "<none>"
        per_ext[ext_label].update(counts)
        for code in counts:
            code_files[code] += 1

        base = e01.get(rel, {})
        rows.append({
            "relpath": rel,
            "extension": ext_label,
            "size_bytes": len(raw),
            "line_count": len(text.splitlines()),
            "decode_note": decode_note,
            "is_valid": result.is_valid,
            "error_count": result.error_count,
            "warning_count": result.warning_count,
            "info_count": sum(1 for i in result.issues if i.severity.value == "info"),
            "issue_codes": ";".join(f"{k}x{v}" for k, v in sorted(counts.items())),
            "binary_content": counts.get("BINARY_CONTENT", 0),
            "empty_content": counts.get("EMPTY_CONTENT", 0),
            "sensitive_data": counts.get("SENSITIVE_DATA", 0),
            "insecure_config": counts.get("INSECURE_CONFIG", 0),
            "long_line": counts.get("LONG_LINE", 0),
            "mixed_line_endings": counts.get("MIXED_LINE_ENDINGS", 0),
            "null_byte": counts.get("NULL_BYTE", 0),
            "zero_issues": len(result.issues) == 0,
            "validate_ms": round(elapsed_ms, 4),
            "e01_ext_result": base.get("ext_result", ""),
            "e01_fixture_class": base.get("fixture_class", ""),
            "e01_would_be_accepted": base.get("would_be_duplicate_rejected", ""),
        })

    # determinism: second pass must reproduce is_valid + issue code multiset
    mismatches = 0
    for path in files:
        rel = str(path.relative_to(DATASET))
        row = next(r for r in rows if r["relpath"] == rel)
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            text = path.read_bytes().decode("latin-1")
        again = validator.validate(text)
        codes_now = ";".join(
            f"{k}x{v}"
            for k, v in sorted(Counter(i.code for i in again.issues).items())
        )
        if again.is_valid != row["is_valid"] or codes_now != row["issue_codes"]:
            mismatches += 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_DIR / "dataset_results.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    def pct(values: list[float], q: float) -> float:
        ordered = sorted(values)
        return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 4)

    joined = [r for r in rows if r["e01_ext_result"]]
    summary = {
        "engine": "02_configuration_validation",
        "dataset_root": str(DATASET),
        "files_total": len(rows),
        "bytes_total": sum(r["size_bytes"] for r in rows),
        "is_valid_true": sum(1 for r in rows if r["is_valid"]),
        "is_valid_false": sum(1 for r in rows if not r["is_valid"]),
        "files_with_zero_issues": sum(1 for r in rows if r["zero_issues"]),
        "files_with_warnings": sum(1 for r in rows if r["warning_count"]),
        "files_with_errors": sum(1 for r in rows if r["error_count"]),
        "files_with_info": sum(1 for r in rows if r["info_count"]),
        "issue_code_totals": dict(code_totals),
        "issue_code_file_counts": dict(code_files),
        "files_with_sensitive_data": sum(1 for r in rows if r["sensitive_data"]),
        "files_with_insecure_config": sum(1 for r in rows if r["insecure_config"]),
        "files_with_empty_content": sum(1 for r in rows if r["empty_content"]),
        "files_with_binary_content": sum(1 for r in rows if r["binary_content"]),
        "files_with_long_line": sum(1 for r in rows if r["long_line"]),
        "files_with_mixed_endings": sum(1 for r in rows if r["mixed_line_endings"]),
        "files_with_null_byte": sum(1 for r in rows if r["null_byte"]),
        "utf8_decode_failures": sum(1 for r in rows if r["decode_note"]),
        "determinism_mismatches": mismatches,
        "timing_ms": {
            "validate_p50": pct(timings, 0.50),
            "validate_p95": pct(timings, 0.95),
            "validate_p99": pct(timings, 0.99),
            "validate_mean": round(statistics.mean(timings), 4),
        },
        "cross_engine_01_join": {
            "joined_files": len(joined),
            "e01_ingestible": sum(
                1 for r in joined
                if r["e01_ext_result"] == "accepted"
                and r["e01_would_be_accepted"] == "False"
            ),
            "e01_ingestible_and_e02_valid": sum(
                1 for r in joined
                if r["e01_ext_result"] == "accepted"
                and r["e01_would_be_accepted"] == "False"
                and r["is_valid"]
            ),
            "e01_ingestible_and_e02_invalid": sum(
                1 for r in joined
                if r["e01_ext_result"] == "accepted"
                and r["e01_would_be_accepted"] == "False"
                and not r["is_valid"]
            ),
            "e01_ingestible_and_e02_issues": sum(
                1 for r in joined
                if r["e01_ext_result"] == "accepted"
                and r["e01_would_be_accepted"] == "False"
                and not r["zero_issues"]
            ),
            "e01_rejected_extension": sum(
                1 for r in joined if r["e01_ext_result"] != "accepted"
            ),
        },
        "top_sensitive_files": [
            {"relpath": r["relpath"], "sensitive_hits": r["sensitive_data"],
             "insecure_hits": r["insecure_config"], "lines": r["line_count"]}
            for r in sorted(rows, key=lambda x: -x["sensitive_data"])[:10]
        ],
        "top_insecure_files": [
            {"relpath": r["relpath"], "insecure_hits": r["insecure_config"],
             "lines": r["line_count"]}
            for r in sorted(rows, key=lambda x: -x["insecure_config"])[:10]
        ],
        "issue_code_by_extension": {
            ext: dict(c) for ext, c in sorted(per_ext.items()) if c
        },
    }

    (OUT_DIR / "dataset_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
