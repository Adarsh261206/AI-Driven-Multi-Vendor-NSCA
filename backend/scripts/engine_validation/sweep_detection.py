"""Engine 03 dataset sweep — runs VendorDetector over the real corpus.

Two passes per file:
  1. deployed path  (ML available, as in production)
  2. regex path     (ML forced unavailable — for comparison only)

plus a determinism re-run of pass 1 and a truncated [:6000] detection to
quantify the caller-truncation contract (audit_execution.py:137/178/215).

Model quality is NOT evaluated here — vendor classification accuracy is
deferred by instruction. Directory-derived labels are recorded only as a
disagreement count.

Outputs (backend/artifacts/engine_validation/03_detection/):
    dataset_results.csv      one row per input file
    dataset_summary.json     distributions, timings, joins, disagreements
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
OUT_DIR = BACKEND / "artifacts" / "engine_validation" / "03_detection"
E01_RESULTS = BACKEND / "artifacts" / "engine_validation" / "01_ingestion" / "dataset_results.csv"
E02_RESULTS = BACKEND / "artifacts" / "engine_validation" / "02_validation" / "dataset_results.csv"

SUPPORTED_VENDORS = {"cisco", "fortinet", "juniper", "paloalto"}


class _UnavailableML:
    is_available = False


def _force_regex():
    import app.ml.model as mlmod

    original = mlmod.get_ml_detector
    mlmod.get_ml_detector = lambda: _UnavailableML()
    return original


def _restore(original) -> None:
    import app.ml.model as mlmod

    mlmod.get_ml_detector = original


def read_text(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8"), ""
    except UnicodeDecodeError as exc:
        return raw.decode("latin-1"), f"utf-8 failed: {exc.reason}"


def load_csv(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    with open(path, newline="", encoding="utf-8") as fh:
        return {row["relpath"]: row for row in csv.DictReader(fh)}


def signature(r) -> tuple:
    return (
        r.vendor,
        r.platform,
        round(r.confidence, 12),
        r.device_type,
        r.hostname,
        r.firmware_version,
        r.detection_method.value,
        len(r.detection_evidence),
        tuple(e.pattern for e in r.detection_evidence),
    )


def pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 4)


def main() -> int:
    from app.engines.detection import VendorDetector, DetectionMethod

    detector = VendorDetector()
    e01 = load_csv(E01_RESULTS)
    e02 = load_csv(E02_RESULTS)
    files = sorted(p for p in DATASET.rglob("*") if p.is_file())

    rows: list[dict] = []
    ml_times: list[float] = []
    rx_times: list[float] = []

    # --- pass 1: deployed path -------------------------------------------
    for path in files:
        rel = str(path.relative_to(DATASET))
        text, decode_note = read_text(path)
        top = rel.split("\\")[0].split("/")[0]
        dir_label = top.lower() if top.lower() in SUPPORTED_VENDORS else ""

        t0 = time.perf_counter()
        r = detector.detect(text)
        ml_ms = (time.perf_counter() - t0) * 1000
        ml_times.append(ml_ms)
        is_ml = r.detection_method is DetectionMethod.PATTERN

        t0 = time.perf_counter()
        trunc = detector.detect(text[:6000])
        trunc_ms = (time.perf_counter() - t0) * 1000

        base01 = e01.get(rel, {})
        base02 = e02.get(rel, {})
        rows.append({
            "relpath": rel,
            "extension": path.suffix.lower() or "<none>",
            "size_bytes": len(text.encode("utf-8", errors="replace")),
            "line_count": len(text.splitlines()),
            "decode_note": decode_note,
            "dir_label": dir_label,
            "vendor": r.vendor,
            "platform": r.platform,
            "confidence": round(r.confidence, 4),
            "path": "ml" if is_ml else "regex",
            "detection_method": r.detection_method.value,
            "device_type": r.device_type,
            "hostname": r.hostname or "",
            "firmware_version": r.firmware_version or "",
            "evidence_count": len(r.detection_evidence),
            "signature": json.dumps(signature(r), ensure_ascii=False, default=str),
            "detect_ms": round(ml_ms, 4),
            "trunc_vendor": trunc.vendor,
            "trunc_platform": trunc.platform,
            "trunc_confidence": round(trunc.confidence, 4),
            "trunc_path": "ml" if trunc.detection_method is DetectionMethod.PATTERN else "regex",
            "trunc_ms": round(trunc_ms, 4),
            "truncation_diverged": trunc.vendor != r.vendor or trunc.platform != r.platform,
            "e01_ext_result": base01.get("ext_result", ""),
            "e01_ingestible": (
                base01.get("ext_result") == "accepted"
                and base01.get("would_be_duplicate_rejected") == "False"
            ),
            "e02_is_valid": base02.get("is_valid", ""),
        })

    # --- pass 2: regex path (comparison only) -----------------------------
    original = _force_regex()
    try:
        for path, row in zip(files, rows):
            text, _ = read_text(path)
            t0 = time.perf_counter()
            r = detector.detect(text)
            rx_ms = (time.perf_counter() - t0) * 1000
            rx_times.append(rx_ms)
            row["rx_vendor"] = r.vendor
            row["rx_platform"] = r.platform
            row["rx_confidence"] = round(r.confidence, 4)
            row["rx_device_type"] = r.device_type
            row["rx_ms"] = round(rx_ms, 4)
            row["path_disagreement"] = r.vendor != row["vendor"] or r.platform != row["platform"]
    finally:
        _restore(original)

    # --- determinism: rerun the deployed path -----------------------------
    determinism_mismatches = 0
    for path, row in zip(files, rows):
        text, _ = read_text(path)
        again = detector.detect(text)
        if json.dumps(signature(again), ensure_ascii=False, default=str) != row["signature"]:
            determinism_mismatches += 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_DIR / "dataset_results.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    vendor_counts = Counter(r["vendor"] for r in rows)
    platform_counts = Counter(r["platform"] for r in rows)
    path_counts = Counter(r["path"] for r in rows)
    device_counts = Counter(r["device_type"] for r in rows)
    method_counts = Counter(r["detection_method"] for r in rows)
    conf_all = [r["confidence"] for r in rows]

    labelled = [r for r in rows if r["dir_label"]]
    disagreements = [r for r in labelled if r["vendor"] != r["dir_label"]]
    by_label: dict[str, Counter] = defaultdict(Counter)
    for r in labelled:
        by_label[r["dir_label"]][r["vendor"]] += 1

    unsupported = [r for r in rows if not r["dir_label"]]
    unsupported_labelled_as_supported = [
        r for r in unsupported if r["vendor"] in SUPPORTED_VENDORS
    ]

    ingestible = [r for r in rows if r["e01_ingestible"]]
    e02_valid = [r for r in ingestible if r["e02_is_valid"] == "True"]

    summary = {
        "engine": "03_vendor_detection",
        "dataset_root": str(DATASET),
        "files_total": len(rows),
        "bytes_total": sum(r["size_bytes"] for r in rows),
        "utf8_decode_failures": sum(1 for r in rows if r["decode_note"]),
        "detection": {
            "vendor_distribution": dict(vendor_counts.most_common()),
            "platform_distribution": dict(platform_counts.most_common()),
            "device_type_distribution": dict(device_counts.most_common()),
            "detection_method_distribution": dict(method_counts.most_common()),
            "path_distribution": dict(path_counts),
            "confidence": {
                "p50": pct(conf_all, 0.50),
                "p95": pct(conf_all, 0.95),
                "p99": pct(conf_all, 0.99),
                "min": min(conf_all),
                "max": max(conf_all),
                "zero_count": sum(1 for c in conf_all if c == 0.0),
                "mean": round(statistics.mean(conf_all), 4),
            },
            "files_with_hostname": sum(1 for r in rows if r["hostname"]),
            "files_with_firmware": sum(1 for r in rows if r["firmware_version"]),
            "files_with_no_evidence": sum(1 for r in rows if r["evidence_count"] == 0),
            "unknown_vendor_files": vendor_counts.get("unknown", 0),
        },
        "path_comparison": {
            "files_vendor_or_platform_differs": sum(
                1 for r in rows if r["path_disagreement"]
            ),
            "regex_vendor_distribution": dict(
                Counter(r["rx_vendor"] for r in rows).most_common()
            ),
        },
        "truncation": {
            "files_diverged_at_6000_chars": sum(1 for r in rows if r["truncation_diverged"]),
            "trunc_unknown_files": sum(1 for r in rows if r["trunc_vendor"] == "unknown"),
            "full_unknown_files": sum(1 for r in rows if r["vendor"] == "unknown"),
        },
        "directory_label_comparison": {
            "note": "directory-derived label is NOT authoritative ground truth; "
                    "ML/model quality is deferred to the ML evaluation phase. "
                    "Reported as disagreement counts only.",
            "labelled_files": len(labelled),
            "disagreements": len(disagreements),
            "per_label_counts": {
                k: dict(v.most_common()) for k, v in sorted(by_label.items())
            },
            "unsupported_vendor_files": len(unsupported),
            "unsupported_files_labelled_as_supported_vendor": len(
                unsupported_labelled_as_supported
            ),
            "unsupported_files_labelled_unknown": sum(
                1 for r in unsupported if r["vendor"] == "unknown"
            ),
            "examples_labelled_unsupported_but_supported": [
                {"relpath": r["relpath"], "vendor": r["vendor"],
                 "confidence": r["confidence"], "path": r["path"]}
                for r in sorted(unsupported_labelled_as_supported,
                                key=lambda x: -x["confidence"])[:15]
            ],
        },
        "determinism": {"mismatches": determinism_mismatches},
        "timing_ms": {
            "deployed_path_p50": pct(ml_times, 0.50),
            "deployed_path_p95": pct(ml_times, 0.95),
            "deployed_path_p99": pct(ml_times, 0.99),
            "deployed_path_mean": round(statistics.mean(ml_times), 4),
            "regex_path_p50": pct(rx_times, 0.50),
            "regex_path_p95": pct(rx_times, 0.95),
            "regex_path_p99": pct(rx_times, 0.99),
            "regex_path_mean": round(statistics.mean(rx_times), 4),
        },
        "cross_engine_join": {
            "e01_ingestible": len(ingestible),
            "e01_ingestible_and_e02_valid": len(e02_valid),
            "e01_ingestible_unknown_vendor": sum(
                1 for r in ingestible if r["vendor"] == "unknown"
            ),
            "e01_ingestible_low_confidence_lt_0_6": sum(
                1 for r in ingestible if 0.0 < r["confidence"] < 0.6
            ),
            "e01_ingestible_vendor_distribution": dict(
                Counter(r["vendor"] for r in ingestible).most_common()
            ),
        },
        "top_evidence_files": [
            {"relpath": r["relpath"], "vendor": r["vendor"],
             "evidence": r["evidence_count"], "confidence": r["confidence"]}
            for r in sorted(rows, key=lambda x: -x["evidence_count"])[:10]
        ],
    }

    (OUT_DIR / "dataset_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
