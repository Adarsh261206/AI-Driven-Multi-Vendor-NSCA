"""Engine 05 dataset sweep - normalize every real dataset file.

Read-only over C:\\Users\\priye\\Downloads\\SIH Config\\final-dataset.
Writes artifacts/engine_validation/05_normalization/{dataset_results.csv,dataset_summary.json}
"""

from __future__ import annotations

import csv
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.engines.normalization import NormalizationEngine  # noqa: E402

ROOT = Path(r"C:\Users\priye\Downloads\SIH Config\final-dataset")
OUT = Path(__file__).resolve().parents[2] / "artifacts" / "engine_validation" / "05_normalization"
OUT.mkdir(parents=True, exist_ok=True)

LABEL_MAP = {
    "cisco": ("cisco", "ios_xe"),
    "juniper": ("juniper", "junos"),
    "fortinet": ("fortinet", "fortios"),
}
COMMENT_RE = re.compile(r"^\s*[!#]")


def flatten(d: dict, prefix: str = "") -> dict:
    out: dict = {}
    for k, v in d.items():
        p = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, p + "."))
        else:
            out[p] = v
    return out


def main() -> int:
    eng = NormalizationEngine()
    rows: list[dict] = []
    files = sorted(p for p in ROOT.rglob("*") if p.is_file())
    t_all = time.perf_counter()

    for p in files:
        rel = str(p.relative_to(ROOT))
        top = rel.split("\\")[0].lower()
        label = LABEL_MAP.get(top)
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            rows.append({"relpath": rel, "read_error": repr(e)})
            continue
        lines = txt.splitlines()
        comment_lines = [ln for ln in lines if COMMENT_RE.match(ln)]
        body = [ln for ln in lines if not COMMENT_RE.match(ln)]

        if label:
            vendor, platform = label
        else:
            vendor, platform = top, "unknown"

        t0 = time.perf_counter()
        r = eng.normalize({"raw_lines": lines}, vendor, platform)
        ms = (time.perf_counter() - t0) * 1000

        # second pass (determinism)
        r2 = eng.normalize({"raw_lines": lines}, vendor, platform)
        deterministic = r.to_dict() == r2.to_dict()

        # comment sensitivity: does deleting comments change the normalized output?
        comment_sensitive = ""
        if comment_lines:
            rc = eng.normalize({"raw_lines": body}, vendor, platform)
            comment_sensitive = str(rc.universal_config != r.universal_config)

        flat = flatten(r.universal_config)
        row = {
            "relpath": rel,
            "dir_label": top,
            "supported": bool(label),
            "vendor_used": vendor,
            "platform_used": platform,
            "size_bytes": len(txt.encode("utf-8", "replace")),
            "line_count": len(lines),
            "comment_lines": len(comment_lines),
            "result_type": r.result_type.value,
            "mappings": len(r.mappings),
            "unmapped": len(r.unmapped_paths),
            "unmapped_concepts": len(r.unmapped_concepts),
            "norm_leaf_values": len(flat),
            "deterministic": deterministic,
            "comment_sensitive": comment_sensitive,
            "hostname": flat.get("device.hostname"),
            "http_enabled": flat.get("management.http.enabled"),
            "https_enabled": flat.get("management.https.enabled"),
            "ssh_enabled": flat.get("management.ssh.enabled"),
            "ssh_version": flat.get("management.ssh.version"),
            "vty_transport": flat.get("management.vty.transport"),
            "snmp_version": flat.get("services.snmp.version"),
            "snmp_enabled": flat.get("services.snmp.enabled"),
            "logging_level": flat.get("logging.level"),
            "ntp_configured": flat.get("ntp.configured"),
            "acl_applied": flat.get("access_control.acl_applied"),
            "syslog_enabled": flat.get("monitoring.syslog.enabled"),
            "audit_trail_enabled": flat.get("monitoring.audit_trail.enabled"),
            "net_access_control": flat.get("networking.access_control.enabled"),
            "confidences": ",".join(str(c) for c in sorted({m.confidence for m in r.mappings})),
            "elapsed_ms": round(ms, 3),
        }
        rows.append(row)

    elapsed = time.perf_counter() - t_all

    fields = sorted({k for r in rows for k in r})
    with open(OUT / "dataset_results.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    ok = [r for r in rows if "result_type" in r]
    supported = [r for r in ok if r["supported"]]
    unsupported = [r for r in ok if not r["supported"]]

    def agg(sub):
        return {
            "files": len(sub),
            "success": sum(1 for r in sub if r["result_type"] == "success"),
            "partial": sum(1 for r in sub if r["result_type"] == "partial"),
            "failed": sum(1 for r in sub if r["result_type"] == "failed"),
            "mappings_sum": sum(r["mappings"] for r in sub),
            "mappings_min": min((r["mappings"] for r in sub), default=0),
            "mappings_max": max((r["mappings"] for r in sub), default=0),
            "unmapped_concepts_sum": sum(r.get("unmapped_concepts", 0) or 0 for r in sub),
            "leaf_values_sum": sum(r["norm_leaf_values"] for r in sub),
            "unmapped_sum": sum(r["unmapped"] for r in sub),
            "nondeterministic": sum(1 for r in sub if r["deterministic"] is False),
            "files_with_comment_lines": sum(1 for r in sub if r["comment_lines"] > 0),
            "comment_sensitive": sum(1 for r in sub if r["comment_sensitive"] == "True"),
            "comment_insensitive": sum(1 for r in sub if r["comment_sensitive"] == "False"),
            "elapsed_ms_sum": round(sum(r["elapsed_ms"] for r in sub), 1),
            "elapsed_ms_max": round(max((r["elapsed_ms"] for r in sub), default=0), 1),
        }

    by_label = {}
    for lab in ("cisco", "juniper", "fortinet", "arista", "a10", "f5", "frr",
                "napalm", "paloalto"):
        sub = [r for r in ok if r["dir_label"] == lab]
        if sub:
            by_label[lab] = agg(sub)

    confidence_sets = sorted({r["confidences"] for r in ok})
    summary = {
        "engine": "05_normalization",
        "dataset_root": str(ROOT),
        "files_total": len(rows),
        "files_normalized": len(ok),
        "bytes_total": sum(r.get("size_bytes", 0) or 0 for r in rows),
        "label_mapping": {k: list(v) for k, v in LABEL_MAP.items()},
        "overall": agg(ok),
        "supported_labels": agg(supported),
        "unsupported_labels": agg(unsupported),
        "by_label": by_label,
        "confidence_sets_seen": confidence_sets,
        "unsupported_failed_count": sum(1 for r in unsupported
                                        if r["result_type"] == "failed"),
        "elapsed_s": round(elapsed, 2),
    }
    (OUT / "dataset_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2)[:4000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
