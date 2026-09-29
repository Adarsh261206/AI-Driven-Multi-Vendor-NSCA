"""Engine 02 post-fix performance measurements (report evidence).

Outputs: backend/artifacts/engine_validation/02_validation/performance_postfix.json
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))

DATASET = Path(r"C:\Users\priye\Downloads\SIH Config\final-dataset")
OUT = (BACKEND / "artifacts" / "engine_validation" / "02_validation"
       / "performance_postfix.json")


def pct(vals, q):
    o = sorted(vals)
    return round(o[min(len(o) - 1, int(q * len(o)))], 4)


def bench(fn, samples=30):
    ts = []
    for _ in range(samples):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1000)
    return {
        "p50_ms": pct(ts, 0.50),
        "p95_ms": pct(ts, 0.95),
        "p99_ms": pct(ts, 0.99),
        "max_ms": round(max(ts), 4),
        "samples": samples,
    }


def main() -> int:
    from app.engines.validation import ConfigurationValidator

    v = ConfigurationValidator()
    out: dict = {"engine": "02_configuration_validation_postfix"}

    # --- size scaling (1 KiB / 100 KiB / 1 MiB) -------------------------
    unit = "interface GigabitEthernet0/1\n description link up\n no shutdown\n"
    rows = []
    for size in (1024, 102400, 1048576):
        content = (unit * (size // len(unit) + 1))[:size]
        assert len(content) == size
        rows.append({"chars": size, **bench(lambda c=content: v.validate(c))})
    out["size_scaling"] = rows
    out["size_scaling_ratio_1mib_over_1kib_p50"] = round(
        rows[-1]["p50_ms"] / max(rows[0]["p50_ms"], 1e-9), 1)

    # --- ReDoS / pathological payloads ----------------------------------
    redos = {
        "long_equals": "password=" + "A" * 200000,
        "long_user_chain": "user " + "u " * 100000,
        "repeated_secret": "secret " + "s" * 100000,
        "nested_ws": "username" + " " * 50000 + "a b c",
        "long_line_1m": "x" * 1000000,
        "bangs_200k": "!" * 200000,
        "zwsp_100k": "\u200b" * 100000,
    }
    out["redos_payloads"] = {
        k: {"chars": len(p),
            **bench(lambda p=p: v.validate(p), samples=10)}
        for k, p in redos.items()
    }

    # --- large corpus files + linearity bisection ------------------------
    chic = DATASET / "Juniper" / "Routers" / "MX-Series" / "chic.conf"
    lines = chic.read_text(encoding="utf-8", errors="replace").splitlines()
    out["corpus_large_file"] = {
        "relpath": "Juniper/Routers/MX-Series/chic.conf",
        "bytes": chic.stat().st_size,
        "lines": len(lines),
        **bench(lambda: v.validate("\n".join(lines)), samples=5),
    }
    bisection = []
    for n in (800, 1600, 3200, 6400, 16221):
        sample = "\n".join(lines[:n])
        t0 = time.perf_counter()
        v.validate(sample)
        bisection.append({"lines": n,
                          "ms": round((time.perf_counter() - t0) * 1000, 3)})
    out["linearity_bisection"] = bisection

    # --- O(n^2) guard: many SNMP blocks ----------------------------------
    unit5 = ["config snmp community", '    edit "public"',
             "        set status enable", "end", "set system services telnet"]
    blocky = "\n".join(unit5 * 1000)  # 5000 lines / 1000 blocks
    out["snmp_block_guard_5000_lines"] = {
        "lines": 5000,
        "blocks": 1000,
        **bench(lambda: v.validate(blocky), samples=5),
    }

    # --- executor-shaped call (bare validate, default flags) -------------
    sample_small = "hostname R1\ninterface GigabitEthernet0/0\n description WAN"
    out["executor_shaped_call"] = bench(lambda: v.validate(sample_small), samples=100)

    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
