"""E04 dataset sweep probe - throwaway, deleted before final verification."""
from __future__ import annotations

import csv
import json
import pathlib
import re
import statistics
import sys
import time

sys.path.insert(0, ".")

from app.engines.parsing.cisco import CiscoIOSParser  # noqa: E402
from app.engines.parsing.juniper import JunosParser  # noqa: E402
from app.engines.parsing.fortinet import FortiOSParser  # noqa: E402

C, J, F = CiscoIOSParser(), JunosParser(), FortiOSParser()
PARSERS = {"cisco": C, "juniper": J, "fortinet": F}
LABEL_MAP = {"cisco": "cisco", "juniper": "juniper", "fortinet": "fortinet"}

ROOT = pathlib.Path(r"C:\Users\priye\Downloads\SIH Config\final-dataset")
OUT = pathlib.Path("artifacts/engine_validation/03_detection/dataset_results.csv")

VALUE_LIKE = re.compile(r"^[0-9][0-9.:/]*$")
STRUCT_KEY = re.compile(r"[{};]")


def walk(nodes):
    n = 0
    for x in nodes:
        n += 1
        n += walk(x.children)
    return n


def depth(nodes, d=1):
    m = d
    for x in nodes:
        m = max(m, depth(x.children, d + 1))
    return m


def collect_nodes(nodes, out):
    for x in nodes:
        out.append(x)
        collect_nodes(x.children, out)


def stats(r):
    nodes = []
    collect_nodes(r.parse_tree, nodes)
    represented = set()
    for n in nodes:
        represented.add(n.raw_text)
    unk_texts = {u.raw_text for u in r.unknown_sections}
    value_keys = sum(1 for n in nodes if n.key and VALUE_LIKE.match(n.key))
    struct_keys = sum(1 for n in nodes if n.key and STRUCT_KEY.search(n.key))
    quoted = sum(1 for n in nodes if n.key and '"' in n.key)
    negated = sum(1 for n in nodes if getattr(n, "negated", False))
    return {
        "nodes": len(nodes),
        "roots": len(r.parse_tree),
        "depth": depth(r.parse_tree),
        "err": len(r.parse_errors),
        "warn": len(r.parse_warnings),
        "unk": len(r.unknown_sections),
        "value_like_keys": value_keys,
        "struct_keys": struct_keys,
        "quoted_keys": quoted,
        "negated": negated,
        "_repr": represented,
        "_lines": {n.line_number for n in nodes if n.line_number},
        "_unk": unk_texts,
    }


def sig(r):
    nodes = []
    collect_nodes(r.parse_tree, nodes)
    return tuple((n.key, n.value, n.line_number) for n in nodes)


det = {}
with OUT.open(newline="", encoding="utf-8") as fh:
    for row in csv.DictReader(fh):
        det[row["relpath"]] = row

files = sorted(p for p in ROOT.rglob("*") if p.is_file())
rows = []
per_parser_times = {"cisco": [], "juniper": [], "fortinet": []}
cross = {k: {"n": 0, "silent": 0, "empty": 0} for k in PARSERS}
cross_ing = {k: {"n": 0, "silent": 0, "empty": 0} for k in PARSERS}
detected_chain = {"match": 0, "mismatch": 0, "unsupported": 0}
examples_mismatch = []
max_depth_seen = 0
CISCO_SECTIONS = {"interface", "line", "router", "vlan", "acl", "crypto",
                  "key_chain", "switch", "nested", "control-plane"}


def new_nest():
    return {"files": 0, "sections_total": 0, "sections_nested": 0,
            "files_with_nested_sections": 0, "by_type": {}, "examples": []}


cisco_nest = new_nest()
cisco_nest_ing = new_nest()
t0 = time.perf_counter()

for p in files:
    rel = str(p.relative_to(ROOT))
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        rows.append({"relpath": rel, "read_error": str(e)})
        continue
    lines = txt.splitlines()
    top = rel.split("\\")[0].lower()
    label = LABEL_MAP.get(top)
    meaningful = [ln for ln in lines if ln.strip() and not ln.strip().startswith(("!", "#"))]

    row = {
        "relpath": rel,
        "dir_label": label or top,
        "supported": label is not None,
        "size_bytes": len(txt.encode("utf-8", "replace")),
        "line_count": len(lines),
        "meaningful_lines": len(meaningful),
        "det_vendor": det.get(rel, {}).get("vendor", ""),
        "det_ingestible": det.get(rel, {}).get("e01_ingestible", ""),
    }

    # label-matched parser metrics
    if label:
        par = PARSERS[label]
        t = time.perf_counter()
        try:
            r = par.parse(txt)
            ms = (time.perf_counter() - t) * 1000
        except Exception as e:
            row.update({"parse_ms": None, "parse_exc": type(e).__name__,
                        "nodes": 0, "roots": 0, "depth": 0, "err": 0,
                        "warn": 0, "unk": 0, "value_like_keys": 0,
                        "struct_keys": 0, "quoted_keys": 0,
                        "negated_nodes": 0,
                        "unrepresented_meaningful_lines": None,
                        "to_dict": "skipped", "deterministic": "skipped"})
            r = None
            s = None
            ms = None
        else:
            per_parser_times[label].append(ms)
            s = stats(r)
            represented_lines: set[int] = set(s["_lines"])
            for u in r.unknown_sections:
                represented_lines.update(u.line_numbers)
            # E04: banner body lines are opaque payload, not configuration;
            # they are exempt from the line-fidelity count (definition change
            # vs the pre-fix sweep, where banner bodies became junk nodes).
            exempt: set[int] = set()
            if label == "cisco":
                _starts, _body0, _unt = CiscoIOSParser._extract_banners(lines)
                exempt = {i + 1 for i in _body0}
            if label == "juniper":
                def structural(ln: str) -> bool:
                    return ln.strip() == "}" or ln.strip().startswith("};")
            elif label == "fortinet":
                def structural(ln: str) -> bool:
                    return ln.strip() in ("end", "next")
            else:
                def structural(ln: str) -> bool:
                    return False
            unrep = sum(1 for i, ln in enumerate(lines, 1)
                        if ln.strip() and not ln.strip().startswith(("!", "#"))
                        and i not in represented_lines and i not in exempt
                        and not structural(ln))
            row.update({
                "parse_ms": round(ms, 3),
                "nodes": s["nodes"], "roots": s["roots"], "depth": s["depth"],
                "err": s["err"], "warn": s["warn"], "unk": s["unk"],
                "value_like_keys": s["value_like_keys"],
                "struct_keys": s["struct_keys"],
                "quoted_keys": s["quoted_keys"],
                "negated_nodes": s["negated"],
                "unrepresented_meaningful_lines": unrep,
            })
        if r is not None:
            max_depth_seen = max(max_depth_seen, s["depth"])
            # banner (cisco)
            if label == "cisco":
                banner_idx = [i for i, ln in enumerate(lines) if ln.strip().lower().startswith("banner ")]
                row["banner_lines"] = len(banner_idx)
                row["no_lines"] = sum(1 for ln in lines if re.match(r"^\s*no\s+\S", ln))
                allnodes = []
                collect_nodes(r.parse_tree, allnodes)
                sections = [n for n in allnodes if n.key in CISCO_SECTIONS]
                nested = [n for n in sections if n.path]
                row["sections_total"] = len(sections)
                row["sections_nested"] = len(nested)
                row["sections_root"] = len(sections) - len(nested)
                ingestible = row["det_ingestible"] == "True"
                for acc in ([cisco_nest] + ([cisco_nest_ing] if ingestible else [])):
                    acc["files"] += 1
                    acc["sections_total"] += len(sections)
                    acc["sections_nested"] += len(nested)
                    if nested:
                        acc["files_with_nested_sections"] += 1
                    for n in nested:
                        acc["by_type"][n.key] = acc["by_type"].get(n.key, 0) + 1
                if nested and len(cisco_nest["examples"]) < 12:
                    n0 = nested[0]
                    cisco_nest["examples"].append(
                        {"file": rel, "key": n0.key, "value": n0.value,
                         "path": n0.path, "line_number": n0.line_number})
            if label == "juniper":
                row["set_lines"] = sum(1 for ln in lines if ln.strip().startswith("set "))
                row["brace_lines"] = sum(1 for ln in lines if ln.rstrip().endswith("{"))
            if label == "fortinet":
                row["set_lines"] = sum(1 for ln in lines if ln.strip().startswith("set "))
            try:
                r.to_dict()
                row["to_dict"] = "ok"
            except Exception as e:
                row["to_dict"] = type(e).__name__
            # determinism second pass
            try:
                row["deterministic"] = str(sig(par.parse(txt)) == sig(r))
            except Exception as e:
                row["deterministic"] = type(e).__name__
        # detected-vendor chain: which parser would the pipeline select?
        # E04: models the post-E03 gate — unsupported/unknown vendors STOP
        # after detection (no parser); they no longer fall back to Cisco.
        dv = row["det_vendor"]
        if dv:
            if LABEL_MAP.get(dv):
                chain_parser = dv
                row["chain_parser"] = chain_parser
                if chain_parser == label:
                    detected_chain["match"] += 1
                else:
                    detected_chain["mismatch"] += 1
                    if len(examples_mismatch) < 15:
                        examples_mismatch.append((rel, dv, chain_parser, label))
            else:
                row["chain_parser"] = "STOPPED"
                detected_chain["stopped"] = detected_chain.get("stopped", 0) + 1
                detected_chain["det_unsupported_or_unknown"] = \
                    detected_chain.get("det_unsupported_or_unknown", 0) + 1

    # cross-vendor: parse every file with every parser
    cross_row = {}
    for name, par in PARSERS.items():
        t = time.perf_counter()
        try:
            r2 = par.parse(txt)
            ms2 = (time.perf_counter() - t) * 1000
            s2 = stats(r2)
            cross_row[f"{name}_nodes"] = s2["nodes"]
            cross_row[f"{name}_err"] = s2["err"]
            cross_row[f"{name}_unk"] = s2["unk"]
            cross_row[f"{name}_ms"] = round(ms2, 2)
            if label is not None and label != name:
                cross[name]["n"] += 1
                if s2["nodes"] > 0 and s2["err"] == 0:
                    cross[name]["silent"] += 1
                if s2["nodes"] == 0:
                    cross[name]["empty"] += 1
                if row.get("det_ingestible") == "True":
                    cross_ing[name]["n"] += 1
                    if s2["nodes"] > 0 and s2["err"] == 0:
                        cross_ing[name]["silent"] += 1
                    if s2["nodes"] == 0:
                        cross_ing[name]["empty"] += 1
        except Exception as e:
            cross_row[f"{name}_exc"] = type(e).__name__
    row.update(cross_row)
    rows.append(row)

elapsed = time.perf_counter() - t0
out = pathlib.Path("artifacts/engine_validation/04_parsing")
out.mkdir(parents=True, exist_ok=True)
with (out / "dataset_results.csv").open("w", newline="", encoding="utf-8") as fh:
    keys = sorted({k for r in rows for k in r})
    w = csv.DictWriter(fh, fieldnames=keys)
    w.writeheader()
    w.writerows(rows)

supported = [r for r in rows if r.get("supported")]
summary = {
    "engine": "04_parsing",
    "dataset_root": str(ROOT),
    "files_total": len(rows),
    "bytes_total": sum(r.get("size_bytes", 0) or 0 for r in rows),
    "supported_label_files": len(supported),
    "label_counts": {k: sum(1 for r in rows if r.get("dir_label") == k) for k in
                     ("cisco", "juniper", "fortinet", "arista", "a10", "f5", "frr", "napalm", "paloalto")},
    "label_parser_totals": {
        k: {
            "files": sum(1 for r in supported if r["dir_label"] == k),
            "nodes": sum(r.get("nodes", 0) or 0 for r in supported if r["dir_label"] == k),
            "err": sum(r.get("err", 0) or 0 for r in supported if r["dir_label"] == k),
            "warn": sum(r.get("warn", 0) or 0 for r in supported if r["dir_label"] == k),
            "unk": sum(r.get("unk", 0) or 0 for r in supported if r["dir_label"] == k),
            "negated_nodes": sum(r.get("negated_nodes", 0) or 0 for r in supported if r["dir_label"] == k),
            "value_like_keys": sum(r.get("value_like_keys", 0) or 0 for r in supported if r["dir_label"] == k),
            "struct_keys": sum(r.get("struct_keys", 0) or 0 for r in supported if r["dir_label"] == k),
            "quoted_keys": sum(r.get("quoted_keys", 0) or 0 for r in supported if r["dir_label"] == k),
            "unrep_lines": sum(r.get("unrepresented_meaningful_lines", 0) or 0 for r in supported if r["dir_label"] == k),
            "files_with_err": sum(1 for r in supported if r["dir_label"] == k and (r.get("err", 0) or 0) > 0),
            "files_with_warn": sum(1 for r in supported if r["dir_label"] == k and (r.get("warn", 0) or 0) > 0),
            "files_with_unk": sum(1 for r in supported if r["dir_label"] == k and (r.get("unk", 0) or 0) > 0),
            "files_with_unrep": sum(1 for r in supported if r["dir_label"] == k and (r.get("unrepresented_meaningful_lines", 0) or 0) > 0),
            "files_with_value_like_keys": sum(1 for r in supported if r["dir_label"] == k and (r.get("value_like_keys", 0) or 0) > 0),
            "files_to_dict_exc": sum(1 for r in supported if r["dir_label"] == k and r.get("to_dict") != "ok"),
            "files_nondeterministic": sum(1 for r in supported if r["dir_label"] == k and r.get("deterministic") == "False"),
        } for k in ("cisco", "juniper", "fortinet")
    },
    "cisco_negation_lines": sum(r.get("no_lines", 0) or 0 for r in supported if r["dir_label"] == "cisco"),
    "cisco_files_with_banner": sum(1 for r in supported if r["dir_label"] == "cisco" and (r.get("banner_lines", 0) or 0) > 0),
    "cisco_section_nesting": cisco_nest_ing,
    "cisco_section_nesting_all_cisco_files": cisco_nest,
    "ingestible_supported_totals": {
        k: {
            "files": sum(1 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True"),
            "nodes": sum(r.get("nodes", 0) or 0 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True"),
            "err": sum(r.get("err", 0) or 0 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True"),
            "warn": sum(r.get("warn", 0) or 0 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True"),
            "unk": sum(r.get("unk", 0) or 0 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True"),
            "negated_nodes": sum(r.get("negated_nodes", 0) or 0 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True"),
            "unrep_lines": sum(r.get("unrepresented_meaningful_lines", 0) or 0 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True"),
            "files_with_err": sum(1 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True" and (r.get("err", 0) or 0) > 0),
            "files_with_warn": sum(1 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True" and (r.get("warn", 0) or 0) > 0),
            "files_with_unk": sum(1 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True" and (r.get("unk", 0) or 0) > 0),
            "negation_lines": sum(r.get("no_lines", 0) or 0 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True"),
            "files_with_banner": sum(1 for r in supported if r["dir_label"] == k and r.get("det_ingestible") == "True" and (r.get("banner_lines", 0) or 0) > 0),
        } for k in ("cisco", "juniper", "fortinet")
    },
    "ingestible_unsupported_files": sum(1 for r in rows if r.get("supported") is False and r.get("det_ingestible") == "True"),
    "ingestible_unsupported_chain_parser": {
        k: sum(1 for r in rows if r.get("supported") is False
               and r.get("det_ingestible") == "True"
               and ((r.get("det_vendor") if r.get("det_vendor") in LABEL_MAP else "cisco") == k))
        for k in ("cisco", "juniper", "fortinet")
    },
    "juniper_files_set_style": sum(1 for r in supported if r["dir_label"] == "juniper" and (r.get("set_lines", 0) or 0) > 0),
    "juniper_files_braces": sum(1 for r in supported if r["dir_label"] == "juniper" and (r.get("brace_lines", 0) or 0) > 0),
    "max_parse_depth": max_depth_seen,
    "cross_vendor": cross,
    "cross_vendor_ingestible": cross_ing,
    "detected_vendor_chain": detected_chain,
    "detected_vendor_mismatch_examples": examples_mismatch,
    "timing_ms": {
        k: {
            "n": len(v),
            "p50": round(statistics.median(v), 3) if v else None,
            "p95": round(sorted(v)[max(0, int(len(v) * 0.95) - 1)], 3) if v else None,
            "max": round(max(v), 3) if v else None,
        } for k, v in per_parser_times.items()
    },
    "elapsed_s": round(elapsed, 1),
}
(out / "dataset_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
print(json.dumps(summary, indent=2))
print("SWEEP DONE")


