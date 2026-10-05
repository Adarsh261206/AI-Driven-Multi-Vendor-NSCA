"""Engine 06 dataset sweep - real config lines through the learn/lookup loop.

Read-only over C:\\Users\\priye\\Downloads\\SIH Config\\final-dataset.

E06 contract exercised here (the metrics are now contract CHECKS, not just
descriptive numbers):
  * a real universal model path is REQUIRED. Each eligible line is resolved
    through the real E05 normalizer; a line the deterministic pipeline cannot
    resolve is recorded as unmapped and is never invented into the KB.
  * exact identity only. Absorption of a caller line into a DIFFERENT stored
    raw_syntax (fuzzy absorption / wrong-meaning absorption) must be 0.
  * lookup is total: hostile argument types are a miss, never a crash.
  * cross-vendor isolation: a line stored for vendor A must never resolve
    under vendor B.
  * deterministic ordering: identical input yields an identical ordered list
    of identities across independent runs.
  * EDIT never confirms and never fabricates confidence; REJECT retains the
    row and unconfirms it.

Pass 1  per file: resolve + ingest + probe identity
Pass 2  cross-file, same vendor (A built, queried with B, then B ingested)
Pass 3  cross-vendor isolation
Pass 4  contract checks over real ingested data + hostile/boundary probes

Writes artifacts/engine_validation/06_knowledge_base/
  {dataset_results.csv,dataset_summary.json,contract_results.json}
Exit code 1 if any contract check fails.
"""

from __future__ import annotations

import csv
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.ai import kb_domain as dom
from app.ai.knowledge_base import KnowledgeBase
from app.engines.normalization import NormalizationEngine

ROOT = Path(r"C:\Users\priye\Downloads\SIH Config\final-dataset")
OUT = Path(__file__).resolve().parents[2] / "artifacts" / "engine_validation" / "06_knowledge_base"
OUT.mkdir(parents=True, exist_ok=True)

LABEL_MAP = {
    "cisco": ("cisco", "ios_xe"),
    "juniper": ("juniper", "junos"),
    "fortinet": ("fortinet", "fortios"),
    "paloalto": ("paloalto", "panos"),
    "arista": ("arista", "eos"),
    "f5": ("f5", "bigip"),
    "a10": ("a10", "a10os"),
    "frr": ("frr", "frr"),
    "napalm": ("napalm", "multi"),
}
MAX_LINES_PER_FILE = 120
MAX_CHARS = 200
CROSS_FILE_LABELS = ("cisco", "juniper", "fortinet")
ISOLATION_LABELS = ("cisco", "juniper", "fortinet", "paloalto")
ISOLATION_LINES_PER_LABEL = 60
SWEEP_ACTOR = "sweep:dataset"
NORMALIZER = NormalizationEngine()


def is_comment(ln: str) -> bool:
    return not ln or ln.lstrip().startswith(("!", "#", "/", "*", "-"))


def eligible_lines(path: Path, cap: int = MAX_LINES_PER_FILE) -> list[str]:
    try:
        txt = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in txt.splitlines():
        ln = raw.strip()
        if is_comment(ln) or len(ln) > MAX_CHARS or ln in seen:
            continue
        seen.add(ln)
        out.append(ln)
        if len(out) >= cap:
            break
    return out


def resolve(ln: str, vendor: str, platform: str) -> dict | None:
    """Resolve ONE real config line through the deterministic pipeline.

    Returns the first mapping the real normalizer produced, or None when the
    pipeline cannot map the line. Nothing is invented: a line with no real
    model path is recorded as unmapped, never stored.
    """
    try:
        result = NORMALIZER.normalize({"raw_lines": [ln]}, vendor, platform)
    except Exception:
        return None
    for mapping in result.normalized_values:
        path = mapping.get("model_path")
        if isinstance(path, str) and dom.is_valid_model_path(path):
            return {"path": path, "value": mapping.get("value")}
    return None


def load_into(kb: KnowledgeBase, vendor: str, platform: str,
              resolved: list[tuple[str, dict]]) -> tuple[int, int, int, float]:
    """Ingest resolved lines; return (exact_dup, fuzzy_dup, created, elapsed_s).

    exact_dup: the line already existed verbatim (dedupe path, versioned in place).
    fuzzy_dup: the line was merged into a row whose raw_syntax differs. E06
               requires this to stay 0: lookup is exact identity, so a caller's
               syntax can never be absorbed into someone else's meaning.
    created:   new rows appended.
    """
    exact_dup = fuzzy_dup = created = 0
    t0 = time.perf_counter()
    for ln, hit in resolved:
        before = kb.lookup(vendor, platform, ln, require_confirmed=False)
        size_before = len(kb.list_mappings())
        kb.create(
            vendor, platform, ln,
            f"auto-resolved {hit['path']}={hit['value']!r} from deterministic parsing",
            universal_model_path=hit["path"],
            actor=SWEEP_ACTOR,
        )
        if len(kb.list_mappings()) > size_before:
            created += 1
        if before is not None:
            if before.raw_syntax.strip() == ln:
                exact_dup += 1
            else:
                fuzzy_dup += 1
    return exact_dup, fuzzy_dup, created, time.perf_counter() - t0


def probe(kb: KnowledgeBase, vendor: str, platform: str,
          lines: list[str]) -> dict:
    exact = collision = miss = 0
    t0 = time.perf_counter()
    for ln in lines:
        got = kb.lookup(vendor, platform, ln, require_confirmed=False)
        if got is None:
            miss += 1
        elif got.raw_syntax.strip() == ln:
            exact += 1
        else:
            collision += 1
    return {
        "lookup_exact": exact,
        "lookup_collision": collision,
        "lookup_miss": miss,
        "lookup_ms": round((time.perf_counter() - t0) * 1000, 3),
    }


def resolve_all(vendor: str, platform: str,
                lines: list[str]) -> tuple[list[tuple[str, dict]], int]:
    resolved: list[tuple[str, dict]] = []
    unmapped = 0
    for ln in lines:
        hit = resolve(ln, vendor, platform)
        if hit is None:
            unmapped += 1
        else:
            resolved.append((ln, hit))
    return resolved, unmapped


def contract_checks(kb: KnowledgeBase, vendor: str, platform: str,
                    resolved: list[tuple[str, dict]]) -> list[dict]:
    """Contract CHECKS over real ingested data (each records real evidence)."""
    checks: list[dict] = []
    sample = [ln for ln, _ in resolved[:25]]

    # C1 lookup is total: hostile types are a miss, never an exception.
    crashes = []
    for hostile in (None, 0, 1.5, [], ["cisco"], {"v": 1}, object(), b"bytes", True):
        try:
            if kb.lookup(hostile, platform, "x") is not None:
                crashes.append(f"hostile vendor {type(hostile).__name__} -> hit")
            if kb.lookup(vendor, hostile, "x") is not None:
                crashes.append(f"hostile platform {type(hostile).__name__} -> hit")
            if kb.lookup(vendor, platform, hostile) is not None:
                crashes.append(f"hostile syntax {type(hostile).__name__} -> hit")
        except Exception as exc:  # noqa: BLE001 - recording the failure mode
            crashes.append(f"{type(hostile).__name__} -> {type(exc).__name__}")
    checks.append({
        "id": "C1", "name": "lookup is total (hostile types are a miss)",
        "probes": 9 * 3, "violations": len(crashes), "detail": crashes[:5],
    })

    # C2 exact identity: every lookup returns the row stored for that exact line.
    wrong = []
    for ln in sample:
        got = kb.lookup(vendor, platform, ln, require_confirmed=False)
        if got is not None and got.raw_syntax.strip() != ln:
            wrong.append(ln[:60])
    checks.append({
        "id": "C2", "name": "exact identity (no wrong-meaning absorption)",
        "probes": len(sample), "violations": len(wrong), "detail": wrong[:5],
    })

    # C3 unconfirmed rows are never auto-reused.
    untrusted = []
    for row in kb.list_mappings(confirmed_only=False):
        trusted = dom.is_trusted(admin_confirmed=row.admin_confirmed,
                                 confidence=row.confidence)
        if row.confidence < dom.KB_TRUST_THRESHOLD and trusted:
            untrusted.append(row.id)
    checks.append({
        "id": "C3", "name": "trust threshold honoured (0.7)",
        "probes": len(kb.list_mappings()), "violations": len(untrusted),
        "detail": untrusted[:5],
    })

    # C4 EDIT never confirms and never fabricates confidence.
    edit_violations = []
    for row in list(kb.list_mappings())[:20]:
        before = (row.admin_confirmed, float(row.confidence))
        edited = kb.update(
            mapping_id=row.id, admin_notes=f"sweep edit probe {SWEEP_ACTOR}",
            change_reason="sweep edit probe", actor=SWEEP_ACTOR)
        after = (edited.admin_confirmed, float(edited.confidence))
        if before != after:
            edit_violations.append(f"{row.id}: {before} -> {after}")
    checks.append({
        "id": "C4", "name": "EDIT is confirmation/confidence neutral",
        "probes": min(20, len(kb.list_mappings())), "violations": len(edit_violations),
        "detail": edit_violations[:5],
    })

    # C5 REJECT retains the row, unconfirms it, versions it, never deletes.
    reject_violations = []
    for row in list(kb.list_mappings())[:10]:
        v_before = row.version
        rejected = kb.reject(row.id, actor=SWEEP_ACTOR, reason="sweep reject probe")
        if rejected is None:
            reject_violations.append(f"{row.id}: no row returned")
        elif rejected.admin_confirmed or rejected.version <= v_before:
            reject_violations.append(
                f"{row.id}: confirmed={rejected.admin_confirmed} "
                f"version {v_before}->{rejected.version}")
        elif kb.lookup(vendor, platform, row.raw_syntax,
                       require_confirmed=False) is None:
            reject_violations.append(f"{row.id}: row was deleted")
    checks.append({
        "id": "C5", "name": "REJECT retains + unconfirms + versions the row",
        "probes": min(10, len(kb.list_mappings())), "violations": len(reject_violations),
        "detail": reject_violations[:5],
    })

    # C6 every stored row names a real model path and a v1 record exists.
    path_violations = []
    for row in kb.list_mappings():
        if not dom.is_valid_model_path(row.universal_model_path):
            path_violations.append(f"{row.id}: {row.universal_model_path!r}")
        elif not kb.get_versions(row.id):
            path_violations.append(f"{row.id}: no version record")
    checks.append({
        "id": "C6", "name": "every row has a valid model path and a version record",
        "probes": len(kb.list_mappings()), "violations": len(path_violations),
        "detail": path_violations[:5],
    })

    return checks


def main() -> int:
    rows: list[dict] = []
    all_checks: list[dict] = []
    check_candidate: tuple[KnowledgeBase, list] = (KnowledgeBase(), [])
    t_all = time.perf_counter()

    files = sorted(p for p in ROOT.rglob("*") if p.is_file())

    # ---------------------------------------------------------------- pass 1
    for p in files:
        rel = str(p.relative_to(ROOT))
        label = rel.split("\\")[0].lower()
        vendor, platform = LABEL_MAP.get(label, (label, "unknown"))
        lines = eligible_lines(p)
        if not lines:
            rows.append({"pass": 1, "relpath": rel, "dir_label": label,
                         "vendor": vendor, "lines_eligible": 0,
                         "lines_mapped": 0, "lines_unmapped": 0})
            continue

        resolved, unmapped = resolve_all(vendor, platform, lines)
        if not resolved:
            rows.append({"pass": 1, "relpath": rel, "dir_label": label,
                         "vendor": vendor, "platform": platform,
                         "lines_eligible": len(lines), "lines_mapped": 0,
                         "lines_unmapped": unmapped, "stored_rows": 0,
                         "kb_size": 0})
            continue
        kb = KnowledgeBase()
        dup_exact, dup_fuzzy, created, load_s = load_into(kb, vendor, platform, resolved)
        pr = probe(kb, vendor, platform, [ln for ln, _ in resolved])
        rows.append({
            "pass": 1,
            "relpath": rel,
            "dir_label": label,
            "vendor": vendor,
            "platform": platform,
            "lines_eligible": len(lines),
            "lines_mapped": len(resolved),
            "lines_unmapped": unmapped,
            "lines_loaded": len(resolved),
            "created_rows": created,
            "absorbed": dup_exact + dup_fuzzy,
            "absorbed_exact": dup_exact,
            "absorbed_fuzzy": dup_fuzzy,
            "absorption_rate": round((dup_exact + dup_fuzzy) / len(resolved), 4),
            "fuzzy_absorption_rate": round(dup_fuzzy / len(resolved), 4),
            "stored_rows": len(kb.list_mappings()),
            **pr,
            "load_ms": round(load_s * 1000, 3),
            "ms_per_create": round(load_s * 1000 / max(len(resolved), 1), 4),
            "kb_size": len(kb.list_mappings()),
        })
        if label == ISOLATION_LABELS[0] and len(resolved) > len(check_candidate[1]):
            check_candidate = (kb, resolved)

    # ---------------------------------------------------------------- pass 2
    # Contract checks C1..C6 over the richest real ingested KB of the sweep.
    if check_candidate[1]:
        all_checks.extend(
            contract_checks(check_candidate[0], ISOLATION_LABELS[0],
                            LABEL_MAP[ISOLATION_LABELS[0]][1], check_candidate[1]))

    # cross-file, same vendor: KB built from file A, queried with file B's lines
    by_label: dict[str, list[Path]] = {}
    for p in files:
        lab = str(p.relative_to(ROOT)).split("\\")[0].lower()
        by_label.setdefault(lab, []).append(p)

    for label in CROSS_FILE_LABELS:
        paths = sorted(by_label.get(label, []))
        if len(paths) < 2:
            continue
        vendor, platform = LABEL_MAP[label]
        # two largest files by eligible-line count (cap applied inside)
        scored = sorted(
            ((len(eligible_lines(p)), p) for p in paths),
            key=lambda t: t[0], reverse=True)
        a_resolved, _ = resolve_all(vendor, platform,
                                    eligible_lines(scored[0][1]))
        b_lines = eligible_lines(scored[1][1])
        b_resolved, _ = resolve_all(vendor, platform, b_lines)
        if not a_resolved or not b_resolved:
            continue
        kb = KnowledgeBase()
        load_into(kb, vendor, platform, a_resolved)
        pr = probe(kb, vendor, platform, [ln for ln, _ in b_resolved])
        # then ingest file B into the same KB: how many of B's lines merge into A's rows?
        dup_exact_b, dup_fuzzy_b, created_b, load_b_s = load_into(
            kb, vendor, platform, b_resolved)
        rows.append({
            "pass": 2,
            "relpath": f"{scored[0][1].relative_to(ROOT)} -> "
                       f"{scored[1][1].relative_to(ROOT)}",
            "dir_label": label,
            "vendor": vendor,
            "platform": platform,
            "lines_eligible": len(b_resolved),
            "lines_loaded": len(a_resolved),
            "created_rows": created_b,
            "absorbed": dup_exact_b + dup_fuzzy_b,
            "absorbed_exact": dup_exact_b,
            "absorbed_fuzzy": dup_fuzzy_b,
            "absorption_rate": round((dup_exact_b + dup_fuzzy_b) / len(b_resolved), 4),
            **pr,
            "load_ms": round(load_b_s * 1000, 3),
            "note": "file B lines queried against a KB built only from file A "
                    "(collision = a lookup returning a DIFFERENT stored syntax, "
                    "i.e. wrong meaning), then file B ingested into that KB "
                    "(absorbed_exact = B repeats A's line verbatim; "
                    "absorbed_fuzzy = B's line merged into a DIFFERENT A row)",
            "kb_size": len(kb.list_mappings()),
        })

    # ---------------------------------------------------------------- pass 3
    # cross-vendor isolation: store lines per label, query under other labels
    shared = KnowledgeBase()
    stored: list[tuple[str, str, str]] = []  # (vendor, platform, line)
    for label in ISOLATION_LABELS:
        paths = sorted(by_label.get(label, []))
        if not paths:
            continue
        vendor, platform = LABEL_MAP[label]
        resolved, _ = resolve_all(vendor, platform,
                                  eligible_lines(paths[0], cap=ISOLATION_LINES_PER_LABEL))
        load_into(shared, vendor, platform, resolved)
        stored.extend((vendor, platform, ln) for ln, _ in resolved)

    breaches = 0
    queries = 0
    t0 = time.perf_counter()
    for vendor, platform, ln in stored:
        for other_label in ISOLATION_LABELS:
            if other_label == vendor:
                continue
            o_vendor, o_platform = LABEL_MAP[other_label]
            queries += 1
            got = shared.lookup(o_vendor, o_platform, ln, require_confirmed=False)
            if got is not None:
                breaches += 1
    rows.append({
        "pass": 3,
        "relpath": "cross-vendor isolation",
        "dir_label": ",".join(ISOLATION_LABELS),
        "vendor": "all",
        "platform": "all",
        "lines_eligible": len(stored),
        "lines_loaded": len(stored),
        "absorbed": 0,
        "absorption_rate": 0.0,
        "lookup_exact": 0,
        "lookup_collision": breaches,
        "lookup_miss": 0,
        "lookup_ms": round((time.perf_counter() - t0) * 1000, 3),
        "note": f"{queries} queries of a stored line under a DIFFERENT vendor label; "
                "collision column = isolation breaches",
        "kb_size": len(shared.list_mappings()),
    })
    all_checks.append({
        "id": "C7", "name": "cross-vendor isolation (no bleed between vendors)",
        "probes": queries, "violations": breaches, "detail": [],
    })

    # ---------------------------------------------------------------- pass 4
    # deterministic ordering: two independent builds of the same data must
    # produce an identical ordered identity list.
    det_vendor, det_platform = LABEL_MAP[ISOLATION_LABELS[0]]
    det_paths = sorted(by_label.get(ISOLATION_LABELS[0], []))
    det_resolved: list[tuple[str, dict]] = []
    if det_paths:
        det_resolved, _ = resolve_all(
            det_vendor, det_platform,
            eligible_lines(det_paths[0], cap=ISOLATION_LINES_PER_LABEL))
    orders = []
    for _ in range(2):
        kb_det = KnowledgeBase()
        load_into(kb_det, det_vendor, det_platform, det_resolved)
        orders.append([
            (r.vendor, r.platform, r.raw_syntax, r.universal_model_path, r.version)
            for r in kb_det.list_mappings()
        ])
    det_violations = 0 if orders[0] == orders[1] else 1
    all_checks.append({
        "id": "C8", "name": "deterministic list order across independent builds",
        "probes": len(orders[0]), "violations": det_violations,
        "detail": [] if not det_violations else ["order differs between builds"],
    })

    fuzzy_total = sum(r.get("absorbed_fuzzy", 0) for r in rows)
    all_checks.append({
        "id": "C9", "name": "zero fuzzy absorption corpus-wide",
        "probes": sum(r.get("lines_mapped", 0) for r in rows),
        "violations": fuzzy_total,
        "detail": [r["relpath"] for r in rows if r.get("absorbed_fuzzy")][:5],
    })
    collision_total = sum(r.get("lookup_collision", 0) for r in rows if r.get("pass") != 3)
    all_checks.append({
        "id": "C10", "name": "zero wrong-meaning lookups corpus-wide (pass 1/2)",
        "probes": sum(r.get("lines_mapped", 0) for r in rows if r.get("pass") != 3),
        "violations": collision_total,
        "detail": [r["relpath"] for r in rows
                   if r.get("pass") != 3 and r.get("lookup_collision")][:5],
    })

    elapsed = time.perf_counter() - t_all

    fields = sorted({k for r in rows for k in r})
    with open(OUT / "dataset_results.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    p1 = [r for r in rows if r.get("pass") == 1 and r.get("lines_eligible")]
    p2 = [r for r in rows if r.get("pass") == 2]
    p3 = [r for r in rows if r.get("pass") == 3]

    def agg(sub: list[dict]) -> dict:
        loaded = sum(r.get("lines_mapped", 0) for r in sub)
        return {
            "files": len(sub),
            "lines_mapped": loaded,
            "lines_unmapped": sum(r.get("lines_unmapped", 0) for r in sub),
            "rows_created": sum(r.get("created_rows", 0) for r in sub),
            "absorbed": sum(r.get("absorbed", 0) for r in sub),
            "absorbed_exact": sum(r.get("absorbed_exact", 0) for r in sub),
            "absorbed_fuzzy": sum(r.get("absorbed_fuzzy", 0) for r in sub),
            "absorption_rate": round(
                sum(r.get("absorbed", 0) for r in sub) / loaded, 4) if loaded else 0.0,
            "fuzzy_absorption_rate": round(
                sum(r.get("absorbed_fuzzy", 0) for r in sub) / loaded, 4)
            if loaded else 0.0,
            "lookup_exact": sum(r.get("lookup_exact", 0) for r in sub),
            "lookup_collision": sum(r.get("lookup_collision", 0) for r in sub),
            "lookup_miss": sum(r.get("lookup_miss", 0) for r in sub),
            "collision_rate": round(
                sum(r.get("lookup_collision", 0) for r in sub) / loaded, 4) if loaded else 0.0,
            "load_ms_sum": round(sum(r.get("load_ms", 0) for r in sub), 1),
            "load_ms_max": round(max((r.get("load_ms", 0) for r in sub), default=0), 1),
            "ms_per_create_max": round(
                max((r.get("ms_per_create", 0) for r in sub), default=0), 4),
        }

    by_dir: dict[str, dict] = {}
    for lab in sorted({r["dir_label"] for r in p1}):
        by_dir[lab] = agg([r for r in p1 if r["dir_label"] == lab])

    worst = sorted(p1, key=lambda r: r.get("fuzzy_absorption_rate", 0),
                   reverse=True)[:10]
    slowest = sorted(p1, key=lambda r: r.get("ms_per_create", 0), reverse=True)[:10]

    violations = sum(c["violations"] for c in all_checks)
    summary = {
        "engine": "06_knowledge_base",
        "contract_version": "E06",
        "dataset_root": str(ROOT),
        "files_seen": len(files),
        "files_ingested": len(p1),
        "caps": {"max_lines_per_file": MAX_LINES_PER_FILE, "max_chars": MAX_CHARS},
        "model_path_policy": "resolved by the real deterministic normalizer; "
                             "unresolvable lines recorded as unmapped, never invented",
        "contract_checks": all_checks,
        "contract_violations_total": violations,
        "contract_verdict": "PASS" if violations == 0 else "FAIL",
        "pass1_per_file": agg(p1),
        "pass1_by_label": by_dir,
        "pass1_worst_absorption": [
            {"relpath": r["relpath"], "fuzzy_absorbed": r.get("absorbed_fuzzy", 0),
             "exact_absorbed": r.get("absorbed_exact", 0),
             "loaded": r.get("lines_mapped"),
             "fuzzy_rate": r.get("fuzzy_absorption_rate", 0.0)}
            for r in worst],
        "pass1_slowest_per_create": [
            {"relpath": r["relpath"], "ms_per_create": r["ms_per_create"],
             "kb_size": r["kb_size"]} for r in slowest],
        "pass2_cross_file": [
            {"pair": r["relpath"], "label": r["dir_label"],
             "stored_from_file_a": r["lines_loaded"],
             "queries_from_file_b": r["lines_eligible"],
             "exact": r.get("lookup_exact"), "collision": r.get("lookup_collision"),
             "miss": r.get("lookup_miss"),
             "collision_rate": round(
                 r.get("lookup_collision", 0) / max(r["lines_eligible"], 1), 4),
             "b_lines_absorbed_into_a_rows": r.get("absorbed"),
             "b_absorbed_exact": r.get("absorbed_exact"),
             "b_absorbed_fuzzy": r.get("absorbed_fuzzy"),
             "b_absorption_rate": r.get("absorption_rate")}
            for r in p2],
        "pass3_isolation": (p3[0] if p3 else {}),
        "elapsed_s": round(elapsed, 2),
    }
    (OUT / "dataset_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / "contract_results.json").write_text(
        json.dumps({"checks": all_checks, "violations_total": violations,
                    "verdict": summary["contract_verdict"]},
                   indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(
        {k: summary[k] for k in ("contract_verdict", "contract_violations_total",
                                 "files_seen", "files_ingested", "pass1_per_file",
                                 "elapsed_s")}, indent=2))
    for check in all_checks:
        print(f"  {check['id']:>3} {check['name']}: {check['probes']} probes, "
              f"{check['violations']} violations")
    return 0 if violations == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
