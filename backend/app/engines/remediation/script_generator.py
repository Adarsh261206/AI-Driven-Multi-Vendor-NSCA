"""Python remediation script generation (user-side execution model).

Takes a VALIDATED + APPROVED plan and renders a self-contained,
reviewable .py script the operator downloads, reviews and runs in
THEIR environment against THEIR device. The NSCA backend never
executes anything (EXECUTION_ENABLED=False).

Hard rules enforced here (fail closed, raise RemediationPlanError):
- plan must be approved and safe_to_apply;
- every required non-secret placeholder must already be resolved
  (no <...> may survive into the script);
- secret placeholders are NEVER resolved server-side: the script
  prompts for them locally via getpass at runtime;
- no credential, secret or token is embedded anywhere in the output.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.engines.remediation import EXECUTION_ENABLED
from app.engines.remediation.models import (
    PlanStatus,
    RemediationPlan,
    RemediationPlanError,
    coerce_status,
)


def _require_scriptable(plan: RemediationPlan) -> None:
    if EXECUTION_ENABLED:  # pragma: no cover - constant False by release
        raise RemediationPlanError(
            "backend device execution must stay disabled")
    status = coerce_status(plan.status)
    if status != PlanStatus.APPROVED:
        raise RemediationPlanError(
            f"script generation requires an approved plan, got "
            f"{status.value}")
    if not plan.safe_to_apply:
        raise RemediationPlanError(
            "plan is not safe_to_apply; refusing script generation")
    allowed_secrets = [p.name for p in plan.params
                       if p.supplied and p.type == "secret"]
    open_params = [p.name for p in plan.params
                   if p.required and not p.supplied]
    if open_params:
        raise RemediationPlanError(
            f"unresolved parameters block scripting: {open_params}")
    from app.engines.remediation.preconditions import (
        check_placeholders_resolved as _check_ph)

    ph = _check_ph(
        [c for ch in plan.changes for c in ch.commands], allowed_secrets)
    if not ph.passed:
        raise RemediationPlanError(ph.message)


def script_filename(plan: RemediationPlan) -> str:
    safe_id = "".join(c for c in plan.plan_id
                      if c.isalnum() or c in ("-", "_")) or "plan"
    return f"nsca_remediation_{safe_id}.py"


def _flatten_changes(plan: RemediationPlan) -> list[str]:
    """Config-mode line stream preserving hierarchical contexts."""
    lines: list[str] = []
    for change in plan.changes:
        if change.context:
            lines.append(change.context)
        lines.extend(change.commands)
    return lines


def _flatten_rollback(plan: RemediationPlan) -> list[str]:
    lines: list[str] = []
    for change in plan.rollback:
        if change.context:
            lines.append(change.context)
        lines.extend(change.commands)
    return lines


def generate_script(plan: RemediationPlan) -> tuple[str, str]:
    """Render (filename, source) for an approved plan. See module docs."""
    if not isinstance(plan, RemediationPlan):
        raise RemediationPlanError(
            f"plan must be a RemediationPlan, got {type(plan).__name__}")
    _require_scriptable(plan)

    secret_params = [p.name for p in plan.params if p.type == "secret"]
    payload = {
        "plan_id": plan.plan_id,
        "finding_id": plan.finding_id,
        "control_id": plan.control_id,
        "vendor": plan.device.vendor,
        "platform": plan.device.platform,
        "device_name": plan.device.name,
        "finding_title": plan.finding.title,
        "severity": plan.finding.severity,
        "changes": [c.to_dict() for c in plan.changes],
        "config_lines": _flatten_changes(plan),
        "rollback_lines": _flatten_rollback(plan),
        "verification": list(plan.verification),
        "secret_params": secret_params,
        "safety_class": plan.safety_class.value
        if hasattr(plan.safety_class, "value") else str(plan.safety_class),
    }
    embedded = json.dumps(payload, indent=2, ensure_ascii=False)
    return script_filename(plan), _render(embedded)


def _render(embedded_json: str) -> str:
    # Plain string concatenation (no templating engine): the output must
    # stay reviewable line by line.
    lines: list[str] = []
    add = lines.append
    add("#!/usr/bin/env python3")
    add('"""NSCA remediation script (user-side execution).')
    add("")
    add("WARNING: review every command below before running. NSCA does NOT")
    add("execute this script on your device. YOU run it, on YOUR machine,")
    add("against YOUR device, after verifying each step. Requires the")
    add("'netmiko' package for live device access (pip install netmiko);")
    add("without it the script runs pre-checks in dry-run print mode only.")
    add('"""')
    add("from __future__ import annotations")
    add("")
    add("import argparse")
    add("import getpass")
    add("import hashlib")
    add("import json")
    add("import sys")
    add("from datetime import datetime, timezone")
    add("")
    add("")
    add("# --- Plan data (no secrets are ever embedded here) ---")
    add("PLAN_JSON = r'''")
    add(embedded_json)
    add("'''")
    add('PLAN = json.loads(PLAN_JSON)')
    add("")
    add("")
    add('def _secret(name: str) -> str:')
    add('    """Prompt for a secret locally; never printed, never logged."""')
    add('    value = getpass.getpass(f"{name}: ")')
    add('    if not value:')
    add('        sys.exit(f"ABORT: required secret {name!r} not supplied")')
    add('    return value')
    add("")
    add("")
    add('def _resolve_placeholders(lines, secrets):')
    add('    """Substitute <placeholders>: secrets from prompts, plain values')
    add('    must already be resolved by NSCA (anything left is fatal)."""')
    add('    import re')
    add('    out = []')
    add('    for line in lines:')
    add('        def _sub(match):')
    add('            name = match.group(1).strip()')
    add('            if name in secrets:')
    add('                return secrets[name]')
    add('            sys.exit(f"ABORT: unresolved placeholder <{name}> in: {line}")')
    add('        out.append(re.sub(r"<([^<>]+)>", _sub, line))')
    add('    return out')
    add("")
    add("")
    add('def _sha256_file(path: str) -> str:')
    add('    digest = hashlib.sha256()')
    add('    with open(path, "rb") as fh:')
    add('        for chunk in iter(lambda: fh.read(65536), b""):')
    add('            digest.update(chunk)')
    add('    return digest.hexdigest()')
    add("")
    add("")
    add('def _session(args, secrets):')
    add('    try:')
    add('        from netmiko import ConnectHandler')
    add('    except ImportError:')
    add('        sys.exit("ABORT: netmiko not installed (pip install netmiko)")')
    add('    conn = ConnectHandler(device_type="cisco_xe", host=args.host,')
    add('                          username=args.username, password=secrets.get(')
    add('                              "password", getpass.getpass("Device password: ")))')
    add('    conn.enable()')
    add('    return conn')
    add("")
    add("")
    add('def _backup(conn, plan_id):')
    add('    running = conn.send_command("show running-config")')
    add('    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")')
    add('    path = f"backup-{plan_id}-{stamp}.cfg"')
    add('    with open(path, "w", encoding="utf-8", errors="replace") as fh:')
    add('        fh.write(running)')
    add('    digest = hashlib.sha256(running.encode("utf-8", "replace")).hexdigest()')
    add('    print(f"BACKUP: {path} sha256={digest}")')
    add('    return path, digest')
    add("")
    add("")
    add('def main() -> int:')
    add('    ap = argparse.ArgumentParser(description="NSCA remediation runner")')
    add('    ap.add_argument("--host", required=True, help="device IP/hostname")')
    add('    ap.add_argument("--username", required=True, help="login username")')
    add('    ap.add_argument("--dry-run", action="store_true",')
    add('                    help="print commands without connecting")')
    add('    args = ap.parse_args()')
    add('')
    add('    print(f"PLAN: {PLAN[\'plan_id\']} finding={PLAN[\'finding_id\']} "')
    add('          f"control={PLAN[\'control_id\']} safety={PLAN[\'safety_class\']}")')
    add('    secrets = {name: _secret(name) for name in PLAN.get("secret_params", [])}')
    add('    config_lines = _resolve_placeholders(PLAN["config_lines"], secrets)')
    add('    print("COMMANDS TO APPLY:")')
    add('    for line in config_lines:')
    add('        print(f"  + {line}")')
    add('    if args.dry_run:')
    add('        print("DRY-RUN: no changes made")')
    add('        return 0')
    add('    answer = input("Apply these commands? Type YES to continue: ").strip()')
    add('    if answer != "YES":')
    add('        print("ABORT: operator did not confirm")')
    add('        return 2')
    add('    conn = _session(args, secrets)')
    add('    try:')
    add('        _backup(conn, PLAN["plan_id"])')
    add('        result = conn.send_config_set(config_lines)')
    add('        print(result)')
    add('        conn.save_config()')
    add('        print("VERIFY: run these checks on the device:")')
    add('        for check in PLAN.get("verification", []):')
    add('            print(f"  ? {check}")')
    add('            try:')
    add('                print(conn.send_command(check))')
    add('            except Exception as exc:  # noqa: BLE001 - report and fail')
    add('                print(f"VERIFY FAILED: {check}: {exc}")')
    add('                return 3')
    add('    finally:')
    add('        conn.disconnect()')
    add('    print("SUCCESS: commands applied; verify output above, then re-audit in NSCA")')
    add('    return 0')
    add("")
    add("")
    add('if __name__ == "__main__":')
    add('    raise SystemExit(main())')
    add("")
    return "\n".join(lines)


def script_metadata(plan: RemediationPlan) -> dict[str, Any]:
    """Download metadata (filename/size/hash) without the source bytes."""
    filename, source = generate_script(plan)
    raw = source.encode("utf-8")
    return {"filename": filename, "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}
