"""Configuration diff: structured changes <-> before/after blocks.

Cisco configuration is hierarchical: a change is a (context, commands)
pair, never a bare line. The diff engine renders both the human
before/after view and the machine add[]/remove[] lists from the same
structures so they cannot disagree.
"""

from __future__ import annotations

from app.engines.remediation.models import PlanChange, PlanDiff


def render_block(context: str, commands: list[str]) -> list[str]:
    """Render one context block as config lines (context + indented)."""
    if not context:
        return list(commands)
    return [context] + [f" {c}" for c in commands]


def build_diff(changes: list[PlanChange],
               removed: list[PlanChange]) -> PlanDiff:
    """Build the before/after diff from structured changes.

    `removed` carries the observed vulnerable lines being replaced
    (same context shape). add[]/remove[] are the flat machine lists.
    """
    before: list[str] = []
    for change in removed:
        before.extend(render_block(change.context, change.commands))
    after: list[str] = []
    for change in changes:
        after.extend(render_block(change.context, change.commands))
    return PlanDiff(
        before=before,
        after=after,
        add=[c for ch in changes for c in ch.commands],
        remove=[c for ch in removed for c in ch.commands],
    )


def render_changes(changes: list[PlanChange]) -> list[str]:
    """Render structured changes as flat config lines (context blocks)."""
    lines: list[str] = []
    for change in changes:
        lines.extend(render_block(change.context, change.commands))
    return lines


def build_diff_from_parts(after_blocks: list[str], add: list[str],
                          before_blocks: list[str],
                          remove: list[str]) -> PlanDiff:
    """Rebuild a diff when one side is re-rendered (e.g. after plain
    parameter substitution). Removal side passes through unchanged."""
    return PlanDiff(before=list(before_blocks), after=list(after_blocks),
                    add=list(add), remove=list(remove))


def parse_command_block(command_text: str) -> list[PlanChange]:
    """Split an authoritative multi-line command into context blocks.

    First line is the context when a second indented line exists (the
    Cisco convention used by every benchmark remediation_command);
    otherwise the whole text is global-mode commands.
    """
    lines = [(ln.strip()) for ln in (command_text or "").splitlines()]
    lines = [ln for ln in lines if ln]
    if not lines:
        return []
    if len(lines) >= 2:
        return [PlanChange(context=lines[0], commands=lines[1:])]
    return [PlanChange(context="", commands=lines)]
