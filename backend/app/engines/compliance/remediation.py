"""Canonical Remediation Engine for Engine 10 (spec §10.10).

One implementation builds every §12 Remediation object in the system:

    Finding (+ control definition + vendor context)
      → input validation (typed errors, never silent coercion)
      → RemediationEngine.build()
      → Remediation {finding_id, finding_title, risk_description,
                     why_it_matters, vendor, platform, recommended_config,
                     verification_steps, rollback_steps, references}

Content-completion policy (honest, deterministic, vendor-aware):

- recommended_config: the control's own remediation_command when present.
  Otherwise a CONSERVATIVE negation derivation from the observed raw
  statement (documented rules below). Otherwise "" — never invented.
- verification_steps: the control's verification_steps when present,
  else [audit_command] when present, else []. The audit command IS the
  control's own audit procedure, so reusing it is sourcing, not invention.
- rollback_steps: the control's rollback_steps when present, else the
  inverse of recommended_config when it matches a safe inversion rule,
  else [].
- why_it_matters: control title/description (the control's own statement
  of what it protects).
- risk_description: the finding's evaluated reasoning (what is wrong).
- references: [source_document + location] when present.

Negation derivation rules (applied ONLY to single-line observed
statements from a known vendor family):

- cisco / ios / ios_xe: "X" → "no X"; "no X" → "X" (strip one leading
  "no "). Lines starting with "default ", "no " + "default ", or
  containing "|" / ">" / "#" are NEVER derived (not safe).
- juniper / junos set-style: "set ..." → "delete ..." (first token
  only). Anything else (including "delete ...") is NEVER derived.
- unknown / unsupported / empty vendor, multi-line statements, empty
  statements: NEVER derived → "".

Rollback uses the same rules in the inverse direction ("no X" → "X",
"delete ..." is never inverted). Every rule is total (returns "" on any
doubt) and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Typed errors. One error type for the whole input contract; a subclass of
# ValueError so ValueError expectations keep working.
# ---------------------------------------------------------------------------

class RemediationError(ValueError):
    """A remediation-engine input violates the canonical contract."""


# ---------------------------------------------------------------------------
# §12 Remediation interface keys (spec docs/PROJECT_MASTER_SPEC.md).
# ---------------------------------------------------------------------------

REMEDIATION_KEYS: tuple[str, ...] = (
    "finding_id",
    "finding_title",
    "risk_description",
    "why_it_matters",
    "vendor",
    "platform",
    "recommended_config",
    "verification_steps",
    "rollback_steps",
    "references",
)

#: Vendor families with safe negation syntax. Anything else → no derivation.
NEGATABLE_VENDORS = frozenset({"cisco", "juniper"})

_UNSAFE_STATEMENT_RE_PARTS = ("|", ">", "#", "\x00")


def validate_remediation(remediation: Any) -> dict[str, Any]:
    """Assert a remediation object carries the §12 interface (keys present,
    list fields are lists, scalar fields are strings). Raises
    RemediationError — never a silent pass."""
    if not isinstance(remediation, dict):
        raise RemediationError(
            f"remediation must be a dict, got {type(remediation).__name__}")
    missing = [k for k in REMEDIATION_KEYS if k not in remediation]
    if missing:
        raise RemediationError(
            f"remediation missing §12 keys: {sorted(missing)}")
    for key in ("verification_steps", "rollback_steps", "references"):
        if not isinstance(remediation[key], list):
            raise RemediationError(
                f"remediation[{key!r}] must be a list, got "
                f"{type(remediation[key]).__name__}")
    for key in ("finding_id", "finding_title", "risk_description",
                "why_it_matters", "vendor", "platform",
                "recommended_config"):
        if not isinstance(remediation[key], str):
            raise RemediationError(
                f"remediation[{key!r}] must be a string, got "
                f"{type(remediation[key]).__name__}")
    return remediation


@dataclass
class Remediation:
    """The §12 Remediation interface as a typed object."""
    finding_id: str = ""
    finding_title: str = ""
    risk_description: str = ""
    why_it_matters: str = ""
    vendor: str = ""
    platform: str = ""
    recommended_config: str = ""
    verification_steps: list[str] = field(default_factory=list)
    rollback_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_title": self.finding_title,
            "risk_description": self.risk_description,
            "why_it_matters": self.why_it_matters,
            "vendor": self.vendor,
            "platform": self.platform,
            "recommended_config": self.recommended_config,
            "verification_steps": list(self.verification_steps),
            "rollback_steps": list(self.rollback_steps),
            "references": list(self.references),
        }


def _single_line(statement: Any) -> str:
    """Normalize to one stripped line, or "" when not safely usable."""
    if not isinstance(statement, str):
        return ""
    line = statement.strip()
    if not line or "\n" in line or "\r" in line:
        return ""
    if any(part in line for part in _UNSAFE_STATEMENT_RE_PARTS):
        return ""
    return line


def negate_statement(statement: str, vendor: str, platform: str) -> str:
    """Conservative vendor-aware negation of one observed config line.

    Returns the negated command, or "" when no safe rule applies. Total
    and deterministic: any doubt yields "".
    """
    line = _single_line(statement)
    if not line:
        return ""
    family = (vendor or "").strip().lower()
    if family not in NEGATABLE_VENDORS:
        return ""
    if family == "cisco":
        lowered = line.lower()
        if lowered.startswith("default ") or lowered.startswith("no default "):
            return ""
        if lowered.startswith("no ") and len(line) > 3:
            return line[3:].lstrip()
        return f"no {line}"
    # juniper set-style
    if line.startswith("set ") and len(line) > 4:
        return "delete " + line[4:].lstrip()
    return ""


def invert_command(command: str, vendor: str, platform: str) -> str:
    """Safe rollback inverse of a recommended command, or "".

    Rollback inverts what negation produced: "no X" → "X" (cisco),
    "delete ..." is never inverted (the set-form cannot be recovered
    reliably). Same safety gates as negate_statement.
    """
    line = _single_line(command)
    if not line:
        return ""
    family = (vendor or "").strip().lower()
    if family not in NEGATABLE_VENDORS:
        return ""
    if family == "cisco":
        lowered = line.lower()
        if lowered.startswith("no ") and len(line) > 3:
            rest = line[3:].lstrip()
            if rest and not rest.lower().startswith("default "):
                return rest
        return ""
    return ""


class RemediationEngine:
    """Canonical Remediation Engine (spec §10.10).

    Builds vendor-specific fix instructions with verification steps,
    rollback guidance and finding references. Content comes from the
    control definition first, from conservative deterministic derivation
    second, and is honestly empty otherwise.
    """

    def build(
        self,
        *,
        finding_id: str = "",
        finding_title: str = "",
        risk_description: str = "",
        why_it_matters: str = "",
        vendor: str = "",
        platform: str = "",
        recommended_config: str = "",
        observed_statement: str = "",
        audit_command: str = "",
        verification_steps: Optional[list[str]] = None,
        rollback_steps: Optional[list[str]] = None,
        references: Optional[list[str]] = None,
        control_id: str = "",
    ) -> dict[str, Any]:
        """Build a §12 Remediation dict.

        - recommended_config: control-authored when supplied, else derived
          from the observed statement via negate_statement(), else "".
        - verification_steps: control-authored when supplied, else
          [audit_command] when supplied, else [].
        - rollback_steps: control-authored when supplied, else the safe
          inverse of the final recommended_config, else [].
        All inputs validated (typed errors); output validated against the
        §12 interface before return.
        """
        for name, value in (("finding_title", finding_title),
                            ("risk_description", risk_description),
                            ("why_it_matters", why_it_matters),
                            ("vendor", vendor),
                            ("platform", platform)):
            if not isinstance(value, str):
                raise RemediationError(
                    f"{name} must be str, got {type(value).__name__}")
        if not isinstance(finding_id, str):
            raise RemediationError(
                f"finding_id must be str, got {type(finding_id).__name__}")
        for name, value in (("recommended_config", recommended_config),
                            ("observed_statement", observed_statement),
                            ("audit_command", audit_command)):
            if not isinstance(value, str):
                raise RemediationError(
                    f"{name} must be str, got {type(value).__name__}")
        for name, value in (("verification_steps", verification_steps),
                            ("rollback_steps", rollback_steps),
                            ("references", references)):
            if value is not None and not isinstance(value, (list, tuple)):
                raise RemediationError(
                    f"{name} must be a list of strings, got "
                    f"{type(value).__name__}")

        command = (recommended_config or "").strip()
        if not command:
            command = negate_statement(observed_statement, vendor, platform)

        verified = (list(verification_steps)
                    if verification_steps is not None
                    else ([audit_command] if (audit_command or "").strip()
                          else []))
        if any(not isinstance(s, str) for s in verified):
            raise RemediationError("verification_steps must be strings")

        rollback = (list(rollback_steps)
                    if rollback_steps is not None
                    else ([invert_command(command, vendor, platform)]
                          if command else []))
        rollback = [s for s in rollback if s]
        if any(not isinstance(s, str) for s in rollback):
            raise RemediationError("rollback_steps must be strings")

        refs = list(references) if references is not None else []
        if any(not isinstance(r, str) for r in refs):
            raise RemediationError("references must be strings")

        return validate_remediation({
            "finding_id": finding_id,
            "finding_title": finding_title,
            "risk_description": risk_description,
            "why_it_matters": why_it_matters,
            "vendor": vendor,
            "platform": platform,
            "recommended_config": command,
            "verification_steps": verified,
            "rollback_steps": rollback,
            "references": refs,
        })

    def build_for_control(
        self,
        *,
        control: Any,
        finding_id: str = "",
        finding_title: str = "",
        risk_description: str = "",
        observed_statement: str = "",
        vendor: str = "",
        platform: str = "",
    ) -> dict[str, Any]:
        """Build remediation from a control definition object.

        Reads remediation_command / audit_command / verification_steps /
        rollback_steps / references (source_document + source_location)
        when present; everything absent follows the standard completion
        policy. A missing control (None) yields a structurally valid but
        content-empty remediation — never an exception, never invented
        commands.
        """
        references: list[str] = []
        if control is not None:
            source_document = getattr(control, "source_document", "") or ""
            source_location = getattr(control, "source_location", "") or ""
            if source_document:
                ref = source_document
                if source_location:
                    ref = f"{ref} [{source_location}]"
                references.append(ref)
            title = getattr(control, "title", "") or finding_title
            why = getattr(control, "description", "") or title
        else:
            title = finding_title
            why = finding_title
        return self.build(
            finding_id=finding_id,
            finding_title=title,
            risk_description=risk_description,
            why_it_matters=why,
            vendor=vendor,
            platform=platform,
            recommended_config=(getattr(control, "remediation_command", "")
                                or "") if control is not None else "",
            observed_statement=observed_statement,
            audit_command=(getattr(control, "audit_command", "")
                           or "") if control is not None else "",
            verification_steps=(getattr(control, "verification_steps", None)
                                if control is not None else None),
            rollback_steps=(getattr(control, "rollback_steps", None)
                            if control is not None else None),
            references=references,
        )
