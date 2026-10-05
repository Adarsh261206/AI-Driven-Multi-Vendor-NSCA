"""Python remediation planning + script generation (plan-first workflow).

Extends the advisory remediation contract in
app.engines.compliance.remediation (left untouched) into structured,
precondition-checked, human-approved remediation plans whose final
artifact is a user-downloaded Python script. The NSCA backend never
touches a device: EXECUTION_ENABLED is False.
"""

EXECUTION_ENABLED = False
