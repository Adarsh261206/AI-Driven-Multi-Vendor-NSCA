"""Vendor device adapters (script-side execution model only).

The NSCA backend never connects to a device (EXECUTION_ENABLED=False).
These adapters define the interface that generated user-side scripts
implement against, keeping future vendors pluggable.
"""
