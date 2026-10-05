"""canonical compliance result enum (E07 F11).

Engine 07 stores §12 result values UPPERCASE ("PASS" | "FAIL" | "REVIEW").
Existing rows written by the pre-E07 pipeline are lowercased in place;
no rows are added, removed, or reinterpreted.

Revision ID: 006
Revises: 005
Create Date: 2026-09-27
"""
from alembic import op

revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "UPDATE compliance_results SET result = UPPER(result) "
        "WHERE result <> UPPER(result)"
    )


def downgrade() -> None:
    op.execute(
        "UPDATE compliance_results SET result = LOWER(result) "
        "WHERE result <> LOWER(result)"
    )
