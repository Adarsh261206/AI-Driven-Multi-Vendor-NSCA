"""canonical finding severity + control linkage (E08 F1/F7).

- findings.severity / compliance_results.severity: stored values are the
  §12 uppercase vocabulary. Pre-E08 rows were written lowercase; they are
  converted in place (no rows added, removed or reinterpreted).
- findings.control_id: the finding-to-control link is part of the §12
  contract, so it is stored on the row (indexed) instead of derived per
  request. Existing rows are backfilled from their compliance_results row
  where a linkage exists; rows without one keep NULL honestly.

Revision ID: 007
Revises: 006
Create Date: 2026-09-28
"""
from alembic import op
import sqlalchemy as sa

revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('findings',
                  sa.Column('control_id', sa.String(100), nullable=True))
    op.create_index('ix_findings_control_id', 'findings', ['control_id'])
    op.execute(
        "UPDATE findings SET control_id = sub.control_id FROM "
        "(SELECT findings.id AS fid, compliance_results.control_id "
        "AS control_id FROM findings JOIN compliance_results "
        "ON compliance_results.id = findings.compliance_result_id) AS sub "
        "WHERE findings.id = sub.fid AND findings.control_id IS NULL"
    )
    for table in ("findings", "compliance_results"):
        op.execute(
            f"UPDATE {table} SET severity = UPPER(severity) "
            f"WHERE severity <> UPPER(severity)"
        )


def downgrade() -> None:
    # Structural reversal only; backfilled control linkage is not restored
    # (it did not exist before this revision).
    op.drop_index('ix_findings_control_id', table_name='findings')
    op.drop_column('findings', 'control_id')
    for table in ("findings", "compliance_results"):
        op.execute(
            f"UPDATE {table} SET severity = LOWER(severity) "
            f"WHERE severity <> LOWER(severity)"
        )
