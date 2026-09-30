"""baseline replacement: audit snapshots + DB-level one-active invariant.

- audits: baseline_id / baseline_name / baseline_controls snapshot columns.
  The audit pipeline resolves the org's active baseline once at audit time
  and stores this snapshot, so replacing the baseline later never rewrites
  historical audit context.
- company_baselines: partial unique index enforcing the product invariant
  "0 or 1 ACTIVE baseline per organization" at the database level, so a
  failed or concurrent replacement can never leave two active baselines.

Revision ID: 010
Revises: 009
Create Date: 2026-09-29
"""
from alembic import op
import sqlalchemy as sa

revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('audits', sa.Column('baseline_id', sa.UUID(), nullable=True))
    op.add_column('audits', sa.Column('baseline_name', sa.String(255), nullable=True))
    op.add_column('audits', sa.Column('baseline_controls', sa.JSON(), nullable=True))
    op.create_index(
        'ix_company_baselines_one_active_per_org',
        'company_baselines',
        ['organization_id'],
        unique=True,
        postgresql_where=sa.text("status = 'ACTIVE'"),
    )


def downgrade() -> None:
    op.drop_index(
        'ix_company_baselines_one_active_per_org',
        table_name='company_baselines',
        postgresql_where=sa.text("status = 'ACTIVE'"),
    )
    op.drop_column('audits', 'baseline_controls')
    op.drop_column('audits', 'baseline_name')
    op.drop_column('audits', 'baseline_id')