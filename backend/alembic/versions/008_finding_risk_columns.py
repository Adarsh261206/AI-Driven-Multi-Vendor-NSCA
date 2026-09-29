"""risk output columns on findings (E09 F1).

The 10.9 risk output (risk_score, priority, risk_method,
risk_model_version) persists on the finding row so it survives
engine → database → API → reports. All four columns are nullable so
historical records pre-dating the contract stay valid; the canonical
pipeline always sets them for new rows. No data migration: historical
NULLs honestly mean "assessed before the risk contract existed".

Revision ID: 008
Revises: 007
Create Date: 2026-09-28
"""
from alembic import op
import sqlalchemy as sa

revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('findings',
                  sa.Column('risk_score', sa.Float(), nullable=True))
    op.add_column('findings',
                  sa.Column('priority', sa.String(10), nullable=True))
    op.add_column('findings',
                  sa.Column('risk_method', sa.String(32), nullable=True))
    op.add_column('findings',
                  sa.Column('risk_model_version', sa.String(64),
                            nullable=True))


def downgrade() -> None:
    op.drop_column('findings', 'risk_model_version')
    op.drop_column('findings', 'risk_method')
    op.drop_column('findings', 'priority')
    op.drop_column('findings', 'risk_score')
