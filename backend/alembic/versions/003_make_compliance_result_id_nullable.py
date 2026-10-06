"""make compliance_result_id nullable in findings

Revision ID: 003
Revises: 002
Create Date: 2026-08-25
"""
from alembic import op

revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.alter_column('findings', 'compliance_result_id', nullable=True)

def downgrade() -> None:
    op.alter_column('findings', 'compliance_result_id', nullable=False)
