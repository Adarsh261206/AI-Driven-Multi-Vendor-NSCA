"""Add ip_address and user_agent to audit_trail

Revision ID: 002
Revises: 001
Create Date: 2026-08-25
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('audit_trail', sa.Column('ip_address', sa.String(45), nullable=True))
    op.add_column('audit_trail', sa.Column('user_agent', sa.String(500), nullable=True))
    # Make entity_id nullable (some entries don't have an entity_id)
    op.alter_column('audit_trail', 'entity_id', nullable=True)


def downgrade() -> None:
    op.alter_column('audit_trail', 'entity_id', nullable=False)
    op.drop_column('audit_trail', 'user_agent')
    op.drop_column('audit_trail', 'ip_address')
