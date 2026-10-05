"""Dedicated remediation_plans table (plan-first workflow).

The executable plan lifecycle lives here — never inside
Finding.remediation (advisory contract, untouched) and never derived
per request. Status transitions are enforced in the service layer;
no API accepts a status value. Secrets are never stored on this row:
only parameter descriptors and resolved PLAIN values.

Revision ID: 010
Revises: 009
Create Date: 2026-10-05
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID


revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'remediation_plans',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('plan_id', sa.String(32), nullable=False, unique=True),
        sa.Column('finding_id', UUID(as_uuid=True),
                  sa.ForeignKey('findings.id', ondelete='CASCADE'),
                  nullable=False, index=True),
        sa.Column('control_id', sa.String(100), nullable=True),
        sa.Column('status', sa.String(32), nullable=False,
                  server_default='draft', index=True),
        sa.Column('plan_json', JSONB, nullable=False),
        sa.Column('configuration_id', UUID(as_uuid=True), nullable=True),
        sa.Column('configuration_hash_before', sa.String(64),
                  nullable=True),
        sa.Column('approved_by', UUID(as_uuid=True), nullable=True),
        sa.Column('approved_at', sa.DateTime(), nullable=True),
        sa.Column('rejection_reason', sa.Text(), nullable=True),
        sa.Column('failure_info', JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('remediation_plans')
