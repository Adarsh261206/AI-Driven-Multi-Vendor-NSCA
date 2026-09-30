"""durable audit execution state (STEP 7).

- audit_executions: one row per execution attempt. Queue state machine
  (queued/running/completed/failed/cancel_requested/cancelled) kept
  separate from the compliance result on audits. Retries create new rows
  so failure history is preserved.
- audit_batches: persistent bulk-execution record (item audit IDs) so the
  bulk progress view survives refresh/navigation.

No backfill: pre-STEP-7 audits simply have no execution rows; status and
summary endpoints fall back to legacy behavior for them.

Revision ID: 012
Revises: 011
Create Date: 2026-09-30
"""
from alembic import op
import sqlalchemy as sa

revision = '012'
down_revision = '011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'audit_executions',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('audit_id', sa.UUID(), nullable=False),
        sa.Column('attempt', sa.Integer(), nullable=False),
        sa.Column('framework', sa.String(50), nullable=False),
        sa.Column('framework_version', sa.String(50), nullable=True),        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('max_attempts', sa.Integer(), nullable=False),
        sa.Column('error_category', sa.String(50), nullable=True),
        sa.Column('error_message', sa.String(500), nullable=True),
        sa.Column('retryable', sa.Boolean(), nullable=False),
        sa.Column('progress', sa.Integer(), nullable=False),
        sa.Column('current_step', sa.String(100), nullable=True),
        sa.Column('celery_task_id', sa.String(255), nullable=True),
        sa.Column('lease_expires_at', sa.DateTime(), nullable=True),
        sa.Column('queued_at', sa.DateTime(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_audit_executions_audit_id', 'audit_executions', ['audit_id']
    )
    op.create_table(
        'audit_batches',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('audit_ids', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('audit_batches')
    op.drop_index('ix_audit_executions_audit_id', table_name='audit_executions')
    op.drop_table('audit_executions')
