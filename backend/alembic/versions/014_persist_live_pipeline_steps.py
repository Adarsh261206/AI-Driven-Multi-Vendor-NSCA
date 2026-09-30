"""persist live pipeline progress on a dedicated audit_progress row

The Celery worker runs in a SEPARATE process from the API, so its
in-memory live-step dict is invisible to the API's status endpoint.
Progress is therefore written to the DB. It lives on its OWN table —
NOT on audit_executions — because the pipeline's main transaction
holds a row lock on the execution row from the first checkpoint until
the final commit; any concurrent UPDATE on that row blocks, which
deadlocks the solo worker (the sync awaits the very lock the pipeline
holds). audit_progress rows are only ever written by the lightweight
sync session, so progress can never block the pipeline.

Revision ID: 014
Revises: 013
Create Date: 2026-09-30
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = '014'
down_revision = '013'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'audit_progress',
        sa.Column(
            'audit_id',
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey('audits.id', ondelete='CASCADE'),
            primary_key=True,
        ),
        sa.Column('progress', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('current_step', sa.String(100), nullable=True),
        sa.Column('live_steps', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('live_logs', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            'updated_at',
            sa.DateTime(),
            nullable=False,
            server_default=sa.text('now()'),
        ),
    )

def downgrade() -> None:
    op.drop_table('audit_progress')