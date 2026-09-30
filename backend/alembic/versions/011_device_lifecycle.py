"""device lifecycle column (STEP 5).

Adds devices.is_active (ACTIVE/ARCHIVED lifecycle), defaulting existing
rows to active. Archive preserves all history — it never deletes. This is
device lifecycle only, separate from audit execution state.

Revision ID: 011
Revises: 010
Create Date: 2026-09-30
"""
from alembic import op
import sqlalchemy as sa

revision = '011'
down_revision = '010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'devices',
        sa.Column(
            'is_active', sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )


def downgrade() -> None:
    op.drop_column('devices', 'is_active')
