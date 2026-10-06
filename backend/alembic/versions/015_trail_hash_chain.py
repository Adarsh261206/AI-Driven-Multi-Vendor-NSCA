"""Hash-chained audit ledger columns on audit_trail.

Extends the Engine 12 trail into an append-oriented hash-chained ledger:
- seq BIGSERIAL UNIQUE NOT NULL: stable ledger ordering (never relies on
  created_at ties) and gap detection.
- previous_hash VARCHAR(64) NULL + event_hash VARCHAR(64) NULL: the
  chain links. (VARCHAR, not CHAR: identical fixed 64-char hex storage
  with no blank-padding hazards on read-back.)

All three columns are nullable-or-defaulted so historical rows pre-dating
the chain stay valid untouched: NULL hashes explicitly mean
"pre-chain audit era" and are never backfilled — rewriting history to
make it look chained would destroy evidence. The first row written
after this migration becomes the genesis event (previous_hash = "").

Revision ID: 015
Revises: 014
Create Date: 2026-10-04
"""
from alembic import op
import sqlalchemy as sa


revision = '015'
down_revision = '014'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE SEQUENCE IF NOT EXISTS audit_trail_seq_seq AS BIGINT")
    op.add_column('audit_trail',
                  sa.Column('seq', sa.BIGINT(), nullable=False,
                            server_default=sa.text(
                                "nextval('audit_trail_seq_seq')")))
    op.create_unique_constraint('uq_audit_trail_seq', 'audit_trail',
                                ['seq'])
    op.add_column('audit_trail',
                  sa.Column('previous_hash', sa.String(64), nullable=True))
    op.add_column('audit_trail',
                  sa.Column('event_hash', sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column('audit_trail', 'event_hash')
    op.drop_column('audit_trail', 'previous_hash')
    op.drop_constraint('uq_audit_trail_seq', 'audit_trail',
                       type_='unique')
    op.drop_column('audit_trail', 'seq')
    op.execute("DROP SEQUENCE IF EXISTS audit_trail_seq_seq")
