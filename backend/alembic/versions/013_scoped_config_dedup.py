"""scoped configuration dedup: unique (device_id, content_hash) + unlinked guard

Fleet reality: the same bytes may legitimately live on many devices
(identical golden configs across 100 switches). The global UNIQUE on
content_hash wrongly rejected the 2nd..nth device upload, and the
STEP 7.6 linkage guard turned that into a 409 dead-end.

New rule (engine-enforced, mirrored here at the DB level): duplicate
identity is scoped to (device_id, content_hash). Same bytes on the
same device stay idempotent; same bytes on another device store a new
row. Every scope stays DB-guarded (E01 N5 is not regressed to
pre-check-only):
  - composite UNIQUE (device_id, content_hash) for device-bound rows
  - partial UNIQUE (content_hash) WHERE device_id IS NULL for
    device-less rows (plain composite UNIQUE would ignore NULL-device
    collisions since Postgres treats NULLs as distinct).

No backfill needed: the old global UNIQUE implies both new indexes'
pairs are already unique, so index replacement cannot fail — unless
two device-less rows share a hash, which the old global UNIQUE also
forbade. Replacement is therefore failure-free on any 004-shaped DB.

Revision ID: 013
Revises: 012
Create Date: 2026-09-30
"""
from alembic import op

revision = '013'
down_revision = '012'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.drop_index('uq_configurations_content_hash', table_name='configurations')
    op.create_index(
        'uq_configurations_device_content_hash',
        'configurations',
        ['device_id', 'content_hash'],
        unique=True,
    )
    op.create_index(
        'uq_configurations_content_hash_unlinked',
        'configurations',
        ['content_hash'],
        unique=True,
        postgresql_where='device_id IS NULL',
    )

def downgrade() -> None:
    # Restores the global-unique shape. Rows already stored per-device
    # with identical content are NOT merged back (one-way by design);
    # downgrading with such rows present will fail on index creation.
    op.drop_index('uq_configurations_content_hash_unlinked', table_name='configurations')
    op.drop_index('uq_configurations_device_content_hash', table_name='configurations')
    op.create_index(
        'uq_configurations_content_hash',
        'configurations',
        ['content_hash'],
        unique=True,
    )
