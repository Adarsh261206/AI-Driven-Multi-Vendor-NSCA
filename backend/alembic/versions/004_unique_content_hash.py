"""unique content_hash on configurations (E01 duplicate-race fix)

Deduplicates historical rows (keeps the earliest upload per content
hash; dependent audit/parse rows cascade with the delete), then
replaces the plain index with a UNIQUE index so concurrent identical
uploads are rejected by the database rather than only by the
application-level pre-check.

Revision ID: 004
Revises: 003
Create Date: 2026-09-26
"""
from alembic import op

revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Remove historical duplicates first: without them the unique index
    # creation would fail. Keeps the earliest row per content_hash
    # (uploaded_at, then id as a deterministic tiebreak).
    op.execute(
        """
        DELETE FROM configurations
        WHERE id IN (
            SELECT id FROM (
                SELECT id,
                       row_number() OVER (
                           PARTITION BY content_hash
                           ORDER BY uploaded_at, id
                       ) AS rn
                FROM configurations
            ) ranked
            WHERE rn > 1
        )
        """
    )
    op.drop_index('ix_configurations_content_hash', table_name='configurations')
    op.create_index(
        'uq_configurations_content_hash',
        'configurations',
        ['content_hash'],
        unique=True,
    )

def downgrade() -> None:
    # Restores the index shape. Deduplicated rows are not restored
    # (deleting exact-content duplicates is intentionally one-way).
    op.drop_index('uq_configurations_content_hash', table_name='configurations')
    op.create_index(
        'ix_configurations_content_hash', 'configurations', ['content_hash']
    )
