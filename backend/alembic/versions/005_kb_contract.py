"""knowledge-base contract alignment (E06 F4/F7/F8)

Brings semantic_mappings / mapping_versions to the spec section 15.1 /
section 12 contract:

- canonicalize stored identity (lower/strip vendor+platform, strip
  raw_syntax) and merge canonical duplicates (earliest created_at wins;
  version rows are reassigned, never deleted)
- backfill NULL universal_model_path with '' (legacy rows predate entry
  validation; new writes are validated non-null/non-empty)
- confidence FLOAT -> NUMERIC(5,2)
- created_by_id UUID FK -> created_by VARCHAR(100) NOT NULL
  (actor identity survives user deletion; drops the users FK)
- changed_by_id UUID FK -> changed_by VARCHAR(100) NOT NULL
- universal_model_path -> NOT NULL on both tables
- UNIQUE(vendor, platform, raw_syntax, version) per spec 15.1
- mapping_versions gains nullable confidence (quality axis
  "AI confidence at creation")

Revision ID: 005
Revises: 004
Create Date: 2026-09-27
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Canonicalize stored identity (approximation of the application
    # canonical form: lower/strip vendor+platform, strip raw_syntax).
    op.execute(
        """
        UPDATE semantic_mappings
        SET vendor = lower(btrim(vendor)),
            platform = lower(btrim(platform)),
            raw_syntax = btrim(raw_syntax)
        """
    )

    # 2. Merge canonical duplicates: earliest created_at wins, version rows
    # are reassigned to the survivor (history is preserved; duplicate
    # version numbers may interleave after a merge - documented).
    op.execute(
        """
        UPDATE mapping_versions v
        SET mapping_id = w.winner
        FROM (
            SELECT id,
                   first_value(id) OVER (
                       PARTITION BY vendor, platform, raw_syntax
                       ORDER BY created_at, id
                   ) AS winner
            FROM semantic_mappings
        ) w
        WHERE v.mapping_id = w.id AND w.id <> w.winner
        """
    )
    op.execute(
        """
        DELETE FROM semantic_mappings a
        USING semantic_mappings b
        WHERE a.vendor = b.vendor
          AND a.platform = b.platform
          AND a.raw_syntax = b.raw_syntax
          AND (a.created_at > b.created_at
               OR (a.created_at = b.created_at AND a.id > b.id))
        """
    )

    # 3. Backfill model paths that predate entry validation. New writes are
    # validated; legacy NULLs become '' (visibly degraded, never valid).
    op.execute(
        "UPDATE semantic_mappings SET universal_model_path = '' "
        "WHERE universal_model_path IS NULL"
    )
    op.execute(
        "UPDATE mapping_versions SET universal_model_path = '' "
        "WHERE universal_model_path IS NULL"
    )

    # 4. Confidence precision per spec 15.1.
    op.alter_column(
        'semantic_mappings', 'confidence',
        existing_type=sa.Float(), type_=sa.Numeric(5, 2),
        postgresql_using='confidence::numeric',
    )

    # 5. Actor identity as VARCHAR(100): drop the users FK first. Default
    # PostgreSQL constraint names are assumed
    # (<table>_<column>_fkey); see downgrade note.
    op.drop_constraint('semantic_mappings_created_by_id_fkey',
                       'semantic_mappings', type_='foreignkey')
    op.alter_column(
        'semantic_mappings', 'created_by_id',
        new_column_name='created_by',
        existing_type=postgresql.UUID(as_uuid=True),
        type_=sa.String(100),
        postgresql_using='created_by_id::text',
    )
    op.alter_column('semantic_mappings', 'created_by',
                    existing_type=sa.String(100), nullable=False)

    op.drop_constraint('mapping_versions_changed_by_id_fkey',
                       'mapping_versions', type_='foreignkey')
    op.alter_column(
        'mapping_versions', 'changed_by_id',
        new_column_name='changed_by',
        existing_type=postgresql.UUID(as_uuid=True),
        type_=sa.String(100),
        postgresql_using='changed_by_id::text',
    )
    op.alter_column('mapping_versions', 'changed_by',
                    existing_type=sa.String(100), nullable=False)

    # 6. Model path NOT NULL on both tables (spec 15.1 DDL + section 12).
    op.alter_column('semantic_mappings', 'universal_model_path',
                    existing_type=sa.String(255), nullable=False)
    op.alter_column('mapping_versions', 'universal_model_path',
                    existing_type=sa.String(255), nullable=False)

    # 7. Identity uniqueness per spec 15.1.
    op.create_unique_constraint(
        'uq_semantic_mappings_identity_version',
        'semantic_mappings',
        ['vendor', 'platform', 'raw_syntax', 'version'],
    )

    # 8. ConfidenceHeld per version (F11 axis input), nullable for history.
    op.add_column('mapping_versions',
                  sa.Column('confidence', sa.Numeric(5, 2), nullable=True))


def downgrade() -> None:
    """Structural reversal only; reconciled/backfilled data is not restored.

    The two actor columns are converted BEFORE they are renamed: PostgreSQL
    evaluates the USING expression against the already-renamed column, so a
    single alter_column(new_column_name=..., postgresql_using='..._id::uuid')
    fails with "column ..._id does not exist".

    Known data limitation: created_by/changed_by now hold actor STRINGS, so
    this downgrade only succeeds while every stored actor string parses as a
    UUID. 005 (the forward direction) is the supported path.
    """
    op.drop_column('mapping_versions', 'confidence')
    op.drop_constraint('uq_semantic_mappings_identity_version',
                       'semantic_mappings', type_='unique')
    op.alter_column('mapping_versions', 'universal_model_path',
                    existing_type=sa.String(255), nullable=True)
    op.alter_column('semantic_mappings', 'universal_model_path',
                    existing_type=sa.String(255), nullable=True)
    op.alter_column('mapping_versions', 'changed_by',
                    existing_type=sa.String(100),
                    type_=postgresql.UUID(as_uuid=True),
                    postgresql_using='changed_by::uuid')
    op.alter_column('mapping_versions', 'changed_by',
                    new_column_name='changed_by_id',
                    existing_type=postgresql.UUID(as_uuid=True),
                    type_=postgresql.UUID(as_uuid=True))
    op.create_foreign_key('mapping_versions_changed_by_id_fkey',
                          'mapping_versions', 'users', ['changed_by_id'],
                          ['id'], ondelete='CASCADE')
    op.alter_column('semantic_mappings', 'created_by',
                    existing_type=sa.String(100),
                    type_=postgresql.UUID(as_uuid=True),
                    postgresql_using='created_by::uuid')
    op.alter_column('semantic_mappings', 'created_by',
                    new_column_name='created_by_id',
                    existing_type=postgresql.UUID(as_uuid=True),
                    type_=postgresql.UUID(as_uuid=True))
    op.create_foreign_key('semantic_mappings_created_by_id_fkey',
                          'semantic_mappings', 'users', ['created_by_id'],
                          ['id'], ondelete='CASCADE')
    op.alter_column('semantic_mappings', 'confidence',
                    existing_type=sa.Numeric(5, 2), type_=sa.Float(),
                    postgresql_using='confidence::float')
