"""company baseline tables (organizations, company_baselines).

Company Baseline is an organization-level security configuration:
- organizations holds baseline_status + active_baseline_id
- company_baselines holds the selected CIS control scope per org
- users.organization_id links the authenticated user to their org

Fresh databases get these via Base.metadata.create_all; this migration
brings migrated databases up to the same contract (and backfills
users.organization_id for databases created before the column existed).

Revision ID: 009
Revises: 008
Create Date: 2026-09-29
"""
from alembic import op
import sqlalchemy as sa

revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'organizations',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('baseline_status', sa.String(50), nullable=False),
        sa.Column('active_baseline_id', sa.UUID(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_table(
        'company_baselines',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('framework', sa.String(50), nullable=False),
        sa.Column('benchmark', sa.String(255), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('controls', sa.JSON(), nullable=False),
        sa.Column('created_by', sa.String(100), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('activated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    # Backfill users.organization_id for migrated databases. Safe: column
    # may already exist if create_all ran against the same database.
    inspector = sa.inspect(op.get_bind())
    if 'organization_id' not in [
        c['name'] for c in inspector.get_columns('users')
    ]:
        op.add_column('users', sa.Column('organization_id', sa.UUID(), nullable=True))
        op.create_foreign_key(
            'fk_users_organization', 'users', 'organizations',
            ['organization_id'], ['id'], ondelete='SET NULL')


def downgrade() -> None:
    op.drop_table('company_baselines')
    op.drop_table('organizations')
    inspector = sa.inspect(op.get_bind())
    if 'organization_id' in [
        c['name'] for c in inspector.get_columns('users')
    ]:
        op.drop_constraint('fk_users_organization', 'users', type_='foreignkey')
        op.drop_column('users', 'organization_id')