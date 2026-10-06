"""Initial migration

Revision ID: 001
Revises: 
Create Date: 2026-08-25

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email', sa.String(255), unique=True, nullable=False, index=True),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('role', sa.String(50), nullable=False, server_default='auditor'),
        sa.Column('is_active', sa.Boolean, server_default='true'),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # Devices table
    op.create_table(
        'devices',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('vendor', sa.String(50), nullable=True),
        sa.Column('platform', sa.String(50), nullable=True),
        sa.Column('firmware_version', sa.String(50), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('notes', sa.Text, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_devices_user_id', 'devices', ['user_id'])

    # Configurations table
    op.create_table(
        'configurations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='SET NULL'), nullable=True),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('content_hash', sa.String(64), nullable=False),
        sa.Column('raw_content', sa.Text, nullable=False),
        sa.Column('content_type', sa.String(50), nullable=False),
        sa.Column('size_bytes', sa.Integer, nullable=False),
        sa.Column('line_count', sa.Integer, nullable=False),
        sa.Column('encoding', sa.String(50), nullable=False, server_default='utf-8'),
        sa.Column('encrypted', sa.Boolean, server_default='false'),
        sa.Column('uploaded_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_configurations_device_id', 'configurations', ['device_id'])
    op.create_index('ix_configurations_content_hash', 'configurations', ['content_hash'])

    # Audits table
    op.create_table(
        'audits',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('status', sa.String(50), nullable=False, server_default='pending'),
        sa.Column('started_at', sa.DateTime, nullable=True),
        sa.Column('completed_at', sa.DateTime, nullable=True),
        sa.Column('overall_score', sa.Float, nullable=True),
        sa.Column('report_url', sa.String(500), nullable=True),
        sa.Column('configuration_count', sa.Integer, server_default='0'),
        sa.Column('findings_count', sa.Integer, server_default='0'),
        sa.Column('critical_findings', sa.Integer, server_default='0'),
        sa.Column('high_findings', sa.Integer, server_default='0'),
        sa.Column('medium_findings', sa.Integer, server_default='0'),
        sa.Column('low_findings', sa.Integer, server_default='0'),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_audits_user_id', 'audits', ['user_id'])
    op.create_index('ix_audits_status', 'audits', ['status'])

    # Audit Configurations junction table
    op.create_table(
        'audit_configurations',
        sa.Column('audit_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('audits.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('configuration_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('configurations.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('vendor_identification', postgresql.JSONB, nullable=True),
        sa.Column('parsed_configuration_id', postgresql.UUID(as_uuid=True), nullable=True),
    )

    # Vendor Identifications table
    op.create_table(
        'vendor_identifications',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('configuration_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('configurations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('vendor', sa.String(50), nullable=False),
        sa.Column('platform', sa.String(50), nullable=False),
        sa.Column('firmware_version', sa.String(50), nullable=True),
        sa.Column('confidence', sa.Float, nullable=False),
        sa.Column('detection_method', sa.String(50), nullable=False),
        sa.Column('detection_evidence', postgresql.JSONB, nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_vendor_identifications_configuration_id', 'vendor_identifications', ['configuration_id'])

    # Parsed Configurations table
    op.create_table(
        'parsed_configurations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('configuration_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('configurations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('vendor', sa.String(50), nullable=False),
        sa.Column('platform', sa.String(50), nullable=False),
        sa.Column('parse_tree', postgresql.JSONB, nullable=False),
        sa.Column('parse_errors', postgresql.JSONB, nullable=False),
        sa.Column('parse_warnings', postgresql.JSONB, nullable=False),
        sa.Column('unknown_sections', postgresql.JSONB, nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_parsed_configurations_configuration_id', 'parsed_configurations', ['configuration_id'])

    # Semantic Interpretations table
    op.create_table(
        'semantic_interpretations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('parsed_configuration_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('parsed_configurations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('semantic_sections', postgresql.JSONB, nullable=False),
        sa.Column('confidence_scores', postgresql.JSONB, nullable=False),
        sa.Column('unknown_meanings', postgresql.JSONB, nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_semantic_interpretations_parsed_configuration_id', 'semantic_interpretations', ['parsed_configuration_id'])

    # Normalized Configurations table
    op.create_table(
        'normalized_configurations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('semantic_interpretation_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('semantic_interpretations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('universal_model_version', sa.String(50), nullable=False),
        sa.Column('normalized_values', postgresql.JSONB, nullable=False),
        sa.Column('unmapped_concepts', postgresql.JSONB, nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_normalized_configurations_semantic_interpretation_id', 'normalized_configurations', ['semantic_interpretation_id'])

    # Compliance Results table
    op.create_table(
        'compliance_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('audit_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('audits.id', ondelete='CASCADE'), nullable=False),
        sa.Column('normalized_configuration_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('normalized_configurations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('framework', sa.String(50), nullable=False),
        sa.Column('framework_version', sa.String(50), nullable=True),
        sa.Column('control_id', sa.String(100), nullable=False),
        sa.Column('control_name', sa.String(255), nullable=False),
        sa.Column('control_description', sa.Text, nullable=True),
        sa.Column('result', sa.String(10), nullable=False),
        sa.Column('confidence', sa.Float, nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('evidence', postgresql.JSONB, nullable=False),
        sa.Column('remediation', postgresql.JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_compliance_results_audit_id', 'compliance_results', ['audit_id'])
    op.create_index('ix_compliance_results_control_id', 'compliance_results', ['control_id'])
    op.create_index('ix_compliance_results_framework', 'compliance_results', ['framework'])

    # Findings table
    op.create_table(
        'findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('audit_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('audits.id', ondelete='CASCADE'), nullable=False),
        sa.Column('compliance_result_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('compliance_results.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text, nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('confidence', sa.Float, nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default='open'),
        sa.Column('evidence', postgresql.JSONB, nullable=False),
        sa.Column('remediation', postgresql.JSONB, nullable=True),
        sa.Column('affected_device', sa.String(255), nullable=True),
        sa.Column('affected_vendor', sa.String(50), nullable=True),
        sa.Column('affected_platform', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_findings_audit_id', 'findings', ['audit_id'])
    op.create_index('ix_findings_compliance_result_id', 'findings', ['compliance_result_id'])
    op.create_index('ix_findings_severity', 'findings', ['severity'])
    op.create_index('ix_findings_status', 'findings', ['status'])

    # Semantic Mappings (Training) table
    op.create_table(
        'semantic_mappings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('vendor', sa.String(50), nullable=False),
        sa.Column('platform', sa.String(50), nullable=False),
        sa.Column('raw_syntax', sa.Text, nullable=False),
        sa.Column('semantic_meaning', sa.Text, nullable=False),
        sa.Column('universal_model_path', sa.String(255), nullable=True),
        sa.Column('confidence', sa.Float, nullable=False),
        sa.Column('admin_confirmed', sa.Boolean, server_default='false'),
        sa.Column('admin_notes', sa.Text, nullable=True),
        sa.Column('version', sa.Integer, nullable=False, server_default='1'),
        sa.Column('created_by_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_semantic_mappings_vendor_platform', 'semantic_mappings', ['vendor', 'platform'])

    # Mapping Versions table
    op.create_table(
        'mapping_versions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('mapping_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('semantic_mappings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('version', sa.Integer, nullable=False),
        sa.Column('raw_syntax', sa.Text, nullable=False),
        sa.Column('semantic_meaning', sa.Text, nullable=False),
        sa.Column('universal_model_path', sa.String(255), nullable=True),
        sa.Column('changed_by_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('changed_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('change_reason', sa.Text, nullable=True),
    )
    op.create_index('ix_mapping_versions_mapping_id', 'mapping_versions', ['mapping_id'])

    # Audit Trail table
    op.create_table(
        'audit_trail',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('entity_type', sa.String(50), nullable=False),
        sa.Column('entity_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action', sa.String(50), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('details', postgresql.JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_audit_trail_entity', 'audit_trail', ['entity_type', 'entity_id'])
    op.create_index('ix_audit_trail_user_id', 'audit_trail', ['user_id'])


def downgrade() -> None:
    op.drop_table('audit_trail')
    op.drop_table('mapping_versions')
    op.drop_table('semantic_mappings')
    op.drop_table('findings')
    op.drop_table('compliance_results')
    op.drop_table('normalized_configurations')
    op.drop_table('semantic_interpretations')
    op.drop_table('parsed_configurations')
    op.drop_table('vendor_identifications')
    op.drop_table('audit_configurations')
    op.drop_table('audits')
    op.drop_table('configurations')
    op.drop_table('devices')
    op.drop_table('users')
