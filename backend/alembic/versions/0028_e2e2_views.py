"""Explicit E2E2 views, immutable staged envelopes and reader grants.

Revision ID: 0028
Revises: 0027
"""
from alembic import op
import sqlalchemy as sa

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("e2e2_realms", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("realm_uuid", sa.String(36), nullable=False, unique=True))
    op.create_table("e2e2_project_identities", sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True), sa.Column("project_uuid", sa.String(36), nullable=False, unique=True))
    op.create_table("e2e2_environment_identities", sa.Column("environment_id", sa.Integer(), sa.ForeignKey("environments.id", ondelete="CASCADE"), primary_key=True), sa.Column("environment_uuid", sa.String(36), nullable=False, unique=True))
    op.create_table("e2e2_views",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("realm_uuid", sa.String(36), nullable=False),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("environment_id", sa.Integer(), sa.ForeignKey("environments.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("project_uuid", sa.String(36), nullable=False), sa.Column("environment_uuid", sa.String(36), nullable=False),
        sa.Column("log_uuid", sa.String(36), nullable=False, unique=True), sa.Column("publisher_keys", sa.Text(), nullable=False),
        sa.Column("read_key_epoch", sa.String(20), nullable=False), sa.Column("publisher_policy_epoch", sa.String(20), nullable=False),
        sa.Column("indexed_sequence", sa.String(20), nullable=False), sa.Column("indexed_hash", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_index("ix_e2e2_views_project_id", "e2e2_views", ["project_id"])
    op.create_index("ix_e2e2_views_environment_id", "e2e2_views", ["environment_id"])
    op.create_table("e2e2_envelopes",
        sa.Column("envelope_hash", sa.String(64), primary_key=True), sa.Column("view_id", sa.String(36), sa.ForeignKey("e2e2_views.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("sequence", sa.String(20), nullable=False), sa.Column("canonical_envelope", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_index("ix_e2e2_envelopes_view_id", "e2e2_envelopes", ["view_id"])
    op.create_table("e2e2_reader_grants",
        sa.Column("view_id", sa.String(36), sa.ForeignKey("e2e2_views.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("machine_id", sa.Integer(), sa.ForeignKey("machine_identities.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("recipient_fingerprint", sa.String(76), nullable=False), sa.Column("canonical_wrapper", sa.Text(), nullable=False),
        sa.Column("read_key_epoch", sa.String(20), nullable=False), sa.Column("publisher_policy_epoch", sa.String(20), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))


def downgrade() -> None:
    op.drop_table("e2e2_reader_grants")
    op.drop_index("ix_e2e2_envelopes_view_id", table_name="e2e2_envelopes")
    op.drop_table("e2e2_envelopes")
    op.drop_index("ix_e2e2_views_environment_id", table_name="e2e2_views")
    op.drop_index("ix_e2e2_views_project_id", table_name="e2e2_views")
    op.drop_table("e2e2_views")
    op.drop_table("e2e2_environment_identities")
    op.drop_table("e2e2_project_identities")
    op.drop_table("e2e2_realms")
