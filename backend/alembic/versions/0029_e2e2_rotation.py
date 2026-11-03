"""Derived authority floors and separate future/current epoch reader wrappers.

Revision ID: 0029
Revises: 0028
"""
from alembic import op
import sqlalchemy as sa

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("e2e2_authority_projections",
        sa.Column("view_id", sa.String(36), sa.ForeignKey("e2e2_views.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("genesis_hash", sa.String(64), nullable=False),
        sa.Column("journal_sequence", sa.String(20), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.Column("witness_epoch", sa.String(20), nullable=False),
        sa.Column("authority_revision", sa.String(20), nullable=False),
        sa.Column("authority_digest", sa.String(64), nullable=False))
    for table in ("e2e2_epoch_reader_grants", "e2e2_staged_reader_wraps"):
        op.create_table(table,
            sa.Column("view_id", sa.String(36), sa.ForeignKey("e2e2_views.id", ondelete="RESTRICT"), primary_key=True),
            sa.Column("machine_id", sa.Integer(), sa.ForeignKey("machine_identities.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("read_key_epoch", sa.String(20), primary_key=True),
            sa.Column("publisher_policy_epoch", sa.String(20), primary_key=True),
            sa.Column("recipient_fingerprint", sa.String(76), nullable=False),
            sa.Column("canonical_wrapper", sa.Text(), nullable=False),
            sa.Column("created_by", sa.String(64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.execute(sa.text("INSERT INTO e2e2_epoch_reader_grants (view_id, machine_id, read_key_epoch, publisher_policy_epoch, recipient_fingerprint, canonical_wrapper, created_by, created_at) SELECT view_id, machine_id, read_key_epoch, publisher_policy_epoch, recipient_fingerprint, canonical_wrapper, created_by, created_at FROM e2e2_reader_grants"))


def downgrade() -> None:
    op.drop_table("e2e2_staged_reader_wraps")
    op.drop_table("e2e2_epoch_reader_grants")
    op.drop_table("e2e2_authority_projections")
