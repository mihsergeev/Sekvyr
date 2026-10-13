"""Машинные личности

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-08

"""
from alembic import op
import sqlalchemy as sa


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "machine_identities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("secret_hash", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("allow_ips", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("agent_version", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("applied", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_ip", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(length=64), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("client_id"),
    )


def downgrade() -> None:
    # Права и ключи проектов машин уходят вместе с таблицей: после повторного
    # upgrade номера машин начинаются заново, и новая машина 1 получила бы
    # права и ключи прежней.
    op.execute("DELETE FROM policies WHERE subject_type = 'machine'")
    op.execute("DELETE FROM project_key_wraps WHERE subject_type = 'machine'")
    op.drop_table("machine_identities")
