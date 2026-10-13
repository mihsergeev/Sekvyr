"""Кластеры Kubernetes и привязка ServiceAccount к личности

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-08

"""
from alembic import op
import sqlalchemy as sa


revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "clusters",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("issuer", sa.String(length=300), nullable=False),
        sa.Column("audience", sa.String(length=120), nullable=False, server_default="sekvyr"),
        sa.Column("jwks", sa.Text(), nullable=False, server_default=""),
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(length=64), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    with op.batch_alter_table("machine_identities") as batch:
        batch.add_column(sa.Column("cluster_id", sa.Integer(), nullable=True))
        batch.add_column(
            sa.Column("k8s_namespace", sa.String(length=120), nullable=False, server_default="")
        )
        batch.add_column(
            sa.Column(
                "k8s_service_account", sa.String(length=120), nullable=False, server_default=""
            )
        )
        batch.create_foreign_key(
            "fk_machine_cluster", "clusters", ["cluster_id"], ["id"], ondelete="CASCADE"
        )


def downgrade() -> None:
    with op.batch_alter_table("machine_identities") as batch:
        batch.drop_constraint("fk_machine_cluster", type_="foreignkey")
        batch.drop_column("k8s_service_account")
        batch.drop_column("k8s_namespace")
        batch.drop_column("cluster_id")
    op.drop_table("clusters")
