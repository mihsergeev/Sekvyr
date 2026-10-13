"""Приложения, которые сервер обслуживает

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-09

Раньше сервер рассказывал о себе одной строкой: версия агента и что он применил
последним. Пока агент обслуживал одно приложение, этого хватало. Теперь агент на
сервере один, а приложений у него список, и "последнее примененное" перестало
отвечать на вопрос, ради которого его заводили: какое приложение на каком
сервере читает это окружение и в какой файл оно попадает.
"""
from alembic import op
import sqlalchemy as sa


revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "machine_apps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "machine_id",
            sa.Integer(),
            sa.ForeignKey("machine_identities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("group_slug", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("project_slug", sa.String(length=120), nullable=False),
        sa.Column("env_name", sa.String(length=120), nullable=False),
        sa.Column("path", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("applied", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "machine_id",
            "group_slug",
            "project_slug",
            "env_name",
            name="uq_machine_apps_target",
        ),
    )
    op.create_index("ix_machine_apps_machine", "machine_apps", ["machine_id"])


def downgrade() -> None:
    op.drop_index("ix_machine_apps_machine", table_name="machine_apps")
    op.drop_table("machine_apps")
