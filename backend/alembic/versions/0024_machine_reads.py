"""Повторные чтения машин не пишутся в журнал строкой каждое

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-05

Агент спрашивает панель раз в минуту по каждому приложению, и журнал рос на
тысячи одинаковых строк в сутки с каждого сервера. В таблице лежит, с чем
машина забрала окружение, когда это последний раз попало в журнал: отпечаток
набора по номерам версий, адреса, время и сколько повторов было после.
"""
from alembic import op
import sqlalchemy as sa


revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "machine_reads",
        sa.Column(
            "machine_id",
            sa.Integer(),
            sa.ForeignKey("machine_identities.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "environment_id",
            sa.Integer(),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("fingerprint", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("ips", sa.String(length=600), nullable=False, server_default=""),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("repeats", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("machine_reads")
