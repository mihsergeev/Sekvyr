"""Система и локальный адрес сервера

Revision ID: 0016
Revises: 0015
Create Date: 2026-09-10

Внешний адрес панель видит по соединению и уже хранит. Систему и адрес во
внутренней сети знает только сам сервер - их присылает агент своим отчетом.
Пока агент старый, поля пустые: панель показывает то, что знает.
"""
from alembic import op
import sqlalchemy as sa


revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "machine_identities",
        sa.Column("os", sa.String(length=128), nullable=False, server_default=""),
    )
    op.add_column(
        "machine_identities",
        sa.Column("local_ip", sa.String(length=64), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("machine_identities", "local_ip")
    op.drop_column("machine_identities", "os")
