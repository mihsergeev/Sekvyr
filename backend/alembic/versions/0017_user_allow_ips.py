"""Белый список адресов у учетной записи

Revision ID: 0017
Revises: 0016
Create Date: 2026-09-11

У машин список адресов был с самого начала, у людей - нет: украденный пароль
работал откуда угодно. Пусто означает "откуда угодно", поэтому существующие
учетные записи после этой миграции работают ровно как прежде.
"""
from alembic import op
import sqlalchemy as sa


revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("allow_ips", sa.String(length=500), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("users", "allow_ips")
