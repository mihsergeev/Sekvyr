"""Публичный ключ ноды для проектов с шифрованием в браузере

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-08

Таблица оберток ключа проекта заведена еще в 0002: тогда она была заделом под
этот режим, теперь начала наполняться. Здесь добавляется только то, чего не
хватало, - публичный ключ машины, на который человек запечатывает ключ проекта.
"""
from alembic import op
import sqlalchemy as sa


revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("machine_identities") as batch:
        batch.add_column(
            sa.Column("public_key", sa.String(length=200), nullable=False, server_default="")
        )


def downgrade() -> None:
    with op.batch_alter_table("machine_identities") as batch:
        batch.drop_column("public_key")
