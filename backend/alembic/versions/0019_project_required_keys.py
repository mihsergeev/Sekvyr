"""Обязательные ключи проекта

Revision ID: 0019
Revises: 0018
Create Date: 2026-09-11

"Нет здесь, а рядом есть" подсказывает по соседним окружениям и молчит про
новое, где пусто везде. Список обязательных ключей - это требование проекта:
без них приложение не поднимется, и сказать об этом панель должна сразу.
"""
from alembic import op
import sqlalchemy as sa


revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column("required_keys", sa.String(length=2000), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("projects", "required_keys")
