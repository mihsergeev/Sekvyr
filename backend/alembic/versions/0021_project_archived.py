"""Проект в архиве

Revision ID: 0021
Revises: 0020
Create Date: 2026-09-12

Через пару лет половина списка - это проекты, которых уже нет: сервис выключили,
лендинг отгорел, стенд снесли. Удалять их нельзя (ключи и журнал нужны для
разбора), а в списке они мешают всем. Флаг убирает проект из общего списка в
раздел "Архив"; вернуть можно в любой момент.
"""
from alembic import op
import sqlalchemy as sa


revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("projects", "archived")
