"""Из каких групп проект переехал

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-24

Агент помнит адрес проекта вместе с группой. Когда проект переносят в другую
группу, машинный контур находит его по прежнему адресу, но только если проект
действительно переехал оттуда. Раньше вместо этого брался любой одноименный
проект, выданный машине: стоило ей потерять право на свой, и она молча
получала значения тезки из соседней группы.
"""
from alembic import op
import sqlalchemy as sa


revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column("moved_from", sa.String(length=400), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("projects", "moved_from")
