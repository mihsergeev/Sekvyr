"""Подпись ключа и срок замены значения

Revision ID: 0018
Revises: 0017
Create Date: 2026-09-11

Комментарий к правке живет в истории и отвечает на "что изменилось". Вопрос
"что это за ключ" задают, глядя на список имен, - для него нужна постоянная
подпись. Срок замены про третье: токен выдан на год, и напомнить о нем надо
заранее, а не показать возраст задним числом.
"""
from alembic import op
import sqlalchemy as sa


revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "secrets",
        sa.Column("note", sa.String(length=200), nullable=False, server_default=""),
    )
    op.add_column(
        "secrets",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("secrets", "expires_at")
    op.drop_column("secrets", "note")
