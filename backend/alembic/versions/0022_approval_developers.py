"""Порог подтверждения 20 становится 30

Revision ID: 0022
Revises: 0021
Create Date: 2026-09-14

Наблюдатель теперь только читает, и порог 20 ("подтверждают правки
наблюдателей") потерял смысл. В интерфейсе он был подписан "правки разработчиков
и ниже", то есть владелец, выбравший его, хотел проверять правки разработчиков:
переводим в 30 - ровно в это.
"""
from alembic import op


revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE projects SET approval_min_level = 30 WHERE approval_min_level = 20")


def downgrade() -> None:
    # Какие проекты были на 20, уже не узнать; 30 строже, оставляем как есть.
    pass
