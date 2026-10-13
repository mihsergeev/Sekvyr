"""С какого возраста значение считается давним

Revision ID: 0020
Revises: 0019
Create Date: 2026-09-11

Год был зашит в панель. Для токена оплаты это много, для внутреннего ключа
мало, и решать должен тот, кто ведет проект. Значение по умолчанию прежнее,
поэтому у существующих проектов ничего не меняется.
"""
from alembic import op
import sqlalchemy as sa


revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column("stale_after_days", sa.Integer(), nullable=False, server_default="365"),
    )


def downgrade() -> None:
    op.drop_column("projects", "stale_after_days")
