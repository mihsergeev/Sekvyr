"""Замечания, о которых уже сообщали

Revision ID: 0015
Revises: 0014
Create Date: 2026-09-10

Панель сама обходит окружения и сообщает о новых замечаниях к значениям. Чтобы
сообщение приходило один раз, а не каждые несколько часов, панель помнит, о чем
уже говорила. Строка исчезает вместе с замечанием: если ошибку исправили, а
потом повторили, об этом стоит узнать снова.
"""
from alembic import op
import sqlalchemy as sa


revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "lint_seen",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "environment_id",
            sa.Integer(),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("path", sa.String(length=200), nullable=False, server_default="/"),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("code", sa.String(length=40), nullable=False),
        sa.Column(
            "first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint(
            "environment_id", "path", "name", "code", name="uq_lint_seen_place"
        ),
    )


def downgrade() -> None:
    op.drop_table("lint_seen")
