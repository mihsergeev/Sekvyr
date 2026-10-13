"""Принятые замечания

Revision ID: 0014
Revises: 0013
Create Date: 2026-09-10

Замечание к значению бывает верным по форме и неверным по сути: `http` на
внутренний адрес, короткий токен, который таким и выдан у поставщика. Пока
такое замечание висит, человек учится пролистывать все остальные, - поэтому его
можно принять, и тогда панель молчит про этот ключ и эту проверку.

Принятие живет отдельной строкой, а не полем в значении: значение меняется
версиями, а решение "так и надо" относится к месту, а не к версии.
"""
from alembic import op
import sqlalchemy as sa


revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "lint_mutes",
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
        sa.Column("muted_by", sa.String(length=64), nullable=False, server_default=""),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint(
            "environment_id", "path", "name", "code", name="uq_lint_mute_place"
        ),
    )


def downgrade() -> None:
    op.drop_table("lint_mutes")
