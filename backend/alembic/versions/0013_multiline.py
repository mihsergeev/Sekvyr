"""Признак многострочного значения

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-09

В списке ключей однострочный пароль и конфиг на полсотни строк выглядят
одинаково - восемь звездочек. А ведут себя они по-разному: один вставляют в
поле, другой открывают редактором. Признак пишется в момент сохранения, чтобы
списку не приходилось расшифровывать значения ради одной пометки.
"""
from alembic import op
import sqlalchemy as sa


revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("secret_versions") as batch:
        batch.add_column(
            sa.Column("multiline", sa.Boolean(), nullable=False, server_default=sa.false())
        )


def downgrade() -> None:
    with op.batch_alter_table("secret_versions") as batch:
        batch.drop_column("multiline")
