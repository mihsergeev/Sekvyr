"""Уровень автора правки и уровень того, кто отключил учетку

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-24

Подтвердить правку может только роль выше автора. Уровень автора брался в
момент подтверждения, и стоило понизить автора, как его правку подтверждал
равный ему по прежней роли. Теперь уровень пишется в версию при предложении.
У правок, предложенных до этой миграции, его нет, и для них берется текущая
роль автора, как раньше.

Отключенную владельцем учетку включал обратно любой ответственный. Теперь
запоминается уровень того, кто отключил, и включить может только роль не ниже.
Учетки, отключенные до этой миграции, считаются отключенными владельцем.
"""
from alembic import op
import sqlalchemy as sa


revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("secret_versions", sa.Column("author_level", sa.Integer(), nullable=True))
    op.add_column("users", sa.Column("disabled_by_level", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "disabled_by_level")
    op.drop_column("secret_versions", "author_level")
