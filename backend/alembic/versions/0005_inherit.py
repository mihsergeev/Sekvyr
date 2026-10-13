"""Наследование окружений и группа проекта

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-07

"""
from alembic import op
import sqlalchemy as sa


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # batch_alter_table, потому что SQLite не умеет ALTER TABLE ADD CONSTRAINT:
    # alembic пересоздает таблицу и переносит данные. На Postgres это обычный
    # ALTER, так что миграция одна на обе базы.
    with op.batch_alter_table('environments') as batch:
        batch.add_column(sa.Column('parent_id', sa.Integer(), nullable=True))
        batch.create_foreign_key(
            'fk_environments_parent', 'environments', ['parent_id'], ['id'], ondelete='SET NULL'
        )
    op.add_column(
        'projects',
        sa.Column('group_name', sa.String(length=64), nullable=False, server_default=''),
    )
    op.add_column(
        'secret_versions',
        sa.Column('inherits', sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column('secret_versions', 'inherits')
    op.drop_column('projects', 'group_name')
    with op.batch_alter_table('environments') as batch:
        batch.drop_constraint('fk_environments_parent', type_='foreignkey')
        batch.drop_column('parent_id')
