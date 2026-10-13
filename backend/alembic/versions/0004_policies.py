"""Группы, политики доступа и подтверждение изменений

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-07

"""
from alembic import op
import sqlalchemy as sa


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('groups',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('group_members',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('group_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['group_id'], ['groups.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('group_id', 'user_id', name='uq_group_member')
    )
    op.create_table('policies',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('subject_type', sa.String(length=16), nullable=False),
    sa.Column('subject_id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=True),
    sa.Column('environment_id', sa.Integer(), nullable=True),
    sa.Column('path_prefix', sa.String(length=200), nullable=False),
    sa.Column('actions', sa.String(length=200), nullable=False),
    sa.Column('effect', sa.String(length=8), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('require_2fa', sa.Boolean(), nullable=False),
    sa.Column('created_by', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['environment_id'], ['environments.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_policies_subject', 'policies', ['subject_type', 'subject_id'], unique=False)
    # server_default обязателен: колонка NOT NULL добавляется в таблицу, где уже
    # есть строки, и без значения по умолчанию миграция падает - на пустой базе
    # это незаметно, а на рабочей ломает обновление.
    op.add_column(
        'secret_versions',
        sa.Column('reviewed_by', sa.String(length=64), nullable=False, server_default=''),
    )
    op.add_column('secret_versions', sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        'secret_versions',
        sa.Column('review_note', sa.String(length=500), nullable=False, server_default=''),
    )


    # --- перенос прав ------------------------------------------------------
    # До этой миграции роль работала глобально: ответственный и выше читали и
    # писали везде, остальные видели список ключей. Включить политики и ничего
    # не перенести значило бы отобрать доступ у всех разом - поэтому заводим
    # политики, повторяющие вчерашнее поведение. Дальше владелец режет их
    # точечно, а не выдает все заново.
    users = sa.table(
        "users",
        sa.column("id", sa.Integer),
        sa.column("username", sa.String),
        sa.column("role", sa.String),
    )
    policies = sa.table(
        "policies",
        sa.column("subject_type", sa.String),
        sa.column("subject_id", sa.Integer),
        sa.column("project_id", sa.Integer),
        sa.column("environment_id", sa.Integer),
        sa.column("path_prefix", sa.String),
        sa.column("actions", sa.String),
        sa.column("effect", sa.String),
        sa.column("require_2fa", sa.Boolean),
        sa.column("created_by", sa.String),
    )
    conn = op.get_bind()
    rows = conn.execute(sa.select(users.c.id, users.c.role)).fetchall()
    seed = []
    for user_id, role in rows:
        if role == "owner":
            continue  # владельцу политики не нужны: у него и так все
        actions = (
            "list,read,write,delete,rotate,approve"
            if role == "maintainer"
            else "list"
        )
        seed.append(
            {
                "subject_type": "user",
                "subject_id": user_id,
                "project_id": None,
                "environment_id": None,
                "path_prefix": "/",
                "actions": actions,
                "effect": "allow",
                "require_2fa": False,
                "created_by": "миграция 0004",
            }
        )
    if seed:
        op.bulk_insert(policies, seed)


def downgrade() -> None:
    op.drop_column('secret_versions', 'review_note')
    op.drop_column('secret_versions', 'reviewed_at')
    op.drop_column('secret_versions', 'reviewed_by')
    op.drop_index('ix_policies_subject', table_name='policies')
    op.drop_table('policies')
    op.drop_table('group_members')
    op.drop_table('groups')
