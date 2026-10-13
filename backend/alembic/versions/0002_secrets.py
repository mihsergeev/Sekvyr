"""Проекты, окружения, ключи окружений, секреты и их версии

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-07

"""
from alembic import op
import sqlalchemy as sa


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('projects',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('slug', sa.String(length=64), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('e2e', sa.Boolean(), nullable=False),
    sa.Column('approval_min_level', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('slug')
    )
    op.create_table('environments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('position', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('project_id', 'name', name='uq_env_project_name')
    )
    op.create_table('project_key_wraps',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=False),
    sa.Column('subject_type', sa.String(length=16), nullable=False),
    sa.Column('subject_id', sa.Integer(), nullable=False),
    sa.Column('nonce', sa.String(length=32), nullable=False),
    sa.Column('wrapped_key', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('project_id', 'subject_type', 'subject_id', name='uq_wrap_project_subject')
    )
    op.create_table('env_keys',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('environment_id', sa.Integer(), nullable=False),
    sa.Column('generation', sa.Integer(), nullable=False),
    sa.Column('root_generation', sa.Integer(), nullable=False),
    sa.Column('nonce', sa.String(length=32), nullable=False),
    sa.Column('wrapped_key', sa.String(length=128), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['environment_id'], ['environments.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('environment_id', 'generation', name='uq_envkey_env_generation')
    )
    op.create_table('secrets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('environment_id', sa.Integer(), nullable=False),
    sa.Column('path', sa.String(length=200), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('current_version', sa.Integer(), nullable=False),
    sa.Column('deleted', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['environment_id'], ['environments.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('environment_id', 'path', 'name', name='uq_secret_env_path_name')
    )
    op.create_table('secret_versions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('secret_id', sa.Integer(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('name_at', sa.String(length=200), nullable=False),
    sa.Column('path_at', sa.String(length=200), nullable=False),
    sa.Column('deleted', sa.Boolean(), nullable=False),
    sa.Column('nonce', sa.String(length=32), nullable=False),
    sa.Column('ciphertext', sa.Text(), nullable=False),
    sa.Column('env_key_generation', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('author', sa.String(length=64), nullable=False),
    sa.Column('comment', sa.String(length=500), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['secret_id'], ['secrets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('secret_id', 'version', name='uq_version_secret_version')
    )
    op.create_index('ix_secret_versions_secret', 'secret_versions', ['secret_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_secret_versions_secret', table_name='secret_versions')
    op.drop_table('secret_versions')
    op.drop_table('secrets')
    op.drop_table('env_keys')
    op.drop_table('project_key_wraps')
    op.drop_table('environments')
    op.drop_table('projects')
