"""Именованные снимки окружений

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-07 21:29:10.804353

"""
from alembic import op
import sqlalchemy as sa


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('env_snapshots',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('environment_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('author', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['environment_id'], ['environments.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('environment_id', 'name', name='uq_snapshot_env_name')
    )
    op.create_table('env_snapshot_items',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('snapshot_id', sa.Integer(), nullable=False),
    sa.Column('secret_id', sa.Integer(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['secret_id'], ['secrets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['snapshot_id'], ['env_snapshots.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('snapshot_id', 'secret_id', name='uq_snapshot_item')
    )


def downgrade() -> None:
    op.drop_table('env_snapshot_items')
    op.drop_table('env_snapshots')
