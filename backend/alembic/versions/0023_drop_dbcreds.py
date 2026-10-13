"""Таблицы временных доступов к базам удалены

Revision ID: 0023
Revises: 0022
Create Date: 2026-09-15

Функция убрана из панели в 0.76.0: описаний баз и выданных ролей больше никто
не читает. Записи о выдачах остаются в журнале. Откат возвращает пустые таблицы
в том виде, в каком их заводила миграция 0010, - сами описания баз с
зашифрованными строками подключения после удаления уже не вернуть.
"""
from alembic import op
import sqlalchemy as sa


revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("db_leases")
    op.drop_table("db_targets")


def downgrade() -> None:
    op.create_table(
        "db_targets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("environment_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False, server_default="postgres"),
        sa.Column("host", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("port", sa.Integer(), nullable=False, server_default="5432"),
        sa.Column("database", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("admin_nonce", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("admin_dsn", sa.Text(), nullable=False, server_default=""),
        sa.Column("env_key_generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("grant_sql", sa.Text(), nullable=False, server_default=""),
        sa.Column("revoke_sql", sa.Text(), nullable=False, server_default=""),
        sa.Column("ttl_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("max_ttl_minutes", sa.Integer(), nullable=False, server_default="720"),
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(length=64), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["environment_id"], ["environments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("environment_id", "name", name="uq_dbtarget_env_name"),
    )
    op.create_table(
        "db_leases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("subject", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("role_name", sa.String(length=64), nullable=False),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome", sa.String(length=200), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["target_id"], ["db_targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("role_name"),
    )
