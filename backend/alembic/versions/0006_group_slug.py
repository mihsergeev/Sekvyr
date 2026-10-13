"""Группа становится частью имени проекта

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-07

Проект `frontend` бывает и у globex, и у initech. Глобально уникальное имя
заставляло писать "globex-frontend" руками - то есть держать группу в имени
дважды. Теперь имя уникально внутри группы, а в адресе группа стоит отдельным
куском.
"""
from alembic import op
import sqlalchemy as sa

from app.naming import slugify


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def _projects_table(with_group_slug: bool) -> sa.Table:
    """Таблица целиком - она нужна SQLite, который пересоздает её при смене
    ограничений и должен знать, что именно пересоздавать."""
    columns = [
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("group_name", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("e2e", sa.Boolean(), nullable=False),
        sa.Column("approval_min_level", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    ]
    constraints: list[sa.schema.SchemaItem] = [sa.PrimaryKeyConstraint("id")]
    if with_group_slug:
        columns.append(
            sa.Column("group_slug", sa.String(length=64), nullable=False, server_default="")
        )
        constraints.append(
            sa.UniqueConstraint("group_slug", "slug", name="uq_projects_group_slug")
        )
    else:
        constraints.append(sa.UniqueConstraint("slug"))
    return sa.Table("projects", sa.MetaData(), *columns, *constraints)


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column("group_slug", sa.String(length=64), nullable=False, server_default=""),
    )

    # Заполняем по имени группы: отдельной сущностью группа не становится, это
    # по-прежнему подпись у проекта - но подпись, попадающая в адрес.
    projects = sa.table(
        "projects",
        sa.column("id", sa.Integer),
        sa.column("group_name", sa.String),
        sa.column("group_slug", sa.String),
    )
    connection = op.get_bind()
    for row in connection.execute(sa.select(projects.c.id, projects.c.group_name)):
        connection.execute(
            projects.update()
            .where(projects.c.id == row.id)
            .values(group_slug=slugify(row.group_name or ""))
        )

    # Старая уникальность по одному slug уступает место паре "группа + имя".
    # SQLite не умеет снимать ограничения - там таблица пересоздается целиком;
    # Postgres обходится обычным ALTER, и имя ограничения у него предсказуемо.
    if connection.dialect.name == "sqlite":
        with op.batch_alter_table(
            "projects", copy_from=_projects_table(True), recreate="always"
        ):
            pass
    else:
        op.drop_constraint("projects_slug_key", "projects", type_="unique")
        op.create_unique_constraint(
            "uq_projects_group_slug", "projects", ["group_slug", "slug"]
        )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "sqlite":
        with op.batch_alter_table(
            "projects", copy_from=_projects_table(False), recreate="always"
        ):
            pass
    else:
        op.drop_constraint("uq_projects_group_slug", "projects", type_="unique")
        op.create_unique_constraint("projects_slug_key", "projects", ["slug"])
        op.drop_column("projects", "group_slug")
