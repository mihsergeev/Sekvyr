"""Ремонт данных, оставленных версиями до 1.0.0

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-13

Три следа старых версий, которые новый код сам не создает, но и не лечит:

  * сироты в SQLite. Внешние ключи там были выключены, и удаление проекта,
    снимка или машины оставляло их строки. SQLite отдает освободившийся номер
    следующей записи, и новый проект получал окружения, значения и права
    удаленного, новая машина - его приложения;
  * две текущие версии у одного ключа (подтверждение и запись шли без
    блокировки окружения): запись новой версии переводила в историю только
    одну из них, и наружу молча уезжало старое значение;
  * ожидающие правки, после которых ключ уже меняли (переименовали): теперь
    такие снимаются сразу, а старые висели навсегда, и ни подтвердить, ни
    отклонить их было нельзя.

На Postgres сирот не бывает (ключи там всегда включены), и первая часть
ничего не находит.
"""
from alembic import op
import sqlalchemy as sa


revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None

STALE_NOTE = "устарела: ключ изменили позже"


def _orphans(bind) -> None:
    insp = sa.inspect(bind)
    links = []
    for table in insp.get_table_names():
        for fk in insp.get_foreign_keys(table):
            if len(fk.get("constrained_columns") or []) != 1:
                continue
            rule = ((fk.get("options") or {}).get("ondelete") or "").upper()
            if rule not in ("CASCADE", "SET NULL"):
                continue
            links.append(
                (table, fk["constrained_columns"][0], fk["referred_table"], fk["referred_columns"][0], rule)
            )
    # Цепочки (проект - окружение - ключ - версия) снимаются за несколько
    # проходов: строка становится сиротой, когда ушел ее родитель.
    while True:
        touched = 0
        for table, column, parent, parent_column, rule in links:
            # NOT EXISTS, а не NOT IN: на большой таблице Postgres переходит
            # с NOT IN на квадратичный план, а панель на время миграций лежит.
            lost = (
                f'"{table}"."{column}" IS NOT NULL AND NOT EXISTS '
                f'(SELECT 1 FROM "{parent}" AS p WHERE p."{parent_column}" = "{table}"."{column}")'
            )
            if rule == "CASCADE":
                result = bind.execute(sa.text(f'DELETE FROM "{table}" WHERE {lost}'))
            else:
                result = bind.execute(sa.text(f'UPDATE "{table}" SET "{column}" = NULL WHERE {lost}'))
            touched += result.rowcount or 0
        if not touched:
            break


def _double_current(bind) -> None:
    # Действует старшая из текущих, остальные - история.
    bind.execute(
        sa.text(
            "UPDATE secret_versions SET status = 'superseded' "
            "WHERE status = 'current' AND EXISTS (SELECT 1 FROM secret_versions newer "
            "WHERE newer.secret_id = secret_versions.secret_id AND newer.status = 'current' "
            "AND newer.version > secret_versions.version)"
        )
    )
    rows = bind.execute(
        sa.text(
            "SELECT s.id, s.environment_id, s.path, s.name, v.version, v.name_at, v.path_at, "
            "v.deleted, v.inherits FROM secrets s JOIN secret_versions v "
            "ON v.secret_id = s.id AND v.status = 'current' "
            "WHERE s.current_version <> v.version"
        )
    ).fetchall()
    for sid, env_id, path, name, version, name_at, path_at, deleted, inherits in rows:
        place = (path, name)
        if (path_at, name_at) != place:
            busy = bind.execute(
                sa.text(
                    "SELECT 1 FROM secrets WHERE environment_id = :env AND path = :path "
                    "AND name = :name AND id <> :sid"
                ),
                {"env": env_id, "path": path_at, "name": name_at, "sid": sid},
            ).first()
            if busy is None:
                place = (path_at, name_at)
        bind.execute(
            sa.text(
                "UPDATE secrets SET current_version = :version, deleted = :deleted, "
                "path = :path, name = :name WHERE id = :sid"
            ),
            {
                "version": version,
                "deleted": bool(deleted or inherits),
                "path": place[0],
                "name": place[1],
                "sid": sid,
            },
        )


def _stale_pending(bind) -> None:
    bind.execute(
        sa.text(
            "UPDATE secret_versions SET status = 'rejected', reviewed_by = 'система', "
            "reviewed_at = CURRENT_TIMESTAMP, review_note = :note "
            "WHERE status = 'pending' AND EXISTS (SELECT 1 FROM secret_versions newer "
            "WHERE newer.secret_id = secret_versions.secret_id "
            "AND newer.version > secret_versions.version "
            "AND newer.status IN ('current', 'superseded'))"
        ),
        {"note": STALE_NOTE},
    )


def upgrade() -> None:
    bind = op.get_bind()
    _orphans(bind)
    _double_current(bind)
    _stale_pending(bind)


def downgrade() -> None:
    # Ремонт данных назад не откатывается: прежнее состояние было ошибкой.
    pass
