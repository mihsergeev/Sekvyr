"""SQLAlchemy-модели Sekvyr.

  - User         - учетка человека (пароль, роль, второй фактор, версия токена)
  - LoginFailure - счетчик неудачных попыток входа
  - AuditLog     - журнал действий, связанный хеш-цепочкой
  - AppSetting   - настройки, редактируемые из интерфейса (kv поверх env)
  - Project / Environment - где живут секреты
  - EnvKey       - ключ окружения, обернутый корневым ключом
  - Secret / SecretVersion - сам секрет и вся его история
  - ProjectKeyWrap - ключ проекта с шифрованием в браузере, запечатанный для
    человека или машины
  - Policy, MachineIdentity и остальное ниже - права, машины и их токены

Модуль импортируется alembic/env.py, чтобы наполнить Base.metadata.
"""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.roles import OWNER


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    # owner / maintainer / developer / viewer - см. app/roles.py. Права на
    # конкретные проекты дают политики (Policy), роль задает иерархию.
    role: Mapped[str] = mapped_column(String(16), default=OWNER)
    # Учетку не удаляют, а отключают, когда человек ушел: удаление увело бы за
    # собой его след в журнале, а журнал должен оставаться читаемым.
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Уровень роли того, кто отключил. Включить обратно может только роль не
    # ниже: иначе ответственный возвращал уволенного владельцем. Пусто у учеток,
    # отключенных до 1.0.1, - они считаются отключенными владельцем.
    disabled_by_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Откуда пускать: адреса и подсети через пробел, как у машин. Пусто -
    # откуда угодно; это состояние по умолчанию, и менять его должен человек,
    # который знает, из какой сети приходит эта учетная запись.
    allow_ips: Mapped[str] = mapped_column(String(500), default="")
    totp_secret: Mapped[str] = mapped_column(String(64), default="")
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # последний использованный счетчик TOTP - защита от повторного ввода кода
    totp_last_counter: Mapped[int] = mapped_column(BigInteger, default=0)
    # версия токена: смена пароля инкрементит её и обнуляет старые JWT
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class LoginFailure(Base):
    """Неудачные попытки входа - счетчик защиты от подбора пароля.

    В базе, а не в памяти процесса: панель может работать несколькими воркерами,
    и у каждого был бы свой счетчик - порог молча умножался бы на их число.
    """

    __tablename__ = "login_failures"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(64))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_login_failures_key_ts", "key", "ts"),)


class AuditLog(Base):
    """Журнал: кто, что, когда и над чем.

    Записи связаны хеш-цепочкой: `chain` = sha256 от предыдущего `chain` и полей
    этой записи. Вырезать или подправить строку в середине незаметно нельзя -
    дальше цепочка не сойдется, и панель это увидит (app/audit.py, verify).

    Значения секретов сюда не попадают НИКОГДА. В журнале живет факт "прочитал
    такой-то ключ", а не то, что в этом ключе лежит.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(200), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    # sha256 предыдущей записи и sha256 этой - вторая считается из первой
    prev_chain: Mapped[str] = mapped_column(String(64), default="")
    chain: Mapped[str] = mapped_column(String(64), default="")

    __table_args__ = (Index("ix_audit_log_ts", "ts"),)


class AppSetting(Base):
    """Настройки, которые правятся из панели, а не из .env."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class Project(Base):
    """Проект - верхний уровень группировки секретов.

    `e2e` - режим, в котором значения шифруются в браузере и сервер их не
    видит (docs/e2e.md). Включается только у пустого проекта.
    """

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(200), default="")
    # Группа для списка: "биллинг", "внутренние сервисы", команда - что угодно,
    # чем человек сам делит сотню проектов. Не отдельная сущность намеренно:
    # уровень иерархии стоит миграции и правил доступа, а строка решает ровно
    # задачу "найти нужное в длинном списке".
    group_name: Mapped[str] = mapped_column(String(64), default="")
    # То же имя куском адреса. Имя проекта уникально ВНУТРИ группы: `frontend`
    # бывает и у globex, и у initech, и заставлять писать "globex-frontend"
    # значит держать группу в имени дважды.
    group_slug: Mapped[str] = mapped_column(String(64), default="")
    # Слаги групп, из которых проект переехал, через пробел, последние
    # MOVED_FROM_KEEP. Агент помнит прежний адрес, и машинный контур находит
    # проект по нему - но только переехавший, а не любой одноименный.
    moved_from: Mapped[str] = mapped_column(String(400), default="", server_default="")
    e2e: Mapped[bool] = mapped_column(Boolean, default=False)
    # Правки от ролей НИЖЕ этого уровня требуют подтверждения. 0 = никогда.
    approval_min_level: Mapped[int] = mapped_column(Integer, default=0)
    # Имена ключей, без которых приложение не поднимется, через пробел. Панель
    # показывает их нехватку в каждом окружении - включая новое, где пусто
    # везде и сравнивать не с кем.
    required_keys: Mapped[str] = mapped_column(String(2000), default="")
    # С какого возраста значение считается давним. Для токена оплаты год - много,
    # для внутреннего ключа мало, и решать это должен тот, кто ведет проект.
    stale_after_days: Mapped[int] = mapped_column(Integer, default=365)
    # Проект закрыт: сервис выключили, лендинг отгорел. Ключи и журнал остаются
    # (их спрашивают и через год), а из общего списка проект уходит в "Архив".
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("group_slug", "slug", name="uq_projects_group_slug"),
    )


class Environment(Base):
    """Окружение проекта: dev, stage, prod - набор свой у каждого проекта.

    У окружения может быть родитель. Это отвечает на реальный случай: десять
    стендов tech1..tech10, где значения одинаковые, кроме нескольких. Вместо
    десяти копий одного пароля - общий родитель и переопределения там, где
    отличается. Копии расходятся молча: меняют в одном месте, забывают в
    девяти, и разница вылезает через месяц на стенде, который никто не трогал.
    """

    __tablename__ = "environments"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    # Родитель - только внутри своего проекта (проверяется в API). Значение
    # берется отсюда, если в самом окружении ключ не задан.
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("environments.id", ondelete="SET NULL"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(200), default="")
    position: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_env_project_name"),)


class EnvKey(Base):
    """Ключ окружения, обернутый корневым ключом.

    Открытым он не хранится нигде: в базе лежит шифротекст, развернуть который
    может только распечатанная панель. Поколения нужны для ротации - новое
    заводится рядом со старым, и лишь когда все значения перешифрованы, старое
    перестает быть активным.
    """

    __tablename__ = "env_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    environment_id: Mapped[int] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE")
    )
    generation: Mapped[int] = mapped_column(Integer, default=1)
    # каким поколением корневого ключа обернут - видно, что осталось перевернуть
    root_generation: Mapped[int] = mapped_column(Integer, default=1)
    nonce: Mapped[str] = mapped_column(String(32))
    wrapped_key: Mapped[str] = mapped_column(String(128))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("environment_id", "generation", name="uq_envkey_env_generation"),
    )


class Secret(Base):
    """Ключ в окружении. Значения здесь нет - только то, где он лежит и какая
    версия сейчас текущая."""

    __tablename__ = "secrets"

    id: Mapped[int] = mapped_column(primary_key=True)
    environment_id: Mapped[int] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE")
    )
    path: Mapped[str] = mapped_column(String(200), default="/")
    name: Mapped[str] = mapped_column(String(200))
    current_version: Mapped[int] = mapped_column(Integer, default=0)
    # Зачем этот ключ нужен. Не комментарий к правке (тот про одно изменение и
    # живет в истории), а постоянная подпись, которую читают в списке.
    note: Mapped[str] = mapped_column(String(200), default="")
    # К какой дате значение надо заменить: срок токена, сертификата, договора.
    # Пусто - срока нет. Панель напоминает заранее, а не показывает возраст
    # задним числом.
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # удаленный секрет остается строкой: историю видно, а само удаление
    # откатывается - удаление это тоже версия
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("environment_id", "path", "name", name="uq_secret_env_path_name"),
    )


class SecretVersion(Base):
    """Одна версия значения. Значения не перезаписываются никогда.

    Имя и путь хранятся ВНУТРИ версии: они входят в связанные данные шифра, и
    переименование ключа - это новая версия с перешифрованным значением, а не
    правка строки. Иначе переименованием можно было бы подсунуть приложению
    чужое значение под нужным именем.
    """

    __tablename__ = "secret_versions"

    id: Mapped[int] = mapped_column(primary_key=True)
    secret_id: Mapped[int] = mapped_column(ForeignKey("secrets.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    name_at: Mapped[str] = mapped_column(String(200))
    path_at: Mapped[str] = mapped_column(String(200), default="/")
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    # Версия-"вернуть наследование": своего значения здесь больше нет, ключ
    # снова берется из родительского окружения. Отдельный вид версии, а не
    # удаление строки: история не переписывается, и видно, когда переопределение
    # завели и когда от него отказались.
    inherits: Mapped[bool] = mapped_column(Boolean, default=False)
    nonce: Mapped[str] = mapped_column(String(32), default="")
    ciphertext: Mapped[str] = mapped_column(Text, default="")
    env_key_generation: Mapped[int] = mapped_column(Integer, default=1)
    # current - та, что отдается; superseded - прежние; pending - правка от роли
    # ниже порога проекта, которая еще не подтверждена и потому НЕ выдается;
    # rejected - отклоненная правка (остается в истории: отказ тоже событие).
    status: Mapped[str] = mapped_column(String(16), default="current")
    # Кто подтвердил или отклонил и почему. Пустое - значит подтверждения не
    # требовалось.
    reviewed_by: Mapped[str] = mapped_column(String(64), default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    review_note: Mapped[str] = mapped_column(String(500), default="")
    author: Mapped[str] = mapped_column(String(64), default="")
    # Уровень роли автора на момент предложения. Подтверждает роль выше ЭТОГО
    # уровня: понижение автора после предложения не открывает его правку
    # равным ему по прежней роли. Пусто у правок до версии 1.0.1.
    author_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    comment: Mapped[str] = mapped_column(String(500), default="")
    # Было ли значение многострочным. Пишется при сохранении: списку иначе
    # пришлось бы расшифровывать все подряд ради одной пометки. В проекте с
    # шифрованием в браузере сервер видит только шифротекст и признак не ставит.
    multiline: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("secret_id", "version", name="uq_version_secret_version"),
        Index("ix_secret_versions_secret", "secret_id"),
    )


class ProjectKeyWrap(Base):
    """Ключ проекта, зашифрованный на ключ получателя - для режима, в котором
    сервер не видит значений (docs/e2e.md)."""

    __tablename__ = "project_key_wraps"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    subject_type: Mapped[str] = mapped_column(String(16))  # user | machine
    subject_id: Mapped[int] = mapped_column(Integer)
    nonce: Mapped[str] = mapped_column(String(32), default="")
    wrapped_key: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "project_id", "subject_type", "subject_id", name="uq_wrap_project_subject"
        ),
    )


class EnvSnapshot(Base):
    """Именованная точка окружения: "перед релизом 4.2".

    Хранит не значения, а номера версий каждого ключа на тот момент. Значения
    уже лежат в истории и никуда не деваются, поэтому копировать их второй раз
    было бы и расточительно, и опасно: чем меньше мест с шифротекстом, тем
    меньше мест, откуда он утечет.
    """

    __tablename__ = "env_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    environment_id: Mapped[int] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(200))
    author: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("environment_id", "name", name="uq_snapshot_env_name"),
    )


class EnvSnapshotItem(Base):
    """Строка снимка: какой ключ какой версией был в тот момент."""

    __tablename__ = "env_snapshot_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("env_snapshots.id", ondelete="CASCADE")
    )
    secret_id: Mapped[int] = mapped_column(ForeignKey("secrets.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)

    __table_args__ = (
        UniqueConstraint("snapshot_id", "secret_id", name="uq_snapshot_item"),
    )


class Group(Base):
    """Команда: набор людей, которым права выдаются разом.

    Без групп список политик растет по человеку на каждый проект, и при найме
    или уходе его правят в десяти местах - то есть однажды не правят вовсе.
    """

    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class GroupMember(Base):
    __tablename__ = "group_members"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

    __table_args__ = (UniqueConstraint("group_id", "user_id", name="uq_group_member"),)


class MachineIdentity(Base):
    """Машина, которая забирает секреты: сборка CI, нода, кластер.

    Пара "идентификатор + секрет" меняется на короткий токен.
    В базе лежит только хеш секрета: её утечка не дает рабочего доступа. Права
    выдаются теми же политиками, что людям, - с тем отличием, что машине можно
    выдать только чтение, а изменяющих маршрутов в машинном контуре нет вовсе.

    `token_version` - рубильник: увеличили, и все выданные токены этой машины
    перестают действовать, не дожидаясь своего срока. Так работает и "отозвать
    доступ" из панели, и `POST /revoke` самой машиной, когда она подозревает,
    что её токен утек.
    """

    __tablename__ = "machine_identities"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    client_id: Mapped[str] = mapped_column(String(64), unique=True)
    secret_hash: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(300), default="")
    # Список адресов и подсетей через пробел. Пусто = откуда угодно: у сборок в
    # облаке постоянного адреса нет, и требовать его значило бы требовать
    # невозможного.
    allow_ips: Mapped[str] = mapped_column(String(500), default="")
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    # Что машина рассказала о себе в последний раз: версия агента и какую
    # версию окружения она применила. Нужно, чтобы в панели было видно, доехала
    # ли правка до сервера, а не только то, что она сохранена.
    # Публичный ключ ноды (ECDH P-256), которым машине запечатывают ключ
    # e2e-проекта. Приватная половина живет на ноде и панели не показывается
    # никогда. P-256, а не X25519: его умеет и WebCrypto во всех браузерах, и
    # стандартная библиотека Go, а браузер здесь - обязательный участник.
    public_key: Mapped[str] = mapped_column(String(200), default="")
    agent_version: Mapped[str] = mapped_column(String(64), default="")
    applied: Mapped[str] = mapped_column(String(200), default="")
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Адрес, с которого агент постучался: его панель видит сама, спрашивать не
    # надо. Страну по нему считает app/geoip.py - офлайн, без обращений наружу.
    last_ip: Mapped[str] = mapped_column(String(64), default="")
    # Что сервер рассказал о себе сам: система ("Ubuntu 24.04.2 LTS") и адрес во
    # внутренней сети. Снаружи это не видно ни по какому соединению, а на
    # вопрос "куда я сейчас зайду" отвечает именно локальный адрес.
    os: Mapped[str] = mapped_column(String(128), default="")
    local_ip: Mapped[str] = mapped_column(String(64), default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    # --- Kubernetes ---
    # Личность, за которой стоит не секрет, а ServiceAccount в кластере. Статики
    # на ноде тогда нет вовсе: под предъявляет свой projected-токен, панель
    # проверяет подпись кластера и отдает свой короткий токен.
    cluster_id: Mapped[int | None] = mapped_column(
        ForeignKey("clusters.id", ondelete="CASCADE"), nullable=True
    )
    k8s_namespace: Mapped[str] = mapped_column(String(120), default="")
    k8s_service_account: Mapped[str] = mapped_column(String(120), default="")


class MachineApp(Base):
    """Приложение на сервере: какое окружение агент забирает и в какой файл.

    Строку сюда пишет сам агент своим отчетом, а не человек. Смысл в том, чтобы
    на странице окружения было видно не только "эти переменные кто-то читает",
    но и кто именно и куда они приезжают: сервер, файл, когда были обновлены.
    Пока агент обслуживал одно приложение, для этого хватало пары полей в
    карточке машины; со списком приложений они стали отвечать про последнее из
    них и вводить в заблуждение.

    Записи живут ровно столько, сколько живет машина: `ondelete="CASCADE"`.
    Приложение, снятое с сервера (`sekvyr rm`), перестает обновлять свою строку,
    и по времени последнего отчета видно, что оно отвалилось.
    """

    __tablename__ = "machine_apps"
    __table_args__ = (
        UniqueConstraint(
            "machine_id",
            "group_slug",
            "project_slug",
            "env_name",
            name="uq_machine_apps_target",
        ),
        # Имя - как в миграции 0012: иначе alembic check видел расхождение.
        Index("ix_machine_apps_machine", "machine_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    machine_id: Mapped[int] = mapped_column(
        ForeignKey("machine_identities.id", ondelete="CASCADE")
    )
    group_slug: Mapped[str] = mapped_column(String(120), default="")
    project_slug: Mapped[str] = mapped_column(String(120))
    env_name: Mapped[str] = mapped_column(String(120))
    # Файл, который агент поддерживает в актуальном виде. Секретом не является:
    # это путь, а не содержимое.
    path: Mapped[str] = mapped_column(String(300), default="")
    applied: Mapped[str] = mapped_column(String(200), default="")
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class MachineRead(Base):
    """С чем машина забрала окружение, когда это последний раз попало в журнал.

    Агент спрашивает панель раз в минуту по каждому приложению. Строка в журнале
    на каждый такой вопрос давала тысячи одинаковых записей в сутки с одного
    сервера, и за ними терялось то, ради чего журнал читают: какие значения и
    куда уехали. Теперь запись появляется, когда набор значений другой, адрес
    новый для этого набора или с прошлой записи прошли сутки, а повторы между
    записями только считаются. Отпечаток собран из номеров версий: самих
    значений и их хешей здесь нет, иначе короткий пароль подбирался бы по
    отпечатку. Адресов несколько, через пробел, последние сверху: поды одного
    ServiceAccount выходят наружу с разных нод, и с одним адресом каждое
    чередование давало бы новую запись.
    """

    __tablename__ = "machine_reads"

    machine_id: Mapped[int] = mapped_column(
        ForeignKey("machine_identities.id", ondelete="CASCADE"), primary_key=True
    )
    environment_id: Mapped[int] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE"), primary_key=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), default="")
    ips: Mapped[str] = mapped_column(String(600), default="")
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    repeats: Mapped[int] = mapped_column(Integer, default=0)


class Cluster(Base):
    """Кластер Kubernetes, чьим ServiceAccount-токенам панель верит.

    Проверка идет по JWKS кластера, а не через TokenReview: панели тогда не
    нужны учетные данные кластера, а кластеру - доступность панели изнутри.
    Ключи вписываются один раз (`kubectl get --raw /openid/v1/jwks`) и лежат
    здесь же; смена ключей в кластере означает обновление этой записи.

    Audience обязателен и по умолчанию свой: токен, выписанный "для kubernetes",
    не должен подходить к панели. Под просит токен именно для нее, и такой токен
    бесполезен где-то еще.
    """

    __tablename__ = "clusters"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    # `iss` из токена: у managed-кластеров это URL, у ванильных - kubernetes/serviceaccount
    issuer: Mapped[str] = mapped_column(String(300))
    audience: Mapped[str] = mapped_column(String(120), default="sekvyr")
    jwks: Mapped[str] = mapped_column(Text, default="")
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class LintMute(Base):
    """Принятое замечание: "здесь так и надо".

    Замечание к значению бывает верным по форме и неверным по сути: `http` на
    внутренний адрес, короткий токен, который таким и выдали у поставщика. Пока
    такое висит, человек привыкает пролистывать замечания вообще - и настоящее
    пролистает вместе с остальными.

    Ключ строки - место и проверка, а не версия значения: решение "так и надо"
    относится к тому, что тут лежит, и переживает правку.
    """

    __tablename__ = "lint_mutes"

    id: Mapped[int] = mapped_column(primary_key=True)
    environment_id: Mapped[int] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE")
    )
    path: Mapped[str] = mapped_column(String(200), default="/")
    name: Mapped[str] = mapped_column(String(200))
    code: Mapped[str] = mapped_column(String(40))
    muted_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("environment_id", "path", "name", "code", name="uq_lint_mute_place"),
    )


class LintSeen(Base):
    """Замечание, о котором панель уже сообщила.

    Нужна ровно для того, чтобы сообщение пришло один раз: обход идет каждые
    несколько часов, и без памяти он повторял бы одно и то же, пока человек не
    научится не читать эти сообщения.

    Строка живет, пока живет само замечание: исправили и повторили ошибку -
    об этом стоит узнать заново.
    """

    __tablename__ = "lint_seen"

    id: Mapped[int] = mapped_column(primary_key=True)
    environment_id: Mapped[int] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE")
    )
    path: Mapped[str] = mapped_column(String(200), default="/")
    name: Mapped[str] = mapped_column(String(200))
    code: Mapped[str] = mapped_column(String(40))
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("environment_id", "path", "name", "code", name="uq_lint_seen_place"),
    )


class EnrollToken(Base):
    """Одноразовый токен: сервер меняет его на постоянную машинную личность.

    Живет минуты и годен ровно на одну регистрацию - это и есть "подключение
    одной командой" из плана (4.1). Токен нельзя переслать "на всякий случай":
    второй сервер по нему уже не подключится, а через четверть часа не
    подключится и первый.

    В базе только хеш: строку целиком видит человек в панели один раз, когда
    копирует команду.
    """

    __tablename__ = "enroll_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    # Что выдать подключившемуся серверу сразу: без этого он появится в панели
    # без единого права, и "одна команда" превратится в две.
    environment_id: Mapped[int | None] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE"), nullable=True
    )
    allow_ips: Mapped[str] = mapped_column(String(500), default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    used_by: Mapped[str] = mapped_column(String(120), default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Policy(Base):
    """Право: кто, где и что может.

    Область задается сверху вниз: проект -> окружение -> путь. Пустой проект
    означает "любой", пустое окружение - "любое в этом проекте", путь работает
    префиксом: `/db` покрывает `/db` и все, что под ним.

    Действия хранятся строкой через запятую, а не отдельной таблицей: набор
    короткий и меняется вместе с кодом, а join ради шести слов только усложнил
    бы чтение политики глазами - а её читают именно глазами, когда разбираются,
    почему у человека нет доступа.

    `effect` = deny сильнее любого allow: запрет должен работать, даже если
    где-то еще выдано разрешение, иначе "отобрать доступ" превращается в поиск
    всех мест, где он был выдан.
    """

    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(16))  # user | group
    subject_id: Mapped[int] = mapped_column(Integer)
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=True
    )
    environment_id: Mapped[int | None] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE"), nullable=True
    )
    path_prefix: Mapped[str] = mapped_column(String(200), default="/")
    actions: Mapped[str] = mapped_column(String(200), default="list")
    effect: Mapped[str] = mapped_column(String(8), default="allow")
    # Доступ с концом: подрядчику до конца месяца, дежурному на неделю. Пусто =
    # бессрочно.
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Право действует, только пока у человека включен второй фактор. Не "мы
    # попросим включить", а "без него права нет".
    require_2fa: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (Index("ix_policies_subject", "subject_type", "subject_id"),)
