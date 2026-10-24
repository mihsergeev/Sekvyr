from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SEKVYR_", env_file=".env")

    app_name: str = "Sekvyr"
    version: str = "1.0.1"
    debug: bool = False
    # Внешний адрес панели (https://sekvyr.example.com). Нужен для команды
    # подключения сервера, которую панель показывает в интерфейсе, и для ссылок
    # в уведомлениях. Пусто = ссылки не строим.
    panel_url: str = ""

    @field_validator("panel_url")
    @classmethod
    def _panel_url_without_slash(cls, value: str) -> str:
        # Косая черта в конце давала команду подключения с "//api/...", и
        # сервер отвечал на нее 404.
        return value.strip().rstrip("/")

    db_url: str = "sqlite+aiosqlite:///./data/sekvyr.db"
    data_dir: str = "./data"
    # Где лежат бинари агента и подписанное описание версии. В образе панель
    # кладет их сюда сама; при запуске из исходников путь задают явно, иначе
    # раздавать нечего и обновляться ноде не с чего.
    agent_dir: str = "/srv/agent"

    # В какой зоне показывать время в панели. По умолчанию UTC: панель ставят
    # где угодно, и "время сервера" без явной зоны - это спор о том, что
    # означала запись в журнале. Свою зону задают явно: Europe/Moscow.
    timezone: str = "UTC"

    # Сколько доверенных прокси стоит перед бэкендом - см. app/clientip.py.
    # 1 = только nginx фронтенда (базовый compose); 2 = еще и внешний прокси
    # (compose.caddy.yml или свой). От этого зависит, чей адрес попадет в журнал
    # и в лимитер входа, поэтому значение стоит выставить осознанно.
    trusted_proxy_hops: int = 1

    # --- Корневой ключ ---
    # Автораспечатывание: ключ (base64, 32 байта) прямо в переменной или в файле.
    # Пусто - панель поднимается ЗАПЕЧАТАННОЙ и ждет долей. Файл предпочтительнее
    # переменной: её содержимое видно в `docker inspect` и в окружении процесса.
    root_key: str = ""
    root_key_file: str = ""

    # --- Аутентификация людей ---
    jwt_secret: str = "dev-insecure-change-me"
    jwt_ttl_minutes: int = 12 * 60

    # Начальный владелец панели (заводится при первом старте; дальше пароль
    # меняется в интерфейсе и из .env НЕ пересинхронизируется).
    admin_user: str = "admin"

    @field_validator("admin_user")
    @classmethod
    def _admin_user_not_empty(cls, value: str) -> str:
        # Строка SEKVYR_ADMIN_USER= без значения (или compose без нее в .env)
        # давала владельца с пустым логином, под которым не войти.
        return value.strip() or "admin"

    admin_password: str = "admin"

    # Аварийный сброс (break-glass): при SEKVYR_ADMIN_PASSWORD_RESET=1 старт
    # сбрасывает пароль владельца на admin_password и отключает второй фактор.
    # Убрать флаг из .env сразу после входа.
    admin_password_reset: bool = False

    # --- Оповещения ---
    # Значения по умолчанию для каналов: в интерфейсе их можно переопределить.
    # Скрипты обслуживания (ops/backup.sh, ops/panel-watchdog.sh) этот .env не
    # читают: канал они берут из файла пульса (app/heartbeat.py), который
    # панель переписывает раз в минуту. Так сторож может позвать на помощь,
    # когда панели уже нет. Панель, ни разу не поднявшаяся, пульса не писала, и
    # сообщить сторожу некуда.
    alert_telegram_token: str = ""
    alert_telegram_chat: str = ""
    # Зеркало Bot API для сетей, где api.telegram.org недоступен.
    alert_telegram_api: str = ""
    alert_webhook: str = ""
    # Окружения, правка которых стоит отдельного сообщения: имена через пробел.
    # Пусто - не сообщать. Значение в такое сообщение не попадает, только место,
    # имя ключа и кто правил.
    alert_on_envs: str = "prod production"

    # --- Копия журнала наружу ---
    # Адрес приемника, куда уезжают записи журнала вместе с их хешами. Пусто -
    # копии нет, и журнал защищен только цепочкой внутри базы (см. app/audit.py).
    audit_webhook: str = ""
    audit_ship_interval: int = 30

    # --- Бэкап ---
    # Файл, в который отмечается ops/backup.sh. Панель его только читает: так
    # скрипту не нужен токен, а панель знает, когда бэкап снимали в последний
    # раз. Пусто - считаем, что бэкап делают снаружи, и не напоминаем.
    backup_state_file: str = ""
    # Через сколько часов молчания бэкапа считать это происшествием.
    backup_max_age_hours: int = 48


@lru_cache
def get_settings() -> Settings:
    return Settings()
