/* Два языка с самого начала.
 *
 * Исходные строки - русские, английские лежат в словаре. Так проще править
 * интерфейс (в коде виден нормальный текст, а не ключи вида `login.title`), а
 * пропущенный перевод деградирует в русскую строку, а не в пустоту.
 *
 * Словарь заводится сразу, хотя строк пока десятки: добавить его к готовой
 * панели - это переписать каждый файл разметки, и в прошлых проектах это уже
 * обошлось дороже, чем стоило бы сделать сразу.
 */

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

export type Lang = 'ru' | 'en'

const LANG_KEY = 'sekvyr_lang'

const EN: Record<string, string> = {
  'Вход в панель': 'Sign in',
  Логин: 'Login',
  Пароль: 'Password',
  Войти: 'Sign in',
  'Проверка…': 'Checking…',
  'Неверный логин или пароль': 'Wrong login or password',
  'Слишком много попыток входа — повторите позже':
    'Too many sign-in attempts — try again later',
  'Не удалось войти': 'Could not sign in',
  Обзор: 'Overview',
  'Учётные записи': 'Accounts',
  Журнал: 'Audit log',
  Выйти: 'Sign out',
  'Сменить пароль': 'Change password',
  'Текущий пароль': 'Current password',
  'Новый пароль': 'New password',
  Сохранить: 'Save',
  Отмена: 'Cancel',
  Добавить: 'Add',
  Роль: 'Role',
  Состояние: 'State',
  Заведена: 'Created',
  Активна: 'Active',
  Отключена: 'Disabled',
  Отключить: 'Disable',
  Включить: 'Enable',
  'Сбросить пароль': 'Reset password',
  'Новая учётная запись': 'New account',
  Владелец: 'Owner',
  Ответственный: 'Maintainer',
  Разработчик: 'Developer',
  Наблюдатель: 'Viewer',
  Когда: 'When',
  Кто: 'Who',
  Действие: 'Action',
  'Над чем': 'Target',
  Подробности: 'Details',
  Адрес: 'Address',
  'Проверить целостность': 'Verify integrity',
  'Цепочка нарушена: первое расхождение — запись {id}, всего расхождений {count}':
    'The chain is broken: first mismatch at entry {id}, {count} mismatches in total',
  'Цепочка журнала цела': 'The log chain is intact',
  'Записей пока нет': 'No entries yet',
  'Вы вошли как': 'Signed in as',
  'Хранилище готово': 'Storage is ready',
  'Секреты, версии, права и подтверждение изменений работают. Дальше — машинный контур: серверы будут забирать значения сами.':
    'Secrets, versions, rights and change approval all work. Next comes the machine surface: servers pulling values on their own.',
  'Пароль изменён': 'Password changed',
  'Пароль не короче {n} символов': 'Password of at least {n} characters',
  'латинские буквы, цифры, точка, дефис и подчеркивание':
    'Latin letters, digits, dot, hyphen and underscore',
  'от 1 до 1440 минут': 'from 1 to 1440 minutes',
  'не длиннее 72 байт: это 72 латинские буквы или 36 русских':
    'at most 72 bytes: that is 72 Latin letters',
  'Ошибка HTTP {code}': 'HTTP error {code}',
  Тема: 'Theme',
  'Автоматическое отпирание': 'Automatic unlocking',
  'Запомнить ключ на сервере': 'Remember the key on the server',
  'Забыть ключ': 'Forget the key',
  'сначала отоприте панель': 'unlock the panel first',
  'Ключ сохранён на сервере, панель поднимается сама. Пока он там лежит, root на хосте означает доступ ко всем значениям.':
    'The key is stored on the server and the panel unlocks itself. While it is there, root on the host means access to every value.',
  'Панель может запомнить ключ файлом и подниматься сама после перезапуска. Удобно на время настройки; для боевой панели это ослабление — ключ окажется рядом с ней.':
    'The panel can remember the key in a file and unlock itself after a restart. Handy while setting things up; for a production panel it is a weakening — the key ends up next to it.',
  Ещё: 'More',
  'Строка разворачивается: видно, что именно поменялось.':
    'Rows expand to show exactly what changed.',
  'Значения читать нельзя, видно только события.':
    'You cannot read values here, only the events.',
  'Значение не менялось': 'The value did not change',
  'Значение пустое': 'The value is empty',
  'Загружаем…': 'Loading…',
  Серверы: 'Servers',
  'Пароль проекта': 'Project password',
  'Шифрование в браузере': 'Browser-side encryption',
  'Включить шифрование в браузере': 'Turn on browser-side encryption',
  'Пароль проекта короче двенадцати символов': 'The project password is shorter than twelve characters',
  'его придётся сказать каждому, кто будет читать значения':
    'you will have to tell it to everyone who reads the values',
  'Машина': 'Machine',
  'Ключ ноды': 'Node key',
  'Ключ проекта': 'Project key',
  'агент ещё не прислал': 'the agent has not sent it yet',
  выдан: 'granted',
  'не выдан': 'not granted',
  'Выдать ключ': 'Grant the key',
  'Выдать заново': 'Grant again',
  есть: 'present',
  'Машин с доступом в проект пока нет.': 'No machines have access to this project yet.',
  'У машины ещё нет ключа: агент присылает его при первом обращении':
    'The machine has no key yet: the agent sends it on its first request',
  'Значения такого проекта шифруются здесь, в браузере: сервер их не увидит и не восстановит. Забытый пароль проекта означает потерю значений без вариантов. Включить можно только у пустого проекта.':
    'Values of such a project are encrypted here, in the browser: the server will not see them and cannot recover them. A forgotten project password means losing the values with no way back. It can only be turned on for an empty project.',
  'Включено: сервер хранит значения этого проекта запечатанными и прочитать их не может. Машинам ключ проекта выдаётся отсюда — панель сделать это за вас не в состоянии.':
    'On: the server keeps the values of this project sealed and cannot read them. Machines are granted the project key from here — the panel cannot do it for you.',
  'Обычный проект панель шифрует сама, и распечатанная панель видит значения. В этом режиме их шифрует браузер: сервер хранит непрозрачные блобы. Плата — забытый пароль проекта означает потерю значений без вариантов.':
    'An ordinary project is encrypted by the panel itself, and an unsealed panel sees the values. In this mode the browser encrypts them: the server keeps opaque blobs. The price is that a forgotten project password means losing the values with no way back.',
  'Пароль не подошёл': 'The password did not match',
  Открыть: 'Open',
  Запереть: 'Lock',
  'Ввести пароль проекта': 'Enter the project password',
  'Значения этого проекта шифруются в браузере. Ключ открыт в этой вкладке.':
    'This project encrypts values in the browser. The key is open in this tab.',
  'Значения этого проекта шифруются в браузере: без пароля проекта их не прочитать.':
    'This project encrypts values in the browser: without the project password they cannot be read.',
  Перенос: 'Migration',
  'Перенос из другого хранилища': 'Migration from another vault',
  Откуда: 'From',
  Куда: 'To',
  Источник: 'Source',
  Папка: 'Folder',
  Ключ: 'Key',
  'Что будет': 'What happens',
  Длина: 'Length',
  Посмотреть: 'Preview',
  Перенести: 'Migrate',
  'Найти проекты': 'Find projects',
  Проект: 'Project',
  'Окружение источника': 'Source environment',
  'Путь в источнике': 'Path in the source',
  'Раздел KV': 'KV mount',
  'Токен Vault': 'Vault token',
  'Идентификатор машинной личности': 'Machine identity id',
  'Секрет машинной личности': 'Machine identity secret',
  'Перезаписывать существующие значения': 'Overwrite existing values',
  создать: 'create',
  обновить: 'update',
  совпадает: 'identical',
  'Всего {total}: создать {create}, обновить {update}, совпадает {same}':
    'Total {total}: create {create}, update {update}, identical {same}',
  'Перенесено: создано {created}, обновлено {updated}, пропущено {skipped}':
    'Migrated: created {created}, updated {updated}, skipped {skipped}',
  'Существующие значения останутся как есть: включите перезапись, если нужно иначе.':
    'Existing values stay as they are: turn on overwrite if you need otherwise.',
  'Сначала панель покажет, что видит на той стороне и что случится с каждым ключом, и только потом перенесёт. Реквизиты источника нигде не сохраняются.':
    'First the panel shows what it sees on the other side and what happens to each key, and only then migrates. Source credentials are not stored anywhere.',
  Понятно: 'Got it',
  'Баз пока нет.': 'No databases yet.',
  'Действует до': 'Valid until',
  действует: 'active',
  Отозвать: 'Revoke',
  Кому: 'To whom',
  Срок: 'Term',
  Выдано: 'Granted',
  мин: 'min',
  Название: 'Name',
  Обслуживание: 'Maintenance',
  Оповещения: 'Alerts',
  Настроить: 'Configure',
  Проверить: 'Check',
  Сохранено: 'Saved',
  Бэкап: 'Backup',
  'Аварийный доступ': 'Emergency access',
  'Аварийный архив': 'Emergency archive',
  'Собрать архив': 'Build the archive',
  Собрать: 'Build',
  'Архив собран': 'The archive is ready',
  'Токен бота Telegram': 'Telegram bot token',
  'Чат или канал': 'Chat or channel',
  'Зеркало Bot API': 'Bot API mirror',
  Вебхук: 'Webhook',
  'Приёмник журнала': 'Audit log receiver',
  'не задан': 'not set',
  'не настроен': 'not configured',
  'Пароль архива': 'Archive password',
  'Пароль ещё раз': 'Repeat the password',
  'Ваш пароль от панели': 'Your panel password',
  'Код второго фактора': 'Two-factor code',
  Пометка: 'Note',
  'например: перед переездом': 'for example: before the migration',
  'Пароли не совпали': 'The passwords do not match',
  'Сообщение отправлено — проверьте канал': 'Message sent — check the channel',
  'Панель не следит за бэкапом': 'The panel does not watch the backup',
  'Отметки о бэкапе ещё не было': 'No backup mark yet',
  'Последний бэкап: {when}': 'Last backup: {when}',
  'Последний бэкап не удался: {when}': 'The last backup failed: {when}',
  КБ: 'KB',
  'Пустое поле оставит прежнее значение, «-» выключит канал.':
    'An empty field keeps the current value, "-" turns the channel off.',
  'для сетей, где api.telegram.org недоступен':
    'for networks where api.telegram.org is unreachable',
  'только https и только внешний адрес': 'https only, and an external address only',
  'копия записей журнала уезжает туда пачками — её не срезать вместе с базой':
    'a copy of the log entries goes there in batches — it cannot be trimmed together with the database',
  'от 12 символов; храните его отдельно от самого архива':
    'at least 12 characters; keep it apart from the archive itself',
  'Задано в .env и потому не стирается отсюда: {fields}':
    'Set in .env and therefore not erasable here: {fields}',
  'копии записей вне этой базы нет': 'there is no copy of the entries outside this database',
  'Панель сообщает о том, о чём нельзя узнать позже: сейф заперли или открыли, вход заблокирован после серии попыток, собран аварийный архив, журнал перестал сходиться. Раз в несколько часов она обходит значения и сообщает о новых замечаниях — заготовка вместо пароля в проде найдётся сама.':
    'The panel reports what cannot be learned later: the vault was sealed or opened, logins were blocked after a burst of attempts, an emergency archive was built, the audit chain stopped matching. Every few hours it walks the values and reports new notes — a placeholder instead of a production password finds you itself.',
  'В файл попадут ВСЕ значения всех окружений открытым текстом, защищённые только вашим паролем. Сборка попадёт в журнал и в оповещения. Продолжать?':
    'The file will hold ALL values of all environments in plain text, protected only by your password. Building it goes into the audit log and the alerts. Continue?',
  'Открыть его без панели: python3 ops/breakglass.py env <файл> группа/проект/окружение':
    'Open it without the panel: python3 ops/breakglass.py env <file> group/project/environment',
  'Бэкап снимает ops/backup.sh по расписанию: дамп шифруется своим паролем, отметка попадает сюда. Корневого ключа в нём нет и не должно быть — иначе дамп и ключ ездят вместе.':
    'ops/backup.sh takes the backup on a schedule: the dump is encrypted with its own password and the mark lands here. The root key is not in it and must not be — otherwise the dump and the key travel together.',
  'Архив отвечает на вопрос «панели нет, корневого ключа нет, а прод надо поднять сейчас». Все значения одним файлом под вашим паролем; открывает его ops/breakglass.py без панели и без сети.':
    'The archive answers the question "no panel, no root key, and production has to come up now". Every value in one file under your password; ops/breakglass.py opens it without the panel and without the network.',
  'Это единственное место, где секреты выходят из панели все сразу. Храните архив там же, где доли ключа, и пересобирайте после заметных изменений.':
    'This is the only place where secrets leave the panel all at once. Keep the archive where you keep the key shares, and rebuild it after notable changes.',
  Кластеры: 'Clusters',
  Кластер: 'Cluster',
  'Добавить кластер': 'Add a cluster',
  'Удалить кластер?': 'Delete the cluster?',
  'Введите имя кластера': 'Type the cluster name',
  'Личность в кластере': 'Identity in a cluster',
  Личностей: 'Identities',
  'Кластеров пока нет.': 'No clusters yet.',
  'Сначала добавьте кластер.': 'Add a cluster first.',
  'Обновить ключи': 'Update keys',
  'Готово. Выдайте ей окружение в разделе «Доступ» — секрет здесь не нужен.':
    'Done. Grant it an environment in the Access section — no secret is needed here.',
  'поле iss из токена ServiceAccount': 'the iss field from a ServiceAccount token',
  'для кого под просит токен; «для kubernetes» панели не подойдёт':
    'who the pod asks the token for; a token for kubernetes will not fit the panel',
  'Вместе с ним исчезнут личности его подов: проверять их токены станет нечем.':
    'Its pod identities go with it: there would be nothing left to verify their tokens with.',
  'Панель верит ServiceAccount-токенам этих кластеров: под доказывает себя подписью кластера, и статического секрета в кластере не остаётся вовсе.':
    'The panel trusts ServiceAccount tokens from these clusters: a pod proves itself with the cluster signature, and no static secret stays in the cluster at all.',
  'На связи': 'Last seen',
  'ещё не забирал': 'has not pulled yet',
  'поиск по имени, адресу, системе и окружениям': 'search by name, address, system and environments',
  'Поиск идёт по имени, адресу, системе и выданным окружениям.':
    'The search covers the name, addresses, system and granted environments.',
  'все': 'all',
  '«Подключить сервер» покажет команду установки агента с одноразовым токеном.':
    '«Connect a server» shows the agent install command with a one-time token.',
  'давние': 'stale',
  'оставить только давние значения': 'show only stale values',
  'Давним считать значение старше': 'Consider a value stale after',
  'трёх месяцев': 'three months',
  'полугода': 'six months',
  'года': 'a year',
  'двух лет': 'two years',
  'для токена оплаты год — много, для внутреннего ключа мало; отсюда и настройка':
    'a year is long for a payment token and short for an internal key, hence the setting',
  'Все окружения одним файлом': 'Every environment in one file',
  'Скачать проект': 'Download the project',
  'каждое окружение своим блоком; попадёт только то, что вам разрешено читать':
    'each environment as its own block; only what you may read gets in',
  'не попали в файл': 'left out of the file',
  'поиск одинаковых значений': 'search for identical values',
  'выгрузка проекта': 'project export',
  'на весь проект': 'whole project',
  'Выход при бездействии': 'Sign out when idle',
  'Закреплённые': 'Pinned',
  'закрепить на главной': 'pin to the home page',
  'убрать из закреплённых': 'unpin',
  'значение изменено': 'value changed',
  'значение прочитано': 'value read',
  'ключ удалён': 'key deleted',
  'ключ переименован': 'key renamed',
  'значение возвращено': 'value rolled back',
  'подпись и срок': 'note and expiry',
  'импорт файла': 'file import',
  'копия окружения': 'environment copy',
  'смена ключа шифрования': 'encryption key rotated',
  'Скопировать значения из': 'Copy values from',
  'ниоткуда: окружение будет пустым': 'from nowhere: the environment starts empty',
  'скопировано значений': 'values copied',
  'Обязательные ключи': 'Required keys',
  'имена через пробел; панель покажет их нехватку в каждом окружении, включая новое':
    'names separated by spaces; the panel shows what is missing in every environment, new ones included',
  'например: токен бота для оповещений': 'e.g. bot token for alerts',
  'заменить до': 'replace before',
  'подпись и срок ключа': 'key note and expiry',
  'перейти куда угодно': 'jump anywhere',
  'проект, окружение, сервер или ключ': 'project, environment, server or key',
  'Откуда пускать': 'Where to allow from',
  'Адреса и подсети через пробел. Пусто — откуда угодно. Проверяется на каждом запросе, поэтому смена адреса закрывает и уже выданный токен.':
    'Addresses and subnets separated by spaces. Empty means from anywhere. Checked on every request, so a change also cuts off a token already issued.',
  'журнал с': 'log starts',
  'старше года': 'over a year old',
  'оставить только значения старше года': 'show only values older than a year',
  'последняя правка': 'last changed',
  'Выбрать все': 'Select all',
  'Записать': 'Write',
  'ничего не выбрано': 'nothing selected',
  'записано': 'written',
  'нет права писать': 'no write permission',
  'уже такое же': 'already the same',
  'Отозвать все доступы?': 'Revoke every grant?',
  'Отозвать все доступы': 'Revoke every grant',
  'Отозвать все права': 'Revoke every grant',
  'Отозвать всё': 'Revoke all',
  'Прав будет снято': 'Grants to be revoked',
  'Сервер перестанет получать эти окружения при следующем обращении. Файлы, которые уже лежат на нём, останутся.':
    'The server stops receiving these environments on its next request. Files already on it stay where they are.',
  'Сравнить': 'Compare',
  'сравнение окружений': 'environments compared',
  'поиск': 'search',
  'поиск по кому выдано, проекту и окружению': 'search by subject, project and environment',
  'молчат': 'silent',
  'ничего не забирают': 'pulling nothing',
  'агент устарел': 'agent is behind',
  'панель раздаёт': 'the panel serves',
  'агент обновится сам': 'the agent will update itself',
  'и ещё': 'and',
  'начните вводить имя': 'start typing a name',
  'ничего не нашлось': 'nothing found',
  'уточните поиск': 'narrow the search',
  'открыть сервер': 'open the server',
  'показать, кто забирает это окружение': 'show who pulls this environment',
  'внешний адрес: с него приходит агент': 'public address: the agent connects from it',
  'локальный адрес во внутренней сети': 'local address on the internal network',
  'Сервер читает выданные ему окружения и не может ничего изменить: в машинном контуре нет маршрутов, которые пишут в секреты. Права выдаются в разделе «Доступ».':
    'A server reads the environments it was granted and can change nothing: the machine contour has no routes that write to secrets. Permissions are granted in the Access section.',
  Сервер: 'Server',
  'Машина без агента': 'Machine without an agent',
  'Серверов пока нет.': 'No servers yet.',
  'Удалить сервер?': 'Delete the server?',
  'Введите имя сервера': 'Type the server name',
  'Секрет сервера': 'Server secret',
  выключен: 'disabled',
  сервер: 'server',
  сервера: 'servers',
  серверов: 'servers',
  'Это окружение забирают': 'Pulled by',
  'Подключить сервер': 'Connect a server',
  'Создать токен': 'Create token',
  Дальше: 'Next',
  'Срок действия токена, минут': 'Token lifetime, minutes',
  'действует на одно подключение': 'valid for one connection',
  'Выполните на сервере': 'Run this on the server',
  'Подключить приложение': 'Connect an application',
  Подключить: 'Connect',
  'Доступ выдан.': 'Access granted.',
  'Доступ уже был выдан раньше.': 'Access had already been granted.',
  'Доступ действует до': 'Access is valid until',
  'Сначала заведите проект с окружением.': 'Create a project with an environment first.',
  'Где используется': 'Used by',
  'Открыть сервер': 'Open server',
  'Скопировать значение': 'Copy the value',
  'выдано, но не забирается': 'granted but not pulled',
  'Такого сервера нет': 'No such server',
  'К списку серверов': 'Back to servers',
  'Ничего не подключено': 'Nothing connected yet',
  '«Подключить приложение» выдаст серверу окружение и покажет команду, которой оно добавляется агенту.':
    '“Connect an app” grants the server an environment and shows the command that adds it to the agent.',
  'Удалить сервер': 'Delete server',
  'Отозвать доступ': 'Revoke access',
  'Отозвать доступ?': 'Revoke access?',
  'Сервер перестанет получать это окружение при следующем обращении. Файл, который уже лежит на нём, останется.':
    'The server stops receiving this environment on its next request. The file already on it stays.',
  'права нет — файл больше не обновляется': 'no permission — the file is no longer updated',
  'по праву на весь проект': 'through a right to the whole project',
  'Название, группу и требования к ключам меняет владелец панели.':
    'The name, the group and the key requirements are changed by the panel owner.',
  'не используется': 'not in use',
  'агент забирает': 'the agent pulls it',
  агент: 'agent',
  обновлено: 'updated',
  'Пода в кластере может доказать себя подписью кластера, без секрета вовсе — для этого добавьте кластер в меню сверху.':
    'A pod can prove itself with its cluster signature and no secret at all — add a cluster from the menu above.',
  'выдано': 'granted',
  'Серверов пока нет': 'No servers yet',
  'Прав пока нет': 'No permissions yet',
  'Никого нет': 'Nobody here yet',
  'Скопировать не вышло': 'Copying did not work',
  'Пароль принят. Осталось подтвердить вход шестизначным кодом.':
    'Password accepted. One more step: confirm the sign-in with a six-digit code.',
  Назад: 'Back',
  Код: 'Code',
  'Проекта нет': 'No such project',
  'Либо его удалили, либо доступ к нему вам не выдавали: панель не показывает даже имена чужих проектов.':
    'Either it was deleted or you were never granted access: the panel does not even show the names of other projects.',
  'Окружений пока нет': 'No environments yet',
  'Ключи живут в окружениях: заведите prod, а рядом dev или stage — они умеют наследовать значения друг от друга.':
    'Keys live in environments: create prod, then dev or stage next to it — they can inherit values from one another.',
  'Проектов пока нет': 'No projects yet',
  'Доступа пока нет': 'No access yet',
  'Проект — это приложение или сервис. Внутри у него окружения, а в окружении лежат ключи.':
    'A project is an app or a service. It holds environments, and an environment holds keys.',
  'Поиск идёт по имени проекта, группе и окружениям.':
    'Search covers project names, groups and environments.',
  'нет окружений': 'no environments',
  'Шаг 1. Откуда': 'Step 1. From',
  'Шаг 2. Куда': 'Step 2. To',
  'Шаг 3. Что изменится': 'Step 3. What will change',
  'Посмотреть, что будет': 'Show what will happen',
  'только изменения': 'changes only',
  'Менять нечего': 'Nothing to change',
  'Всё, что нашлось в источнике, уже лежит здесь с теми же значениями.':
    'Everything found in the source is already here with the same values.',
  'Реквизиты уходят только в этот запрос: панель их не сохраняет и вторым местом хранения доступа к старому хранилищу не становится.':
    'Credentials go into this one request: the panel does not store them and does not become a second home for access to the old vault.',
  'симв.': 'chars',
  'заперта: значения не выдаются': 'locked: values are not served',
  'Забыть ключ на сервере': 'Forget the key on the server',
  'Ключ на сервере': 'Key on the server',
  'панель поднимается сама, но root на хосте открывает все значения':
    'the panel unlocks itself, but root on the host opens every value',
  'не сохранён: после перезапуска панель ждёт ключ':
    'not stored: after a restart the panel waits for the key',
  'это вы': 'you',
  отключена: 'disabled',
  заведена: 'created',
  'поиск по логину и роли': 'search by login and role',
  'Сменить роль': 'Change role',
  'вход подтверждается кодом': 'sign-in is confirmed with a code',
  'Роль решает, какие разделы панели человек видит. Что он видит внутри проектов, задаётся правами в «Доступе».':
    'The role decides which sections of the panel a person sees. What they see inside projects is set by permissions in Access.',
  'поиск по журналу: кто, что, над чем, адрес': 'search the log: who, what, on what, address',
  'Журнал пишется сам: вход, чтение значений, правки, выданные права.':
    'The log writes itself: sign-ins, value reads, edits, granted permissions.',
  'включены': 'on',
  'не настроены': 'not set up',
  'отказ': 'denied',
  'Групп пока нет': 'No groups yet',
  'Свернуть': 'Collapse',
  видеть: 'list',
  читать: 'read',
  менять: 'write',
  удалять: 'delete',
  'ключ окружения': 'env key',
  подтверждать: 'approve',
  'Кластеров пока нет': 'No clusters yet',
  'Сервер только читает выданные ему окружения: в машинном контуре нет маршрутов, которые пишут в секреты.':
    'A server only reads the environments granted to it: the machine API has no routes that write secrets.',
  'ещё': 'more',
  'многострочное значение': 'a multi-line value',
  'Поиск идёт по имени ключа и по папке.': 'The search covers key names and folders.',
  'Сбросить поиск': 'Clear the search',
  'Добавьте первый или залейте готовый .env через импорт.':
    'Add the first one, or import a ready .env file.',
  'Добавьте первый ключ: значение запечатает браузер.':
    'Add the first key: the browser will seal its value.',
  'скопирован': 'copied',
  'поиск по ключам — /': 'search keys — /',
  'из родителя': 'inherited',
  'выдано ещё': 'also granted',
  'Панель выдаст серверу это окружение и покажет команду, которой оно добавляется агенту.':
    'The panel will grant the server this environment and show the command that adds it to the agent.',
  '1. Новый сервер — подключение, агент и приложение одной командой:':
    '1. A new server — enrolment, agent and application in one command:',
  '2. Сервер уже подключён — добавить ему это приложение:':
    '2. The server is already connected — add this application to it:',
  'Вторая команда не расходует токен и ничего не перезапускает.':
    'The second command does not use up the token and restarts nothing.',
  'Каталог приложения должен совпадать с именем проекта: /app/<проект>/compose.yml':
    'The application directory must match the project name: /app/<project>/compose.yml',
  'Токен действителен до': 'Token valid until',
  'У проекта нет окружений.': 'The project has no environments.',
  'Новая машина': 'New machine',
  Завести: 'Create',
  Зачем: 'What for',
  'например: сборки биллинга': 'e.g. billing CI builds',
  Адреса: 'Addresses',
  'через пробел; пусто — откуда угодно': 'space separated; empty means from anywhere',
  'пусто — бессрочно': 'empty means no end date',
  'Секрет машины': 'Machine secret',
  Идентификатор: 'Identifier',
  Секрет: 'Secret',
  'Секрет показывается один раз — сохраните его сейчас.':
    'The secret is shown once — save it now.',
  'Сменить секрет?': 'Rotate the secret?',
  'Сменить секрет': 'Rotate the secret',
  'Прежний секрет и все выданные по нему токены перестанут работать сразу.':
    'The old secret and every token issued with it stop working at once.',
  'Удалить машину?': 'Delete the machine?',
  'Вместе с ней исчезнут её права. Записи в журнале останутся.':
    'Its permissions go with it. The audit log stays.',
  'Введите имя машины': 'Type the machine name',
  'Машин пока нет.': 'No machines yet.',
  'Машина читает выданные ей окружения и не может ничего изменить: в машинном контуре нет маршрутов, которые пишут в секреты. Права выдаются в разделе «Доступ».':
    'A machine reads the environments it was granted and can change nothing: the machine contour has no routes that write to secrets. Permissions are granted in the Access section.',
  'ничего не выдано': 'nothing granted',
  Выключить: 'Disable',
  Была: 'Last seen',
  'Не получилось': 'Did not work',
  'Редактировать все': 'Edit all',
  'Все значения': 'All values',
  'Сохранено ключей': 'Keys saved',
  'отправлено на подтверждение': 'sent for approval',
  'не записано': 'not written',
  'Скопировано в буфер': 'Copied to the clipboard',
  изменено: 'changed',

  'имя проекта должно быть уникальным внутри группы, а не во всей панели':
    'the project name must be unique inside its group, not across the whole panel',
  'Скачать файл': 'Download file',
  'Сохранить изменения': 'Save changes',
  'Выбрать файл': 'Pick a file',
  'Текст можно поправить прямо здесь и сохранить. Сохранение создаёт и обновляет ключи; удалённые из текста строки остаются в панели — удаление делается вручную и попадает в журнал отдельно.':
    'You can edit this text here and save it. Saving creates and updates keys; lines removed from the text stay in the panel — deleting is manual and gets its own audit entry.',
  'показать и править': 'reveal and edit',
  'показать значение': 'reveal the value',
  Скрыть: 'Hide',
  сохранено: 'saved',
  'ждёт подтверждения': 'waiting for approval',
  отклонена: 'rejected',
  'у родителя': 'from the parent',
  Окружения: 'Environments',
  Ключей: 'Keys',
  'Сменить ключ': 'Rotate key',
  'Наследование и смена ключа — то, что трогают редко, поэтому живут здесь. Правки в этой таблице применяются сразу.':
    'Inheritance and key rotation are rarely touched, so they live here. Changes in this table apply immediately.',
  'Сменить ключ окружения?': 'Rotate the environment key?',
  'Сменить ключ окружения': 'Rotate the environment key',
  'Все значения этого окружения будут перешифрованы новым ключом. Читаться они будут как раньше.':
    'Every value in this environment will be re-encrypted with a new key. They will read the same as before.',
  'перешифровано версий': 'versions re-encrypted',
  'выберите существующую или введите новую; можно оставить пустым':
    'pick an existing one or type a new one; can be left empty',
  'или оставьте своё — будет новая группа': 'or keep yours — it becomes a new group',
  'Настройки проекта': 'Project settings',
  'показывается вместо имени; можно оставить пустым':
    'shown instead of the name; can be left empty',
  'правка от роли ниже порога не вступит в силу, пока её не подтвердит кто-то выше':
    'a change from a role below the threshold does not take effect until someone senior approves it',
  'Удалить проект': 'Delete the project',
  'Удалить проект?': 'Delete the project?',
  'Вместе с ним исчезнут все окружения, ключи и их история. Восстановить можно только из бэкапа базы.':
    'All its environments, keys and their history go with it. Recovery is only possible from a database backup.',
  'Введите имя проекта': 'Type the project name',
  'вместе со всеми ключами и историей': 'together with every key and its history',
  'Проект не найден или доступ к нему не выдан.':
    'The project does not exist, or access to it was not granted.',
  'Окружение не найдено или доступ к нему не выдан.':
    'The environment does not exist, or access to it was not granted.',
  'Ссылка скопирована': 'Link copied',
  Готово: 'Done',
  Создать: 'Create',
  Сменить: 'Rotate',
  'строчные латинские буквы, цифры и дефис': 'lowercase latin letters, digits and hyphen',
  'чтобы длинный список читался; можно оставить пустым':
    'so a long list stays readable; can be left empty',
  'напр. Биллинг': 'e.g. Billing',
  'напр. Бэкенд': 'e.g. Backend',
  'Наследовать от': 'Inherit from',
  'ни от какого': 'from nothing',
  'своё значение перекрывает родительское, остальное берётся оттуда':
    'a local value overrides the parent, everything else comes from there',
  'Отклонить правку': 'Reject the change',
  Причина: 'Reason',
  'её увидит автор, и она останется в истории':
    'the author will see it, and it stays in the history',
  'Переименовать ключ': 'Rename the key',
  'Новое имя': 'New name',
  'Удалить ключ?': 'Delete the key?',
  'историю это не стирает, удаление обратимо':
    'history stays, and the deletion can be undone',
  'Вернуть прежнее значение?': 'Restore the previous value?',
  'Значения и история останутся на месте.': 'Values and history stay where they are.',
  'Удалить группу?': 'Delete the group?',
  'Вместе с ней уйдут и выданные ей права.': 'The rights granted to it go away with it.',
  'Учётная запись': 'Account',
  'Отключить учётную запись?': 'Disable the account?',
  'вход закроется сразу, а имя останется в журнале':
    'sign-in stops immediately, the name stays in the audit log',
  'Прежние сессии этой учётки закроются, а событие попадёт в журнал.':
    'Existing sessions of this account will end, and the event goes into the audit log.',
  'право, выданное группе, действует на всех её участников':
    'a right granted to a group applies to all of its members',
  'Сменить корневой ключ?': 'Rotate the root key?',
  'Прежние доли и прежний ключ перестанут подходить.':
    'The old shares and the old key will stop working.',
  Проекты: 'Projects',
  окружение: 'environment',
  проект: 'project',
  проекта: 'projects',
  проектов: 'projects',
  ключ: 'key',
  ключа: 'keys',
  окружения: 'environments',
  'своё': 'own',
  свои: 'own',
  окружений: 'environments',
  'ждут подтверждения': 'waiting for approval',
  'поиск по проектам, группам и окружениям': 'search projects, groups and environments',
  'поиск по окружениям': 'search environments',
  'поиск по ключам': 'search keys',
  'окр.': 'env',
  'на подтверждении': 'awaiting approval',
  'Последнее в журнале': 'Latest in the audit log',
  'Проектов пока нет. Заведите первый — внутри будут окружения и ключи.':
    'No projects yet. Create the first one — environments and keys live inside it.',
  'Вам пока не выдали доступ ни к одному проекту.':
    'You have not been granted access to any project yet.',
  'Группа (можно пусто): команда, продукт, что угодно':
    'Group (optional): a team, a product, anything',
  'Окружений пока нет. Заведите prod или dev — ключи живут в них.':
    'No environments yet. Create prod or dev — keys live in them.',
  'От какого окружения наследовать? Пусто — ни от какого':
    'Which environment to inherit from? Empty means none',
  Наследование: 'Inheritance',
  'наследует от': 'inherits from',
  'Показать ещё': 'Show more',
  Ключи: 'Keys',
  Выбрать: 'Select',
  'с замечаниями': 'with notes',
  'Принятые замечания': 'Accepted notes',
  'Взять значение из {env}?': 'Take the value from {env}?',
  Взять: 'Take',
  'так и надо': 'this is fine',
  'панель перестанет показывать это замечание': 'the panel will stop showing this note',
  'замечание принято': 'note accepted',
  'замечание возвращено': 'note brought back',
  'оставить только ключи с замечаниями': 'show only keys with notes',
  'показать все ключи': 'show all keys',
  'значение начинается или кончается пробелом': 'the value starts or ends with a space',
  'пусто, хотя имя обещает секрет': 'empty, though the name promises a secret',
  'это заготовка, а не значение': 'this is a placeholder, not a value',
  'слишком короткое для секрета': 'too short for a secret',
  'отладка включена на боевом окружении': 'debug is on in a production environment',
  'локальный адрес на боевом окружении': 'a local address in a production environment',
  'тестовый ключ на боевом окружении': 'a test key in a production environment',
  'адрес без шифрования: http вместо https': 'address without encryption: http instead of https',

  // Названия действий журнала: в базе лежат коды, а это их человеческие
  // подписи - те же строки, что показывает список.
  'аварийный сброс пароля владельца': 'owner password emergency reset',
  'база убрана из панели': 'database removed from the panel',
  'включено шифрование в браузере': 'browser encryption enabled',
  'включён второй фактор': 'second factor enabled',
  'восстановлен снимок': 'snapshot restored',
  'временный доступ отозван': 'temporary access revoked',
  вход: 'sign-in',
  'выгружено окружение': 'environment exported',
  'выдан временный доступ к базе': 'temporary database access issued',
  'выдано право': 'permission granted',
  'изменен срок права': 'permission expiry changed',
  'выключен второй фактор': 'second factor disabled',
  'создан токен подключения сервера': 'server enrollment token created',
  'добавлен в группу': 'added to a group',
  'добавлен кластер': 'cluster added',
  'обновлены ключи кластера': 'cluster keys updated',
  'добавлена база': 'database added',
  доступ: 'access',
  журнал: 'audit log',
  'заведена машина': 'machine created',
  'заведена учётная запись': 'account created',
  'загружен .env': '.env imported',
  'записано значение': 'value written',
  'изменена учётная запись': 'account changed',
  'изменено окружение': 'environment changed',
  'изменены оповещения': 'alerts changed',
  'изменён проект': 'project changed',
  'ключ сохранён на сервере': 'key stored on the server',
  'машина включена': 'machine enabled',
  'изменена машина': 'machine changed',
  'неверный пароль при подтверждении': 'wrong password on confirmation',
  'машина выключена': 'machine disabled',
  'машина забрала значения': 'machine pulled values',
  'машина отозвала свои токены': 'machine revoked its tokens',
  'машина отчиталась': 'machine reported in',
  'машина получила токен': 'machine got a token',
  'машине выдан ключ проекта': 'project key issued to a machine',
  'машине отказано': 'machine denied',
  'неудачная попытка отпереть': 'failed unseal attempt',
  'неудачный вход': 'failed sign-in',
  обслуживание: 'maintenance',
  'отказ в подключении': 'enrolment denied',
  'откат значения': 'value rolled back',
  'панель заперта': 'panel sealed',
  'панель отперта': 'panel unsealed',
  'переименован ключ': 'key renamed',
  перенос: 'migration',
  'перенос из другого хранилища': 'migration from another vault',
  'правка ждёт подтверждения': 'edit waits for approval',
  'правка отклонена': 'edit rejected',
  'правка подтверждена': 'edit approved',
  'право отозвано': 'permission revoked',
  'проверка оповещений': 'alerts test',
  'прочитана старая версия': 'old version read',
  'прочитано значение': 'value read',
  'прочитаны все значения': 'all values read',
  'сброшен пароль учётной записи': 'account password reset',
  'сервер подключён': 'server enrolled',
  серверы: 'servers',
  'смена своего пароля': 'own password change',
  'сменён ключ окружения': 'environment key rotated',
  'сменён корневой ключ': 'root key rotated',
  'сменён секрет машины': 'machine secret rotated',
  'снят снимок': 'snapshot taken',
  'снято переопределение': 'override removed',
  'собран аварийный архив': 'emergency archive built',
  'создан владелец панели': 'panel owner created',
  'создан проект': 'project created',
  'создан сейф': 'vault created',
  'создана группа': 'group created',
  'создано окружение': 'environment created',
  'сохранённый ключ удалён': 'stored key deleted',
  'убран из группы': 'removed from a group',
  'удалена группа': 'group deleted',
  'удалена машина': 'machine deleted',
  'удалён кластер': 'cluster deleted',
  'удалён ключ': 'key deleted',
  'удалён проект': 'project deleted',
  'удалён снимок': 'snapshot deleted',
  'учётные записи': 'accounts',
  до: 'until',
  человека: 'people',
  Скопировано: 'Copied',
  'Скопировать ссылку': 'Copy link',
  'Сначала введите пароль проекта': 'Enter the project password first',
  Продолжить: 'Continue',
  'Снимает ops/backup.sh по расписанию: дамп шифруется своим паролем, отметка попадает сюда. Корневого ключа в дампе нет и быть не должно — иначе дамп и ключ ездят вместе.':
    'Taken by ops/backup.sh on a schedule: the dump is encrypted with its own password and the mark lands here. The root key is not in the dump and must not be — otherwise the dump and the key travel together.',
  Группа: 'Group',
  'Наследование и смена ключа — то, что трогают редко, поэтому живут здесь. Правки применяются сразу, без кнопки «Сохранить».':
    'Inheritance and key rotation are rarely touched, so they live here. Edits apply immediately, with no Save button.',
  'Без группы': 'No group',
  'Сочетания клавиш': 'Keyboard shortcuts',
  'Работают, пока курсор не стоит в поле ввода. Буквы можно набирать в любой раскладке.':
    'They work while the cursor is not in a text field. Letters work in any keyboard layout.',
  'поиск на странице': 'search on the page',
  проекты: 'projects',
  сейф: 'vault',
  'по списку ключей': 'move through the key list',
  'открыть строку': 'open the row',
  'сохранить значение': 'save the value',
  'закрыть окно или меню': 'close a dialog or menu',
  'Собираем…': 'Collecting…',
  'В файл попали последние записи: {n} из {total}. Сузьте поиск или период':
    'The file has the latest entries: {n} of {total}. Narrow the search or the period',
  выбрано: 'selected',
  'Снять выбор': 'Clear selection',
  'Перенести в папку': 'Move to folder',
  'Удалить выбранные ключи?': 'Delete the selected keys?',
  'значения останутся в истории, но выдаваться перестанут':
    'values stay in history but stop being served',
  время: 'time in',
  'панель показывает время в своей зоне, а не в зоне вашего компьютера':
    'the panel shows time in its own zone, not your computer’s',
  'все события': 'everything',
  'только отказы': 'denied only',
  'над самой защитой': 'security itself',
  сутки: 'day',
  неделя: 'week',
  месяц: 'month',
  'всё время': 'all time',
  'поиск по проектам, группам, окружениям и ключам':
    'search projects, groups, environments and keys',
  Разделы: 'Sections',
  'без приложений': 'no applications',
  'Меняет секреты в пределах выданного доступа. Правки ждут подтверждения, если проект этого требует.':
    'Changes secrets within granted access. Edits wait for approval if the project requires it.',
  'Только видит ключи и читает значения в пределах выданного доступа.':
    'Only sees keys and reads values within granted access.',
  'правки разработчиков':
    'edits by developers',
  'Без проекта': 'Without a project',
  'Приложения добавляются на странице сервера кнопкой «Подключить приложение».':
    'Applications are added on the server page with “Connect application”.',
  'Все проекты без выданного доступа, права, сейф, оповещения и бэкапы.':
    'All projects without granted access, permissions, the vault, alerts and backups.',
  'Серверы, учётные записи и журнал; окружения - в проектах, выданных целиком. Секреты - по выданному доступу, правки без подтверждения.':
    'Servers, accounts and the audit log; environments in projects granted as a whole. Secrets by granted access, edits without approval.',
  'Доступ к секретам выдаётся в разделе «Доступ», роль его не даёт.':
    'Access to secrets is granted in the Access section; a role does not give it.',
  'Выдать доступ': 'Grant access',
  'Запереть панель?': 'Lock the panel?',
  'Значения перестанут читаться и отдаваться серверам, пока панель не отопрут снова.':
    'Values will not be readable or served to servers until the panel is unlocked again.',
  'Забыть ключ на сервере?': 'Forget the key on the server?',
  'Панель заперта, и файл ключа на сервере - его единственная копия здесь. Без своей копии ключа или долей значения будут потеряны.':
    'The panel is locked, and the key file on the server is its only copy here. Without your own copy of the key or the shares, the values will be lost.',
  'Панель перестанет отпираться сама после перезапуска: ключ придется вводить или собирать из долей.':
    'The panel will no longer unlock itself after a restart: the key will have to be entered or assembled from shares.',
  Забыть: 'Forget',
  'Уйти, не записав?': 'Leave without writing it down?',
  'Права в этой папке не загрузились: значения не показаны.':
    'The rights in this folder did not load: values are not shown.',
  'Значение этой версии лежало в папке, где у вас нет права читать.':
    'The value of this version was in a folder where you have no right to read.',
  'Доли и ключ показываются один раз: после ухода со страницы их не увидеть, а сейф уже работает с ними.':
    'The shares and the key are shown once: after you leave the page they cannot be seen again, and the vault already uses them.',
  Уйти: 'Leave',
  'значение с пробелами': 'value with spaces',
  'Сменить родителя?': 'Change the parent?',
  'Сменить родителя': 'Change the parent',
  'Окружение начнет брать недостающие ключи из {name}, а унаследованное от прежнего родителя пропадет. Серверы получат новые значения на следующем круге.':
    'The environment will take missing keys from {name}, and what it inherited from the previous parent will disappear. Servers get the new values on their next round.',
  'Унаследованные ключи пропадут из окружения, останутся только свои. Серверы получат это на следующем круге.':
    'Inherited keys will disappear from the environment, only its own keys stay. Servers get this on their next round.',
  'Люди и группы': 'People and groups',
  'сервер удалён': 'server deleted',
  'Добавить участника': 'Add member',
  'учётной записи': 'an account',
  'серверу': 'a server',
  'Тип': 'Type',
  'разрешение': 'allow',
  'Права': 'Permissions',
  'Значения сравниваются на сервере и в ответе не передаются.':
    'Values are compared on the server and are not included in the response.',
  'Окружение для сравнения':
    'Environment to compare with',
  'Меняется только путь ключей, значения и история сохраняются.':
    'Only the key path changes; values and history are kept.',
  'Значение {name} будет скопировано из {env} новой версией. Исходное окружение не изменится.':
    'The value of {name} will be copied from {env} as a new version. The source environment stays unchanged.',
  'создаётся новая версия с перешифрованием':
    'a new re-encrypted version is created',
  'Значения проекта шифруются в браузере. Сервер пароль не хранит и восстановить не может.':
    'The project\'s values are encrypted in the browser. The server does not store the password and cannot recover it.',
  'Значение записывается в выбранные окружения новой версией. Где оно уже совпадает, запись не создаётся.':
    'The value is written to the selected environments as a new version. Where it already matches, nothing is written.',
  'через пробел или запятую': 'separated by spaces or commas',
  'Импорт из .env': 'Import from .env',
  'Сравнить с другим окружением': 'Compare with another environment',
  'Неиспользуемые ключи': 'Unused keys',
  'Журнал окружения': 'Environment log',
  'Права доступа': 'Access rights',
  'Отсутствуют в этом окружении': 'Missing in this environment',
  'найден в': 'found in',
  'Скопировать значение из этого окружения': 'Copy the value from this environment',
  'Нет права на запись': 'No write permission',
  'Совпадения значения': 'Matching values',
  'Совпадений нет': 'No matches',
  'Только владелец панели': 'Panel owner only',
  'Событий нет': 'No events',
  'Без чтений за год': 'Not read for a year',
  'Все ключи читались за последний год': 'Every key was read within the last year',
  'изменён': 'changed',
  'Расхождения с': 'Differences from',
  'Расхождений нет': 'No differences',
  'значения различаются': 'values differ',
  'нет в текущем': 'missing in the current one',
  'нет права на чтение': 'no read permission',
  'Отсутствуют обязательные ключи': 'Required keys missing',
  'Найти совпадения значения': 'Find matching values',
  'Скопировать в другие окружения': 'Copy to other environments',
  'Описание и срок действия': 'Description and expiry',
  'Восстановить наследование': 'Restore inheritance',
  'во всех окружениях проекта': 'in all environments of the project',
  'переименовано также в': 'also renamed in',
  'Значения копируются однократно, без связи с исходным окружением': 'Values are copied once, with no link to the source environment',
  'для ключей без указанной папки': 'for keys without a folder',
  'По умолчанию существующие ключи не перезаписываются.': 'Existing keys are not overwritten by default.',
  'Описание показывается в списке ключей. Срок действия — дата плановой замены значения, уведомление приходит заранее.': 'The description is shown in the key list. The expiry is the planned replacement date of the value; a reminder comes in advance.',
  'Описание': 'Description',
  'Срок действия до': 'Expires on',
  'совпадений': 'matching',
  'нет в': 'missing in',
  'Переопределить': 'Override',
  'свой логотип': 'custom logo',
  'стандартный логотип': 'standard logo',
  'Файл логотипа': 'Logo file',
  'Поставить свой логотип': 'Set a custom logo',
  'Исходный код на GitHub': 'Source code on GitHub',
  'Сообщить о проблеме': 'Report a problem',
  'Вариант для тёмной темы': 'Variant for the dark theme',
  'Убрать вариант для тёмной темы': 'Remove the dark theme variant',
  Оформление: 'Appearance',
  'авто: подстроить цвета под тему': 'auto: adapt colours to the theme',
  'всегда на плашке': 'always on a plate',
  'как есть': 'as is',
  'PNG, SVG, WebP или JPEG до {n} КБ': 'PNG, SVG, WebP or JPEG up to {n} KB',
  'Файл больше {n} КБ — уменьшите логотип': 'The file is larger than {n} KB — make the logo smaller',
  'Не удалось прочитать файл': 'Could not read the file',
  'тёмная тема': 'dark theme',
  'светлая тема': 'light theme',
  'Подпись на экране входа': 'Caption on the sign-in screen',
  'например, название компании': 'e.g. company name',
  'Сохранить логотип': 'Save logo',
  'Вернуть стандартный': 'Back to standard',
  Порядок: 'Order',
  'по имени': 'by name',
  'по изменению': 'by last change',
  'по ключам': 'by key count',
  Избранное: 'Favourites',
  Архив: 'Archive',
  'Свернуть все': 'Collapse all',
  'Развернуть все': 'Expand all',
  'В избранное': 'Add to favourites',
  'Убрать из избранного': 'Remove from favourites',
  'Скрыть у себя': 'Hide for me',
  'Вернуть в список': 'Show again',
  'В архив': 'Move to archive',
  'Вернуть из архива': 'Restore from archive',
  скрыт: 'hidden',
  Скрыто: 'Hidden',
  показать: 'show',
  спрятать: 'hide',
  осталось: 'left',
  'поиск по журналу: кто, что, над чем, адрес — по всем записям':
    'search the whole log: who, what, on what, address',
  'ключ проекта выдан': 'project key issued',
  'ключ проекта не выдан': 'project key not issued',
  'агент ещё не прислал свой ключ': 'the agent has not sent its own key yet',
  самостоятельное: 'standalone',
  свой: 'own',
  своих: 'own',
  'значение из другого окружения': 'value comes from another environment',
  Доступ: 'Access',
  'Выданные права': 'Granted rights',
  'Прав пока нет. Владелец панели видит всё и без них, остальные — только то, что здесь выдано.':
    'No rights yet. The panel owner sees everything anyway; everyone else sees only what is granted here.',
  Где: 'Where',
  Что: 'What',
  До: 'Until',
  человек: 'person',
  группа: 'group',
  машина: 'machine',
  группе: 'a group',
  'все проекты': 'all projects',
  'все окружения': 'all environments',
  Окружение: 'Environment',
  'Папка и ниже': 'Folder and below',
  запрет: 'deny',
  бессрочно: 'no end date',
  истекло: 'expired',
  выберите: 'choose',
  'только со включённым вторым фактором': 'only with two-factor enabled',
  Группы: 'Groups',
  'Новая группа': 'New group',
  'Название группы': 'Group name',
  'Кого добавить в группу': 'Who joins the group',
  'убрать из группы': 'remove from the group',
  пусто: 'empty',
  'видеть ключи': 'see keys',
  'читать значения': 'read values',
  'менять значения': 'change values',
  'удалять ключи': 'delete keys',
  'менять ключ окружения': 'rotate the environment key',
  'подтверждать изменения': 'approve changes',
  'Ждут подтверждения': 'Waiting for approval',
  Подтвердить: 'Approve',
  Отклонить: 'Reject',
  'ждёт того, кто выше': 'waiting for someone senior',
  'правка ждёт': 'change pending',
  'Почему отклоняем? Причина попадёт в историю':
    'Why reject it? The reason goes into the history',
  'Подтверждение изменений': 'Change approval',
  'не требуется': 'not required',
  'Двухфакторная аутентификация': 'Two-factor authentication',
  вкл: 'on',
  'Код из приложения': 'Code from the app',
  'Код не подошёл': 'The code did not match',
  'Отсканируйте код приложением-аутентификатором и введите шесть цифр, чтобы включить.':
    'Scan the code with an authenticator app and enter six digits to enable it.',
  'Если камера недоступна, введите ключ вручную:':
    'If the camera is unavailable, enter the key by hand:',
  'Второй фактор включен. Чтобы выключить, подтвердите пароль и код из приложения: иначе его снял бы любой, кто дотянется до открытой вкладки.':
    'Two-factor is on. To turn it off, confirm your password and a code from the app: otherwise anyone who reaches an open tab could remove it.',
  Секреты: 'Secrets',
  'Новый проект': 'New project',
  'Новое окружение': 'New environment',
  'окружений пока нет': 'no environments yet',
  'Имя проекта латиницей, например billing': 'Project name in latin letters, e.g. billing',
  'Имя окружения, например prod': 'Environment name, e.g. prod',
  'поиск по имени или папке': 'search by name or folder',
  'Добавить ключ': 'Add a key',
  Экспорт: 'Export',
  Значение: 'Value',
  'Ключей пока нет': 'No keys yet',
  'Ничего не нашлось': 'Nothing found',
  'Кто менял': 'Changed by',
  Показать: 'Reveal',
  Копировать: 'Copy',
  Изменить: 'Edit',
  История: 'History',
  Переименовать: 'Rename',
  Удалить: 'Delete',
  'Новое имя ключа': 'New key name',
  'Удалить ключ {name}? Историю это не стирает, удаление обратимо.':
    'Delete the key {name}? History stays, and the deletion can be undone.',
  'Новый ключ': 'New key',
  Имя: 'Name',
  версия: 'version',
  'Комментарий к изменению': 'Comment for this change',
  'зачем меняем — это останется в истории': 'why it changes — this stays in the history',
  Комментарий: 'Comment',
  текущая: 'current',
  удаление: 'deletion',
  Вернуть: 'Restore',
  'Вернуть значение версии {n}? Появится новая версия.':
    'Restore the value of version {n}? A new version will be created.',
  'Значение версии': 'Value of version',
  'Импорт .env': 'Import .env',
  'Содержимое файла': 'File contents',
  'перезаписывать существующие': 'overwrite existing keys',
  Импортировать: 'Import',
  'Создано {c}, обновлено {u}, пропущено {s}': 'Created {c}, updated {u}, skipped {s}',
  'Экспорт .env': 'Export .env',
  'Это все значения окружения открытым текстом. Выгрузка отдельной строкой записана в журнал.':
    'These are all the values of the environment in plain text. The export is recorded in the audit log as its own entry.',
  Скопировать: 'Copy',
  'Снимок помнит, какой ключ какой версией был. Значения не копируются — они и так в истории.':
    'A snapshot remembers which version each key was at. Values are not copied — they are already in the history.',
  'например: перед релизом 4.2': 'e.g. before release 4.2',
  Снять: 'Take',
  ключей: 'keys',
  'Что изменится': 'What will change',
  'При восстановлении:': 'On restore:',
  Восстановить: 'Restore',
  'Возвращено {r}, удалено {d}': 'Restored {r}, removed {d}',
  Меню: 'Menu',
  'На главную': 'Home',
  'О панели Sekvyr': 'About Sekvyr',
  Закрыть: 'Close',
  Лицензия: 'License',
  'Панель хранения секретов и переменных окружения. Значения шифруются, ключ живёт только в памяти панели.':
    'A panel for secrets and environment variables. Values are encrypted; the key lives only in the panel memory.',
  Сейф: 'Vault',
  'сейф ещё не создан': 'no vault yet',
  открыта: 'unlocked',
  'Режим ключа': 'Key mode',
  доли: 'shares',
  из: 'of',
  'переменная окружения': 'environment variable',
  'Поколение ключа': 'Key generation',
  'Создать сейф': 'Create the vault',
  'Доли: ключ разложен по нескольким местам или людям':
    'Shares: the key is split across places or people',
  'Один ключ: ввожу сам после каждого перезапуска':
    'A single key: I enter it myself after every restart',
  'Один ключ: лежит на сервере, панель поднимается сама':
    'A single key: kept on the server, the panel unseals itself',
  'один ключ, вводится вручную': 'a single key, entered by hand',
  'один ключ, панель поднимается сама': 'a single key, the panel unseals itself',
  'На сервере ключа нет: дамп базы, бэкап и украденный диск без него бесполезны. Плата — панель после каждого перезапуска ждёт, пока вы вставите ключ.':
    'The key is not on the server: a database dump, a backup and a stolen disk are useless without it. The price is that the panel waits for the key after every restart.',
  'Панель поднимается сама после перезагрузки. Плата — ключ лежит рядом с ней, поэтому root на хосте означает доступ ко всем значениям.':
    'The panel comes up on its own after a reboot. The price is that the key sits next to it, so root on the host means access to every value.',
  'Ключ показывается один раз. Положите его в менеджер паролей: после каждого перезапуска панели вы будете вставлять его здесь. На сервере он не хранится, поэтому дамп базы и бэкап без него бесполезны.':
    'The key is shown once. Put it in your password manager: you will paste it here after every restart. It is not stored on the server, so a database dump and a backup are useless without it.',
  'Ключ показывается один раз. Положите его файлом на сервер и укажите путь в SEKVYR_ROOT_KEY_FILE, иначе после перезапуска панель окажется запертой. Копию храните отдельно от бэкапов.':
    'The key is shown once. Put it in a file on the server and point SEKVYR_ROOT_KEY_FILE at it, otherwise the panel comes up sealed after a restart. Keep a copy away from your backups.',
  'Выбран автоматический подъём, но ключ панели не задан: после перезапуска она окажется запертой. Положите ключ файлом и укажите путь в SEKVYR_ROOT_KEY_FILE.':
    'Automatic unsealing was chosen, but no root key is configured: the panel will come up sealed after a restart. Put the key in a file and point SEKVYR_ROOT_KEY_FILE at it.',
  'Корневой ключ задан в окружении панели, хотя при заведении выбирался ручной ввод. Панель поднимется сама, и ключ лежит на сервере.':
    'A root key is configured for the panel even though manual entry was chosen. The panel will unseal itself, and the key sits on the server.',
  'Администратор один? Берите один ключ и держите его в менеджере паролей — или доли, разложенные по разным местам, чтобы потеря одного хранилища не была фатальной.':
    'Working alone? Take a single key and keep it in your password manager — or take shares and spread them across places, so losing one of them is not fatal.',
  'Всего долей': 'Shares in total',
  'Нужно для входа': 'Needed to unseal',
  'Ключа целиком не будет ни у кого. Порог 3 из 5 переживает потерю двух долей; потеря большего числа — потеря всех значений.':
    'Nobody holds the whole key. A 3-of-5 threshold survives losing two shares; losing more means losing every value.',
  Отпереть: 'Unlock',
  Ввести: 'Submit',

  'Доля или корневой ключ': 'Share or root key',
  'Введено долей': 'Shares entered',
  'Запишите это сейчас': 'Write this down now',
  'Записал, скрыть': 'Written down, hide',
  'Опасные действия': 'Dangerous actions',
  'Сменить корневой ключ': 'Rotate the root key',
  'Сменить корневой ключ? Прежние доли перестанут работать.':
    'Rotate the root key? The old shares will stop working.',
  'Корневой ключ сменён. Прежние доли и прежний ключ больше не работают — замените их везде, где они лежат.':
    'The root key has been rotated. The old shares and key no longer work — replace them wherever they are kept.',
  'Как только панель заперта, значения перестают выдаваться и людям, и серверам.':
    'Once the panel is locked, values stop being handed out — to people and servers alike.',
  'Долей должно быть хотя бы две — иначе это просто копия ключа.':
    'There must be at least two shares — otherwise it is just a copy of the key.',
  'Порог 1 означает, что каждая доля сама по себе открывает панель. Возьмите от 2.':
    'A threshold of 1 means every single share unseals the panel on its own. Use 2 or more.',
  'Порог не может быть больше числа долей.': 'The threshold cannot exceed the number of shares.',
  'Панель заперта: чтобы читать значения, введите корневой ключ.':
    'The panel is locked: enter the root key to read values.',
}

// Без сохраненного выбора язык берется из браузера: русский тем, у кого браузер
// русский, остальным английский. Раньше всем доставался русский, и человек,
// поставивший панель с GitHub, начинал с поиска переключателя.
function initialLang(): Lang {
  const saved = localStorage.getItem(LANG_KEY)
  if (saved === 'ru' || saved === 'en') return saved
  const browser = (navigator.languages?.[0] || navigator.language || '').toLowerCase()
  return browser.startsWith('ru') ? 'ru' : 'en'
}

let current: Lang = initialLang()
// index.html объявляет русский; без этой строки браузер считал бы английскую
// страницу русской (переносы, проверка орфографии, чтение с экрана).
document.documentElement.setAttribute('lang', current)

/** Язык интерфейса вне React-дерева. */
export function currentLang(): Lang {
  return current
}

/** Перевод вне React-дерева (например, в api.ts, где хука нет). */
export function tr(text: string, vars?: Record<string, string | number>): string {
  const base = current === 'en' ? EN[text] ?? text : text
  if (!vars) return base
  return Object.entries(vars).reduce(
    (acc, [k, v]) => acc.replaceAll(`{${k}}`, String(v)),
    base,
  )
}

type Ctx = {
  lang: Lang
  setLang: (l: Lang) => void
  t: (text: string, vars?: Record<string, string | number>) => string
}

const I18nContext = createContext<Ctx>({ lang: 'ru', setLang: () => {}, t: tr })

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(current)

  const setLang = useCallback((l: Lang) => {
    current = l
    localStorage.setItem(LANG_KEY, l)
    setLangState(l)
    document.documentElement.setAttribute('lang', l)
  }, [])

  const value = useMemo<Ctx>(
    () => ({ lang, setLang, t: (text, vars) => tr(text, vars) }),
    [lang, setLang],
  )
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): Ctx {
  return useContext(I18nContext)
}

/** Русская форма числительного: 1 ключ, 2 ключа, 5 ключей.
 *
 * Нужна именно функция, а не "ключ(а/ей)": панель показывает счетчики в каждой
 * карточке, и "1 своих" бросается в глаза так же, как опечатка. В английском
 * достаточно двух форм, поэтому третья там просто дублирует вторую. */
export function plural(n: number, forms: [string, string, string]): string {
  // Для английского берем вторую форму: третья у "человек" совпадает с первой
  // ("5 person"), а вторая у всех слов переведена множественным числом.
  if (current === 'en') return n === 1 ? forms[0] : forms[1]
  const mod100 = Math.abs(n) % 100
  const mod10 = mod100 % 10
  if (mod100 >= 11 && mod100 <= 14) return forms[2]
  if (mod10 === 1) return forms[0]
  if (mod10 >= 2 && mod10 <= 4) return forms[1]
  return forms[2]
}
