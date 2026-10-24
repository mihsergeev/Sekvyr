import { currentLang, tr } from './i18n'

/* Тексты, которые формирует сервер: ошибки API, подробности журнала,
 * предупреждения при создании сейфа, состояние бэкапа.
 *
 * Сервер пишет их по-русски. Журнал хранит строку как есть, а агент сверяет
 * отказы машинного контура со своей таблицей (agent/apierrors.go), поэтому
 * английский интерфейс переводит их у себя: точные строки словарем, строки с
 * подстановками шаблонами. Неизвестная строка показывается как есть: русский
 * текст лучше пустоты. Полноту словаря сверяет ops/selfcheck.py, и новое
 * сообщение сервера без перевода роняет самопроверку.
 */

/** Точные строки. Ключ - ровно то, что отдает сервер. */
const EXACT: Record<string, string> = {
  // вход, сессия, права
  'Текущий пароль неверен': 'The current password is wrong',
  'Второй фактор уже включён': 'Two-factor authentication is already on',
  'Сначала запросите секрет': 'Request the secret first',
  'Код не подошёл': 'The code did not match',
  'Пароль неверен': 'The password is wrong',
  'Слишком много попыток входа — повторите позже': 'Too many login attempts, try again later',
  'Слишком много попыток — повторите позже': 'Too many attempts, try again later',
  'ключ переименовали или перенесли, пока выполнялся запрос: обновите страницу':
    'the key was renamed or moved while the request was running: reload the page',
  'Снимок удалили, пока шло восстановление: окружение не тронуто':
    'The snapshot was deleted while it was being restored: the environment was not touched',
  'Такая запись уже есть: ее только что завели параллельно. Обновите страницу':
    'This record already exists: it was just created by a parallel request. Reload the page',
  'Запрос столкнулся с параллельным и отменен: повторите его':
    'The request collided with a parallel one and was cancelled: try it again',
  принято: 'accepted',
  'токены отозваны': 'tokens revoked',
  'Окружение удалили, пока выполнялся запрос: обновите страницу':
    'The environment was deleted while the request was running: reload the page',
  'Связанную запись удалили, пока выполнялся запрос: обновите страницу':
    'A related record was deleted while the request was running: reload the page',
  'создатель токена больше не может выдать это окружение':
    'the creator of the token can no longer grant this environment',
  'У окружения нет действующего ключа шифрования: база повреждена или смена ключа оборвалась. Восстановите базу из бэкапа':
    'The environment has no active encryption key: the database is damaged or a key change broke off. Restore the database from a backup',
  'Значение зашифровано ключом окружения, которого больше нет: его не открыть. Запишите этот ключ заново':
    'A value is encrypted with an environment key that no longer exists and cannot be opened. Write this key again',
  'Второй фактор не включен': 'Two-factor authentication is not on',
  'Пароль длиннее 72 байт: bcrypt учитывает только первые 72, а это 36 русских букв. Сократите его':
    'The password is longer than 72 bytes: bcrypt only takes the first 72 into account. Make it shorter',
  'У этой учетной записи есть права, которых нет у вас: задать ей пароль может тот, у кого они тоже есть, или владелец':
    'This account has permissions you do not have: its password can be set by someone who has them too, or by the owner',
  'Для этого ServiceAccount машина уже заведена': 'A machine for this ServiceAccount already exists',
  'токен живет дольше суток: это уже статический секрет':
    'the token lives longer than a day: that is a static secret already',
  описание: 'description',
  бессрочно: 'no expiry',
  'Неверный логин или пароль': 'Wrong login or password',
  'Недействительный или отсутствующий токен': 'Invalid or missing token',
  'Этой учётной записи не разрешён вход с вашего адреса':
    'This account may not log in from your address',
  'Учётная запись только для просмотра — изменения запрещены':
    'This account is view-only: changes are not allowed',
  'Требуются права владельца панели': 'Panel owner rights are required',
  'Недостаточно прав для этого раздела': 'Not enough rights for this section',
  'Неверный пароль': 'Wrong password',
  'Нужен код второго фактора': 'A two-factor code is required',
  'Неверный код второго фактора': 'Wrong two-factor code',

  // логотип
  'В SVG есть скрипты или внешние ссылки — сохраните логотип без них или загрузите PNG':
    'The SVG contains scripts or external links: save the logo without them or upload a PNG',
  'Нужен файл PNG, JPEG, WebP, GIF или SVG': 'A PNG, JPEG, WebP, GIF or SVG file is required',
  'Логотип не задан': 'No logo is set',
  'Выберите файл логотипа': 'Choose a logo file',
  'Файл повреждён': 'The file is damaged',
  'Пустой файл': 'The file is empty',

  // шифрование в браузере
  'Режим уже включён': 'The mode is already on',
  'В проекте уже есть ключи: включить шифрование в браузере можно только у пустого проекта':
    'The project already has keys: browser-side encryption can only be turned on for an empty project',
  'Обёртка ключа проекта потеряна': 'The wrapped project key is missing',
  'У проекта нет шифрования в браузере': 'The project does not use browser-side encryption',
  'Машина не найдена': 'Machine not found',
  'У машины ещё нет ключа: агент присылает его при первом обращении':
    'The machine has no key yet: the agent sends it on its first request',
  'Проект не найден': 'Project not found',
  'публичный ключ не разбирается как base64': 'the public key is not valid base64',
  'публичный ключ должен быть длиной 32 или 65 байт':
    'the public key must be 32 or 65 bytes long',
  'в проект с шифрованием в браузере можно класть только запечатанные значения — панель не должна видеть открытый текст':
    'a project with browser-side encryption only accepts sealed values: the panel must not see plaintext',
  'запечатанное значение не того размера': 'the sealed value has the wrong size',
  'запечатанное значение не разбирается как base64': 'the sealed value is not valid base64',
  'обёртка': 'the wrap',
  'у проекта шифрование в браузере: перенести в него открытые значения нельзя, запечатать их некому':
    'the project uses browser-side encryption: plaintext values cannot be migrated into it, nobody here can seal them',
  'у проекта шифрование в браузере: файл с открытыми значениями сюда не заливается, ключи заводятся по одному, и значения запечатывает браузер':
    'the project uses browser-side encryption: a file of plaintext values cannot be imported here, keys are added one by one and the browser seals the values',
  'у проекта шифрование в браузере: файл собирает тот, у кого есть ключ проекта, а не сервер':
    'the project uses browser-side encryption: the file is built by whoever holds the project key, not by the server',
  'В проекте с шифрованием в браузере значения копируются из браузера':
    'In a project with browser-side encryption values are copied from the browser',
  'В проекте с шифрованием в браузере раскладывать значения нужно из браузера':
    'In a project with browser-side encryption values are spread from the browser',

  // серверы и кластеры
  'Дата не разобралась: нужен формат ГГГГ-ММ-ДД': 'The date could not be parsed: use YYYY-MM-DD',
  'Для кластерной личности нужны namespace и ServiceAccount':
    'A cluster identity needs a namespace and a ServiceAccount',
  'У кластерной личности нет секрета: вход по токену ServiceAccount':
    'A cluster identity has no secret: it logs in with a ServiceAccount token',
  'Окружение не найдено': 'Environment not found',
  'Кластер не найден': 'Cluster not found',
  'Учетные данные этой машины открывают окружение, которое вам не выдано: распоряжаться ими может тот, кто сам читает это окружение, или владелец':
    'The credentials of this machine open an environment you have not been granted: only someone who can read that environment, or the panel owner, can manage them',
  'в ключах кластера нет ни одного пригодного': 'the cluster keys contain no usable key',
  'ключ с таким kid кластеру не принадлежит': 'no key with this kid belongs to the cluster',
  'это не токен ServiceAccount': 'this is not a ServiceAccount token',
  ключи: 'keys',

  // перенос
  'нужны идентификатор и секрет машинной личности':
    'the machine identity ID and secret are required',
  'нужны проект и окружение Infisical': 'the Infisical project and environment are required',
  'нужен токен Vault': 'a Vault token is required',
  'слишком много ключей — сузьте путь': 'too many keys, narrow the path',
  'Infisical не отдал секреты': 'Infisical did not return the secrets',
  'Infisical не отдал список проектов': 'Infisical did not return the project list',
  'в поддереве больше 500 узлов — сузьте путь': 'the subtree has more than 500 nodes, narrow the path',
  'Vault не отдал список': 'Vault did not return the list',
  'вход в Infisical не удался': 'the Infisical login failed',
  'Infisical не вернул токен': 'Infisical did not return a token',
  'Infisical не отдал значение: у машинной личности нет права его читать':
    'Infisical did not return the value: the machine identity may not read it',
  'недопустимое имя': 'invalid name',
  'недопустимая папка': 'invalid folder',

  // оповещения
  'Каналы оповещений не настроены': 'No alert channels are set up',
  'Вебхук': 'Webhook',
  'Приёмник журнала': 'Audit log receiver',
  'Зеркало Bot API': 'Bot API mirror',
  'адрес должен начинаться с https:// — иначе оповещения уйдут открытым текстом':
    'the address must start with https://, otherwise alerts would travel in plain text',
  'в адресе не разобрать имя хоста': 'the address has no recognizable host name',
  'в адресе не разобрать порт': 'the address has no recognizable port',
  'адреса внутренних сетей недопустимы': 'internal network addresses are not allowed',
  'адрес источника должен начинаться с http:// или https://':
    'the source address must start with http:// or https://',
  'адрес источника ведет в саму панель или к служебным адресам облака':
    'the source address leads into the panel itself or to cloud service addresses',

  // права и группы
  'Учётная запись не найдена': 'Account not found',
  'Наблюдателю выдаются только «видеть ключи» и «читать значения»':
    'A viewer can only be granted "see keys" and "read values"',
  'Окружение принадлежит другому проекту': 'The environment belongs to another project',
  'Право не найдено': 'Right not found',
  'Группа с таким именем уже есть': 'A group with this name already exists',
  'Группа или учётная запись не найдена': 'Group or account not found',
  'Такого участника в группе нет': 'The group has no such member',
  'Группа не найдена': 'Group not found',
  'Дату окончания не разобрать': 'The end date could not be parsed',

  // проекты и окружения
  'В этой группе уже есть проект с таким именем':
    'This group already has a project with this name',
  'Проект с таким именем уже есть': 'A project with this name already exists',
  'Панель заперта: окружения появятся только после ввода ключа':
    'The panel is sealed: environments appear only after the key is entered',
  'Окружения повторяются': 'The environments repeat',
  'Неизвестный уровень роли': 'Unknown role level',
  'Такое окружение уже есть': 'This environment already exists',
  'Копировать можно из окружения этого проекта':
    'Values can only be copied from an environment of this project',
  'Родителем может быть окружение того же проекта':
    'The parent must be an environment of the same project',
  'Родителем можно назначить только окружение, которое вы читаете целиком: его значения увидит каждый, кто читает наследника':
    'Only an environment you can read in full can be a parent: everyone who reads the child will see its values',
  'Скопировать можно только окружение, которое вы читаете целиком':
    'You can only copy an environment you can read in full',
  'Окружение не наследует само себя': 'An environment cannot inherit from itself',
  'Так получится круг наследования': 'That would make an inheritance loop',
  проекта: 'of the project',
  окружения: 'of the environment',

  // ключи и значения
  'Такого окружения в проекте нет': 'The project has no such environment',
  'Снимок не найден': 'Snapshot not found',
  'Такой правки, ожидающей подтверждения, нет': 'There is no such change waiting for approval',
  'Свою правку подтверждает кто-то другой': 'Someone else has to approve your own change',
  'Подтвердить может только роль выше той, что предложила правку':
    'Only a role above the one that proposed the change can approve it',
  'У окружения нет родителя — наследовать не от кого':
    'The environment has no parent: there is nothing to inherit from',
  'Здесь нет своего значения': 'There is no own value here',
  'Такого ключа здесь нет': 'There is no such key here',
  'Значение не сошлось с ключом — возможна правка базы в обход панели':
    'The value does not match its key: the database may have been edited around the panel',
  'Не разобрал дату: нужен вид 2027-03-01': 'The date could not be parsed: use the form 2027-03-01',
  'Сравнивать можно окружения одного проекта':
    'Only environments of one project can be compared',
  'шифротекст не сошёлся': 'the ciphertext does not match',
  'секрет удалён или не имеет версий': 'the secret was deleted or has no versions',
  'такой версии нет или она была удалением': 'there is no such version, or it was a deletion',
  'имя и путь не изменились': 'the name and the path did not change',
  'ключ с таким именем здесь уже есть': 'a key with this name already exists here',
  'отметка не читается: в ней не объект': 'the mark cannot be read: it is not an object',
  'Окружения в проекте заводит владелец панели или тот, у кого есть право менять проект целиком':
    'Environments in a project are created by the panel owner or by someone allowed to change the whole project',
  'ключи кластера не разобрались: нужен объект JWKS с массивом keys':
    'the cluster keys could not be parsed: a JWKS object with a keys array is expected',
  'Такого объекта нет: номер вне допустимого диапазона': 'There is no such object: the number is out of range',
  'Значение длиннее, чем помещается в базу': 'The value is longer than the database can hold',
  'В запросе нулевой символ: такие строки база не хранит': 'The request has a null character: the database does not store such strings',
  'ключ ноды сменился, выданные этой машине ключи проектов сняты':
    'the node key changed, the project keys granted to this machine were withdrawn',
  'под этим именем здесь хранится история удаленного или взятого у родителя ключа: верните его из истории или выберите другое имя':
    'this name here holds the history of a deleted key or one taken from the parent: bring it back from the history or choose another name',
  'снимок с таким именем уже есть': 'a snapshot with this name already exists',
  'имя или папка ключа не совпадают с версией':
    'the key name or folder does not match the version',
  'откатиться можно только к версии, которая действовала':
    'you can only roll back to a version that was in effect',
  'у этой версии нет своего значения: ключ тогда брался у родителя':
    'this version has no own value: the key was taken from the parent then',
  'Ключ изменили после этой правки: ее нужно предложить заново':
    'The key was changed after this proposal: propose it again',
  'Правки вашей роли в этом проекте идут на подтверждение, а это действие его не проходит: оно доступно роли не ниже порога проекта':
    'Changes by your role in this project go through approval, and this action does not: it needs a role at or above the project threshold',
  'nonce не того размера': 'the nonce has the wrong size',

  // учетные записи
  'Такой логин уже занят': 'This login is already taken',
  'Это последний владелец панели — роль не менять':
    'This is the last panel owner: the role cannot change',
  'Это последний владелец панели — не отключать':
    'This is the last panel owner: it cannot be disabled',
  'Распоряжаться можно только учётками с ролью ниже своей':
    'You can only manage accounts with a role below yours',
  'Неизвестная роль': 'Unknown role',
  'Нельзя выдать роль вровень со своей или выше':
    'You cannot grant a role equal to yours or above it',

  // сейф
  'Долей должно быть хотя бы две — иначе это просто копия ключа. Если ключ должен лежать целиком, выберите режим переменной окружения':
    'There must be at least two shares, otherwise it is just a copy of the key. If the key should be kept whole, choose the environment variable mode',
  'Порог 1 означает, что каждая доля сама по себе открывает панель, то есть равна полному ключу. Возьмите порог от 2 или выберите режим переменной окружения':
    'A threshold of 1 means every share unseals the panel on its own, so each one equals the whole key. Use a threshold of 2 or more, or choose the environment variable mode',
  'Сейф ещё не заведён': 'The vault is not set up yet',
  'Это не корневой ключ панели': 'This is not the root key of the panel',
  'Введите долю или корневой ключ': 'Enter a share or the root key',
  'Ключ не сошёлся: среди введённых долей есть чужая. Начните заново':
    'The key did not match: one of the entered shares belongs to another key. Start over',
  'Панель заперта: сначала введите текущий корневой ключ':
    'The panel is sealed: enter the current root key first',
  'Путь для ключа не задан: укажите SEKVYR_ROOT_KEY_FILE и перезапустите панель':
    'No path for the key is set: set SEKVYR_ROOT_KEY_FILE and restart the panel',
  'Панель заперта: сначала введите ключ': 'The panel is sealed: enter the key first',
  'Панель заперта: чтобы читать значения, введите корневой ключ':
    'The panel is sealed: enter the root key to read values',
  'панель заперта': 'the panel is sealed',
  'сейф уже заведён': 'the vault is already set up',
  'неизвестный режим корневого ключа': 'unknown root key mode',
  'Доли показываются один раз. Раздайте их разным людям и сохраните вне этой панели: восстановить их неоткуда, а без порога долей значения не расшифруются никогда.':
    'The shares are shown once. Hand them to different people and keep them outside this panel: they cannot be recovered, and without the threshold of shares the values can never be decrypted.',
  'Ключ показывается один раз. Положите его в SEKVYR_ROOT_KEY_FILE (права 0400, вне тома с базой) и храните копию отдельно от бэкапов: потерянный ключ означает потерю всех значений.':
    'The key is shown once. Put it into SEKVYR_ROOT_KEY_FILE (mode 0400, outside the database volume) and keep a copy away from the backups: a lost key means every value is lost.',
  'доля не сходится с контрольной суммой — проверьте, чем копировали':
    'the share does not match its checksum: check how it was copied',
  'доля другого формата': 'the share is of another format',
  'нужно 2 <= порог <= число долей <= 255': '2 <= threshold <= number of shares <= 255 is required',
  'нет ни одной доли': 'there are no shares',
  'доли от разных ключей': 'the shares belong to different keys',
  'одна и та же доля подана дважды': 'the same share was entered twice',
  'доли разной длины': 'the shares differ in length',
  'в GF(256) нет обратного к нулю': 'zero has no inverse in GF(256)',
  'это не доля Sekvyr': 'this is not a Sekvyr share',
  'доля испорчена': 'the share is damaged',

  // запечатанные файлы
  'это не запечатанный файл Sekvyr': 'this is not a sealed Sekvyr file',
  'заголовок не разобрался': 'the header could not be parsed',
  'файл новее этой утилиты': 'the file is newer than this tool',
  'файл запечатан паролем — его и нужно ввести': 'the file is sealed with a password: enter that password',
  'файл запечатан ключом — нужен ключ на 32 байта': 'the file is sealed with a key: a 32-byte key is required',
  'файл обрывается: последний кусок не помечен как последний':
    'the file is cut short: the last chunk is not marked as the last one',
  'файл обрывается посреди куска': 'the file is cut short in the middle of a chunk',
  'не открывается: неверный пароль либо файл испорчен':
    'it does not open: the password is wrong or the file is damaged',
  'файл испорчен: кусок не сошёлся': 'the file is damaged: a chunk does not match',
  'нужен либо пароль, либо ключ на 32 байта': 'either a password or a 32-byte key is required',
  'ключ должен быть длиной 32 байта': 'the key must be 32 bytes long',

  // бэкапы
  'отметки о бэкапе ещё нет': 'there is no backup mark yet',
  'в отметке не разобрать время': 'the time in the mark cannot be parsed',

  // журнал: подробности событий
  система: 'system',
  'неверный код 2FA': 'wrong 2FA code',
  'порог попыток достигнут': 'attempt limit reached',
  'значения шифруются в браузере, сервер их не видит':
    'values are encrypted in the browser, the server does not see them',
  'файл .env': '.env file',
  доставлено: 'delivered',
  'вместе с окружениями, ключами и историей': 'with its environments, keys and history',
  'снято переопределение': 'override removed',
  'уже открыта': 'already unsealed',
  'корневым ключом': 'with the root key',
  'долей достаточно, но ключ не сошёлся': 'enough shares, but the key did not match',
  открыта: 'unsealed',
  'Панель будет отпираться сама при запуске': 'The panel will unseal itself on start',
  'Ключ удалён': 'The key was deleted',
  'Файла и так не было': 'There was no file anyway',
  'аварийный сброс по SEKVYR_ADMIN_PASSWORD_RESET': 'emergency reset via SEKVYR_ADMIN_PASSWORD_RESET',
  название: 'title',
  группа: 'group',
  'в архив': 'archived',
  'из архива': 'unarchived',
  нет: 'none',
  отключена: 'disabled',
  включена: 'enabled',
  'откуда угодно': 'from anywhere',
  // подробности журнала: оповещения и свой логотип
  вебхук: 'webhook',
  'копия журнала': 'audit log copy',
  выключено: 'off',
  настройки: 'settings',
  'тёмная тема': 'dark theme',
  'вариант для тёмной темы убран': 'the dark theme variant removed',
  'Восстановление уберет ключи, заведенные после снимка, а права удалять их у вас нет':
    'The restore would remove keys created after the snapshot, and you have no right to delete them',
  'убрать: у родителя такого ключа нет': 'remove: the parent has no such key',
  'Шифрование в браузере включает владелец панели или тот, кому проект выдан целиком на запись':
    'Browser-side encryption is turned on by the panel owner or by someone granted write on the whole project',
  'Восстановление перенесет старое значение из папки, где у вас нет права читать значения':
    'The restore would move an old value out of a folder where you have no right to read values',
  'было в закрытой папке': 'was in a closed folder',
  'в закрытой папке': 'in a closed folder',
  'переименован из закрытой папки': 'renamed from a closed folder',
  'Подтвердить правку может только роль не ниже порога проекта':
    "Only a role at or above the project's threshold can approve a change",
  'Эту учетную запись отключила роль выше вашей: включить ее может только роль не ниже':
    'This account was disabled by a role above yours: only that role or higher can turn it back on',
  'автора отключили': 'the author was disabled',
  'автору сменили роль': "the author's role was changed",
  'сброшен владельцем': 'reset by the owner',
  // правка поверх чужой
  'Ключ изменили, пока вы его правили: ваша правка не записана':
    'The key was changed while you were editing it: your edit was not saved',
  'Ключ удалили, пока вы его правили: ваша правка не записана':
    'The key was deleted while you were editing it: your edit was not saved',
  'Ключ с таким именем уже есть: ваша правка не записана':
    'A key with this name already exists: your edit was not saved',
}

/** Строки с подстановками. Заготовка ровно как в коде сервера, {} - место
 *  подстановки. Подставленное переводится еще раз: часто это не данные, а
 *  русское слово ("проекта", "видеть ключи") или вложенная ошибка. */
const TEMPLATES: [string, string][] = [
  // ошибки
  ['Нет права «{}» в этом месте', 'No "{0}" right in this place'],
  ['Нет права «{}» в этом проекте', 'No "{0}" right in this project'],
  ['Файл больше {} КБ — уменьшите логотип', 'The file is larger than {0} KB: make the logo smaller'],
  ['Для удаления подтвердите имя машины: {}', 'To delete, confirm the machine name: {0}'],
  ['Для удаления подтвердите имя кластера: {}', 'To delete, confirm the cluster name: {0}'],
  ['Для удаления подтвердите имя проекта: {}', 'To delete, confirm the project name: {0}'],
  [
    'на той стороне {} ключей — это больше предела ({}); сузьте путь',
    'the source has {0} keys, more than the limit ({1}): narrow the path',
  ],
  ['Неизвестные действия: {}', 'Unknown actions: {0}'],
  ['Машине можно выдать только чтение, а не {}', 'A machine can only be granted reading, not {0}'],
  ['Имя {}: строчные латинские буквы, цифры и дефис', 'The name {0}: lowercase Latin letters, digits and hyphens'],
  ['Файл не разобрался: {}', 'The file could not be parsed: {0}'],
  ['Не разобрал адрес: {}', 'Could not parse the address: {0}'],
  [
    'Порог ({}) больше числа долей ({}) — отпереть панель было бы невозможно',
    'The threshold ({0}) is larger than the number of shares ({1}): the panel could never be unsealed',
  ],
  ['{} не того размера', '{0} has the wrong size'],
  ['{} не разбирается как base64', '{0} is not valid base64'],
  ['у окружения {} нет активного ключа', 'environment {0} has no active key'],
  ['у окружения {} нет ключа поколения {}', 'environment {0} has no key of generation {1}'],
  ['Vault не отдал секрет {}', 'Vault did not return the secret {0}'],
  [
    '{}: ответ не в том формате, что описан в API источника',
    '{0}: the answer is not in the format described by the source API',
  ],
  ['{}: ответ больше {} МБ, сузьте путь', '{0}: the answer is larger than {1} MB, narrow the path'],
  ['на той стороне больше {} ключей, сузьте путь', 'the source has more than {0} keys, narrow the path'],
  [
    'ключей из импортов Infisical: {}. Они переносятся как обычные ключи и ссылками больше не будут, а ключ самого окружения важнее импортированного с тем же именем',
    'keys from Infisical imports: {0}. They are moved as ordinary keys and are no longer references, and a key of the environment itself wins over an imported one with the same name',
  ],
  ['ключи кластера не разобрались: {}', 'the cluster keys could not be parsed: {0}'],
  ['заголовок токена не разобрался: {}', 'the token header could not be parsed: {0}'],
  ['токен не прошёл проверку: {}', 'the token failed verification: {0}'],
  [
    'имя "{}" сломает файл окружения на сервере: в имени ключа бывают только буквы, цифры, _, точка и дефис',
    'the name "{0}" would break the environment file on the server: a key name may only contain letters, digits, _, dots and hyphens',
  ],
  ['строка без «=»: {}', 'a line without "=": {0}'],
  ['пустое имя переменной: {}', 'an empty variable name: {0}'],
  ['незакрытая кавычка: {}', 'an unclosed quote: {0}'],
  ['имя «{}» не резолвится: {}', 'the name "{0}" does not resolve: {1}'],
  ['имя «{}» не резолвится', 'the name "{0}" does not resolve'],
  ['имя «{}» указывает на внутренний адрес {}', 'the name "{0}" points to an internal address {1}'],
  ['отметка не читается: {}', 'the mark cannot be read: {0}'],

  // журнал
  ['{}, повторных чтений с прошлой записи: {}', '{0}, repeated reads since the last entry: {1}'],
  ['ключей: {}', 'keys: {0}'],
  ['на {} мин', 'for {0} min'],
  ['{}/{}: list, read · до {}', '{0}/{1}: list, read · until {2}'],
  ['{}/{} · до {}', '{0}/{1} · until {2}'],
  ['{}/{}: срок {}', '{0}/{1}: expires {2}'],
  ['{}/{}: срок снят', '{0}/{1}: expiry removed'],
  ['личностей {}, прав снято {}', 'identities {0}, rights removed {1}'],
  ['из {}: создано {}, обновлено {}, пропущено {}', 'from {0}: created {1}, updated {2}, skipped {3}'],
  ['проектов {}, окружений {}, значений {}', 'projects {0}, environments {1}, values {2}'],
  ['из {}, ключей {}', 'from {0}, keys {1}'],
  ['окружений {}, пропущено {}', 'environments {0}, skipped {1}'],
  ['версия {} · взято из {}', 'version {0} · taken from {1}'],
  ['совпадений {}', 'matches {0}'],
  ['версия {} · как в {}', 'version {0} · same as in {1}'],
  ['создано {}, обновлено {}, пропущено {}', 'created {0}, updated {1}, skipped {2}'],
  ['возвращено {}, удалено {}', 'restored {0}, deleted {1}'],
  ['версия {}, автор {}: {}', 'version {0}, author {1}: {2}'],
  ['версия {}, автор {}', 'version {0}, author {1}'],
  ['версия {}', 'version {0}'],
  ['снимок «{}»', 'snapshot "{0}"'],
  [
    'В окружении есть папки, где у вас нет права "{}": действие над всем окружением недоступно',
    'The environment has folders where you lack the "{0}" right: an action on the whole environment is not available',
  ],
  ['в файле {} ключей - больше предела {}: разбейте его на части', 'the file has {0} keys, more than the limit of {1}: split it into parts'],
  [
    'папка "{}" не переживет выгрузку и обратную заливку: в пути не бывает пробелов, # и управляющих символов',
    'the folder "{0}" would not survive an export and import back: a path has no spaces, # or control characters',
  ],
  ['поколение {}, перешифровано версий: {}', 'generation {0}, versions re-encrypted: {1}'],
  ['к версии {}, стала версия {}', 'back to version {0}, now version {1}'],
  ['откат к версии {}, на подтверждении версия {}', 'rollback to version {0}, version {1} awaits approval'],
  ['подпись: {} · срок: {}', 'note: {0} · expires: {1}'],
  ['подпись: {} · срока нет', 'note: {0} · no expiry'],
  ['было {}:{} · вслед за {}', 'was {0}:{1} · following {2}'],
  ['было {}:{}', 'was {0}:{1}'],
  ['было {} · вслед за {}', 'was {0} · following {1}'],
  ['было {}', 'was {0}'],
  ['различий {}, совпало {}', 'differences {0}, matched {1}'],
  ['режим: {}, доли: {} из {}', 'mode: {0}, shares: {1} of {2}'],
  ['режим: {}', 'mode: {0}'],
  ['доля принята, нужно ещё {}', 'share accepted, {0} more needed'],
  ['долями: {} из {}', 'with shares: {0} of {1}'],
  ['поколение {} → {}, обёрток: {}', 'generation {0} -> {1}, wraps: {2}'],
  ['порог согласования: {} → {}', 'approval threshold: {0} -> {1}'],
  ['обязательные ключи: {} шт.', 'required keys: {0}'],
  ['давним считается старше: {} → {} дн.', 'stale after: {0} -> {1} days'],
  ['родитель: {} → {}', 'parent: {0} -> {1}'],
  ['роль: {} → {}', 'role: {0} -> {1}'],
  ['роль: {}', 'role: {0}'],
  ['адреса: {} → {}', 'addresses: {0} -> {1}'],
  ['срок: {} → {}', 'expires: {0} -> {1}'],
  // выдача права: "allow list,read все проекты/"
  ['{} {} все проекты{}', '{0} {1} all projects{2}'],
  [
    'Право "{}" здесь действует только со вторым фактором: включите его в меню своей учетной записи',
    'The "{0}" right works here only with two-factor authentication: turn it on in your account menu',
  ],
  // сервер или кластер забрали на себя; длинная заготовка раньше короткой
  ['забрал на себя у {}, личностей {}', 'took over from {0}, identities {1}'],
  ['забрал на себя у {}', 'took over from {0}'],
]

function escape(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

const COMPILED: [RegExp, string][] = TEMPLATES.map(([ru, en]) => [
  new RegExp('^' + ru.split('{}').map(escape).join('(.+?)') + '$', 's'),
  en,
])

// Обертки, которых нет одной строкой в коде: ошибка источника переноса, где
// за описанием идут код HTTP и начало ответа (importers._fail).
const WRAPPERS: [RegExp, string][] = [
  [/^(.+?): HTTP (\d+) — (.*)$/s, '{0}: HTTP {1}, {2}'],
  [/^(.+?): HTTP (\d+)$/s, '{0}: HTTP {1}'],
  // Размер логотипа. Регуляркой, а не заготовкой: заготовка с {} захватила бы
  // через "; " соседний пункт журнала целиком.
  [/^([^;]+), (\d+) байт$/s, '{0}, {1} bytes'],
]

function fill(en: string, parts: string[], depth: number): string {
  return en.replace(/\{(\d)\}/g, (_, i: string) => translate(parts[Number(i)] ?? '', depth + 1))
}

function translate(text: string, depth: number): string {
  if (depth > 3 || !text) return text
  const exact = EXACT[text]
  if (exact) return exact
  // Слова и фразы, которые интерфейс уже переводит сам (названия прав, ролей).
  const known = tr(text)
  if (known !== text) return known
  for (const [re, en] of [...COMPILED, ...WRAPPERS]) {
    const m = re.exec(text)
    if (m) return fill(en, m.slice(1), depth)
  }
  // Пункты журнала через "; ": каждый переводится сам по себе, сколько бы их
  // ни было.
  if (text.includes('; ')) {
    return text
      .split('; ')
      .map((part) => translate(part, depth + 1))
      .join('; ')
  }
  // "Что: подробность" - например, название канала и отказ проверки адреса.
  const at = text.indexOf(': ')
  if (at > 0) {
    const head = translate(text.slice(0, at), depth + 1)
    const tail = translate(text.slice(at + 2), depth + 1)
    if (head !== text.slice(0, at) || tail !== text.slice(at + 2)) return `${head}: ${tail}`
  }
  return text
}

// Комментарии версий, которые пишет сам сервер. Комментарий версии - это и
// текст человека, поэтому общий перевод с разбором на куски тут не годится:
// "роль: старый ключ" стал бы "role: старый ключ". Переводится только то, что
// целиком совпало с одной из этих строк.
const VERSION_COMMENTS: [RegExp, string][] = [
  [/^откат к версии (\d+)$/, 'rollback to version {0}'],
  [/^переименован из закрытой папки$/, 'renamed from a closed folder'],
  [/^переименован из (.+)$/, 'renamed from {0}'],
  [/^импорт \.env$/, 'import of .env'],
  [/^снимок «(.+)», версия (\d+)$/, 'snapshot "{0}", version {1}'],
  [/^снимок «(.+)»$/, 'snapshot "{0}"'],
  [/^снято переопределение$/, 'override removed'],
  [/^перенос из (.+)$/, 'migrated from {0}'],
  [/^копия из (.+)$/, 'copied from {0}'],
  [/^взято из (.+)$/, 'taken from {0}'],
  [/^как в (.+)$/, 'as in {0}'],
]

/** Комментарий версии на языке интерфейса: серверный переводится целиком,
 *  написанный человеком остается как есть. */
export function versionComment(text: string): string {
  if (currentLang() !== 'en' || !text) return text
  for (const [re, en] of VERSION_COMMENTS) {
    const m = re.exec(text)
    if (m) return en.replace(/\{(\d)\}/g, (_, i: string) => m[Number(i) + 1] ?? '')
  }
  return text
}

/** Текст сервера на языке интерфейса. */
export function serverText(text: string): string {
  if (currentLang() !== 'en') return text
  return translate(text, 0)
}
