package main

// Ответы машинного контура панели по-английски.
//
// Панель отвечает по-русски, а агент, который говорит по-английски,
// переводит известные ответы сам; незнакомый текст показывается как есть.
// ops/selfcheck.py сверяет таблицу с отказами в backend/app/api/machine.py и
// с ответами общих обработчиков ошибок (backend/app/main.py): новый отказ без
// перевода не пройдет CI.
var apiErrors = map[string]string{
	"Недействительный или отсутствующий токен":                                                                               "invalid or missing token",
	"Адрес не в белом списке личности":                                                                                       "the address is not on the identity's allow-list",
	"Слишком много попыток — повторите позже":                                                                                "too many attempts, try again later",
	"Неверная пара идентификатор и секрет":                                                                                   "wrong client id or secret",
	"Этой машине окружение не выдано":                                                                                        "this machine has not been granted the environment",
	"Проект с таким именем есть в нескольких группах — укажите group":                                                        "several groups have a project with this name: set the group",
	"Проект или окружение не найдено":                                                                                        "project or environment not found",
	"Ключ проекта этой машине не выдан: откройте проект в панели и выдайте ей ключ":                                          "the project key has not been granted to this machine: open the project in the panel and grant it",
	"У проекта шифрование в браузере: файл собирает агент из значений, полученных запросом /secrets":                         "the project is encrypted in the browser: the agent builds the file from the values of /secrets",
	"Токен подключения недействителен или уже использован":                                                                   "the enrollment token is invalid or already used",
	"Версия агента не подписана":                                                                                             "the agent release is not signed",
	"Нет сборки под эту архитектуру":                                                                                         "there is no build for this architecture",
	"Агент не собран в этом образе":                                                                                          "the agent is not built into this image",
	"Бинарь агента не совпадает с подписанным описанием":                                                                     "the agent binary does not match the signed release",
	"Скрипт не собран в этом образе":                                                                                         "the install script is not built into this image",
	"Панель заперта: чтобы читать значения, введите корневой ключ":                                                           "the panel is sealed: values are unavailable until the root key is entered",
	"Значение не сошлось с ключом — возможна правка базы в обход панели":                                                     "a value does not match its key: the database may have been changed bypassing the panel",
	"Такого объекта нет: номер вне допустимого диапазона":                                                                    "no such object: the number is out of range",
	"Значение длиннее, чем помещается в базу":                                                                                "the value is longer than the database can hold",
	"В запросе нулевой символ: такие строки база не хранит":                                                                  "the request has a NUL character: the database does not store such strings",
	"Такая запись уже есть: ее только что завели параллельно. Обновите страницу":                                             "this record already exists: a parallel request has just created it",
	"Окружение удалили, пока выполнялся запрос: обновите страницу":                                                           "the environment was deleted while the request was running",
	"Связанную запись удалили, пока выполнялся запрос: обновите страницу":                                                    "a related record was deleted while the request was running",
	"Запрос столкнулся с параллельным и отменен: повторите его":                                                              "the request collided with a parallel one and was cancelled: try again",
	"ключ переименовали или перенесли, пока выполнялся запрос: обновите страницу":                                            "the key was renamed or moved while the request was running",
	"У окружения нет действующего ключа шифрования: база повреждена или смена ключа оборвалась. Восстановите базу из бэкапа": "the environment has no active encryption key: the database is damaged or a key change broke off; restore the database from a backup",
	"Значение зашифровано ключом окружения, которого больше нет: его не открыть. Запишите этот ключ заново":                  "a value is encrypted with an environment key that no longer exists and cannot be opened: write this key again",
	"секрет удалён или не имеет версий":                                                                                      "the secret was deleted or has no versions",
	"такой версии нет или она была удалением":                                                                                "there is no such version, or it was a deletion",
	"у проекта шифрование в браузере: файл собирает тот, у кого есть ключ проекта, а не сервер":                              "the project is encrypted in the browser: the file is built by whoever has the project key, not by the server",
	"Пароль длиннее 72 байт: bcrypt учитывает только первые 72, а это 36 русских букв. Сократите его":                        "the password is longer than 72 bytes: bcrypt uses only the first 72. Shorten it",
}

// apiError - текст отказа панели на языке вывода.
func apiError(text string) string {
	if russian {
		return text
	}
	if en, ok := apiErrors[text]; ok {
		return en
	}
	return text
}
