// Агент Sekvyr: забирает секреты окружения и отдает их процессу или файлу.
//
// Один бинарь без зависимостей - только стандартная библиотека. На ноде он
// живет рядом с systemd-юнитом, читает свой конфиг и больше ничего не требует:
// у сервера, который поднимают в три часа ночи, не должно быть ни рантайма, ни
// пакетного менеджера в списке условий.
//
// Команды:
//
//	sekvyr enroll --url URL --token T   подключить сервер к панели
//	sekvyr render -o /run/app/env       записать .env файлом
//	sekvyr run -- ./app                 отдать секреты процессу через окружение
//	sekvyr agent                        следить за изменениями и применять их
//	sekvyr update                       обновиться до подписанной версии
//	sekvyr version                      версия агента
//
// Секреты не касаются диска, если не попросили обратного: `run` кладет их в
// окружение потомка, `render` пишет файл с правами 0400 (владелец - тот, от
// кого работает агент, обычно root).
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

// Version подставляется при сборке: -ldflags "-X main.Version=0.16.0".
var Version = "dev"

// PublicKey - публичная половина ключа, которым подписываются версии агента.
// Подставляется при сборке из agent/pubkey.txt. Закрытой половины на панели
// нет: она у того, кто выпускает версии. Поэтому панель может раздать любой
// бинарь, но нода поставит только подписанный.
var PublicKey = ""

const defaultConfig = "/etc/sekvyr/agent.json"

// Config - все, что агент знает о себе. Секрет здесь единственная тайна,
// поэтому файл создается с правами 0600 и проверяется при чтении.
type Config struct {
	URL          string `json:"url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Group        string `json:"group,omitempty"`
	// Старый формат: одно приложение прямо здесь. Пустые поля не пишем -
	// после переезда в список они только сбивают с толку того, кто откроет
	// конфиг.
	Project string `json:"project,omitempty"`
	Env     string `json:"env,omitempty"`
	// Путь к projected-токену ServiceAccount. Задан - значит секрета нет вовсе:
	// в поде доказательством служит подпись кластера, а не строка на диске.
	TokenFile string `json:"kubernetes_token_file,omitempty"`

	// Язык вывода агента (ru или en): его записывает установщик по языку
	// панели, откуда взяли команду. Пусто - по окружению, иначе английский.
	Lang string `json:"lang,omitempty"`

	// Приложения на этом сервере. Пусто - работает старый формат, где проект и
	// окружение заданы на верхнем уровне; такие конфиги остались на нодах,
	// подключенных раньше, и ломать их незачем.
	Apps []App `json:"apps,omitempty"`

	// Файл из флага службы -o, который уже отнесен к приложению (bindOut).
	// Привязка делается один раз: юниты старых нод держат -o всегда, и после
	// sekvyr rm или add -o флаг иначе прилипал бы к другому приложению.
	BoundOut string `json:"bound_out,omitempty"`

	// Откуда конфиг прочитан. Рядом с ним живет ключ ноды (см. e2e.go), и
	// путь нужно помнить, а не угадывать заново.
	path string
}

type value struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Value string `json:"value"`
}

type secretsResponse struct {
	Project     string  `json:"project"`
	Environment string  `json:"environment"`
	Values      []value `json:"values"`
	// Проект с шифрованием в браузере: значения запечатаны, а ключ к ним
	// приходит обернутым на ключ этой ноды (см. e2e.go).
	E2E        bool        `json:"e2e"`
	ProjectKey *projectKey `json:"project_key"`
}

func main() {
	peekConfigLang()
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "render":
		err = cmdRender(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "agent":
		err = cmdAgent(os.Args[2:])
	case "update":
		err = cmdUpdate(os.Args[2:])
	case "config":
		err = cmdConfig(os.Args[2:])
	case "add":
		err = cmdAdd(os.Args[2:])
	case "ls", "list":
		err = cmdList(os.Args[2:])
	case "rm", "remove":
		err = cmdRemove(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("sekvyr", Version)
	case "help", "--help", "-h":
		usage()
	default:
		err = fmt.Errorf(tr("неизвестная команда %q", "unknown command %q"), os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sekvyr:", err)
		os.Exit(1)
	}
}

func usage() {
	if !russian {
		fmt.Fprint(os.Stderr, `sekvyr - the Sekvyr secrets panel agent

  sekvyr enroll --url URL --token TOKEN   connect this server to the panel
  sekvyr render -o FILE [--mode 0400]     write the values as a .env file
  sekvyr run -- COMMAND [ARGS]            run a process with the secrets in its environment
  sekvyr agent [--interval 60s]           watch for changes and apply them
  sekvyr update [--check]                 update to a signed release
  sekvyr update --restart sekvyr-agent    update and restart the service
  sekvyr add project/environment          add an application to this server
  sekvyr ls                               which applications are served
  sekvyr rm project/environment           remove an application
  sekvyr config --project P --env E -o F  a separate config (a rare case)
  sekvyr version                          agent version

Default config: `+defaultConfig+`
Output language: SEKVYR_LANG=ru or en.
`)
		return
	}
	fmt.Fprint(os.Stderr, `sekvyr — агент панели секретов

  sekvyr enroll --url URL --token TOKEN   подключить сервер к панели
  sekvyr render -o FILE [--mode 0400]     записать значения файлом .env
  sekvyr run -- КОМАНДА [АРГУМЕНТЫ]       запустить процесс с секретами в окружении
  sekvyr agent [--interval 60s]           следить за изменениями и применять их
  sekvyr update [--check]                 обновиться до подписанной версии
  sekvyr update --restart sekvyr-agent    обновиться и перезапустить службу
  sekvyr add проект/окружение             добавить приложение этому серверу
  sekvyr ls                               какие приложения обслуживаются
  sekvyr rm проект/окружение              убрать приложение
  sekvyr config --project P --env E -o F  отдельный конфиг (редкий случай)
  sekvyr version                          версия агента

Конфиг по умолчанию: `+defaultConfig+`
Язык вывода: SEKVYR_LANG=ru или en.
`)
}

// --- работа с панелью ------------------------------------------------------

// configFromEnv - конфиг из окружения, без файла. В кластере так удобнее:
// адрес и окружение приходят из ConfigMap, а доказательство - из смонтированного
// projected-токена, который кладет сам kubernetes.
func configFromEnv() *Config {
	cfg := &Config{
		URL:       strings.TrimRight(os.Getenv("SEKVYR_URL"), "/"),
		Group:     os.Getenv("SEKVYR_GROUP"),
		Project:   os.Getenv("SEKVYR_PROJECT"),
		Env:       os.Getenv("SEKVYR_ENV"),
		TokenFile: os.Getenv("SEKVYR_TOKEN_FILE"),
	}
	if cfg.TokenFile == "" {
		const projected = "/var/run/secrets/sekvyr/token"
		if _, err := os.Stat(projected); err == nil {
			cfg.TokenFile = projected
		}
	}
	return cfg
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		// Файла нет - пробуем окружение: под в кластере живет именно так.
		cfg := configFromEnv()
		if cfg.URL != "" && cfg.TokenFile != "" && cfg.Project != "" && cfg.Env != "" {
			cfg.path = path
			return cfg, nil
		}
		return nil, fmt.Errorf(tr("конфиг %s: %w (сначала выполните enroll)", "config %s: %w (run enroll first)"), path, err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf(tr("конфиг %s не разобрался: %w", "config %s could not be parsed: %w"), path, err)
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf(tr("конфиг %s неполон", "config %s is incomplete"), path)
	}
	if cfg.TokenFile == "" && (cfg.ClientID == "" || cfg.ClientSecret == "") {
		return nil, fmt.Errorf(tr("конфиг %s неполон", "config %s is incomplete"), path)
	}
	cfg.path = path
	useConfigLang(cfg.Lang)
	return &cfg, nil
}

func saveConfig(path string, cfg *Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// Через временный файл рядом и переименование: запись поверх старого
	// файла, оборванная посередине (кончилось место во время add, сбой
	// питания), оставляла пустой конфиг, а вместе с ним пропадал и секрет
	// машины - нода после перезапуска была мертва. Временный файл создается
	// сразу с правами 0600: секрет не бывает читаем никому, даже на мгновение.
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func post(url string, body any, token string, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return do(req, out)
}

func get(url string, token string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return do(req, out)
}

// shortBody - чужой ответ одной строкой для журнала. Перед панелью стоят
// прокси, и пока она перезапускается, 502 приходит от nginx страницей HTML:
// в журнал службы легли бы шесть строк разметки. От такой страницы остается
// название кода, остальное сводится в строку и режется по буквам, а не по
// байтам, чтобы не разорвать русскую.
func shortBody(raw []byte, code int) string {
	text := strings.Join(strings.Fields(string(raw)), " ")
	if text == "" || strings.HasPrefix(text, "<") {
		return http.StatusText(code)
	}
	if r := []rune(text); len(r) > 300 {
		text = string(r[:300]) + "..."
	}
	return text
}

// panelError - отказ панели с кодом ответа. По коду fetchOrCache решает, можно
// ли подменить ответ копией значений: недоступная панель - да, отказ по
// существу - нет.
type panelError struct {
	code int
	text string
}

func (e *panelError) Error() string { return e.text }

// netError - панель не ответила вовсе: сеть, перезапуск, обрыв посреди ответа.
type netError struct{ err error }

func (e *netError) Error() string { return e.err.Error() }
func (e *netError) Unwrap() error { return e.err }

// maxBody - больше этого ответ панели не читается. Сотня ключей по 200 000
// символов - это 20 МБ, а прежний предел в 8 МБ молча обрезал такой ответ, и
// агент писал непонятное "unexpected end of JSON input".
const maxBody = 32 << 20

func do(req *http.Request, out any) error {
	req.Header.Set("User-Agent", "sekvyr-agent/"+Version)
	client := &http.Client{Timeout: 20 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return &netError{err}
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return &netError{err}
	}
	if len(raw) > maxBody {
		return fmt.Errorf(tr("ответ панели больше %d МБ: столько агент не читает",
			"the panel answer is larger than %d MB: the agent does not read that much"), maxBody>>20)
	}
	if res.StatusCode >= 400 {
		detail := ""
		// Панель отвечает {"detail": "..."}: показываем сам текст, а агенту,
		// который говорит по-английски, - его перевод, если он известен.
		var body struct {
			Detail any `json:"detail"`
		}
		if json.Unmarshal(raw, &body) == nil {
			if text, ok := body.Detail.(string); ok {
				detail = apiError(text)
			}
		}
		if detail == "" {
			detail = shortBody(raw, res.StatusCode)
		}
		return &panelError{
			code: res.StatusCode,
			text: fmt.Sprintf(tr("панель ответила %d: %s", "the panel answered %d: %s"), res.StatusCode, detail),
		}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// unreachable - можно ли заменить ответ панели копией. Копия нужна, когда
// панели нет: сеть, перезапуск, 502 от прокси, запертая после перезагрузки
// панель (503), перегрузка. Отказ по существу - доступ отозван, окружения нет,
// ответ не разобрался - копией не лечится: агент молча отдавал бы значения,
// которые ему уже не положены, а render выходил бы с кодом 0.
func unreachable(err error) bool {
	var gone *netError
	if errors.As(err, &gone) {
		return true
	}
	var refused *panelError
	if errors.As(err, &refused) {
		// 429 панель отдает на вход машины только после серии отказов этой
		// машине (отозвана, выключена, не с того адреса): копия значений ей не
		// положена так же, как при 403.
		return refused.code >= 500 || refused.code == http.StatusRequestTimeout
	}
	return false
}

func token(cfg *Config) (string, error) {
	var res struct {
		AccessToken string `json:"access_token"`
	}
	body := map[string]string{
		"client_id":     cfg.ClientID,
		"client_secret": cfg.ClientSecret,
	}
	if cfg.TokenFile != "" {
		// Токен читаем каждый раз: kubernetes перевыпускает projected-токен сам,
		// и прочитанный однажды через час окажется просроченным.
		raw, err := os.ReadFile(cfg.TokenFile)
		if err != nil {
			return "", fmt.Errorf(tr("токен ServiceAccount: %w", "ServiceAccount token: %w"), err)
		}
		body = map[string]string{"kubernetes_token": strings.TrimSpace(string(raw))}
	}
	if err := post(cfg.URL+"/api/v1/machine/token", body, "", &res); err != nil {
		return "", err
	}
	return res.AccessToken, nil
}

func fetch(cfg *Config) (*secretsResponse, error) {
	access, err := token(cfg)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/machine/secrets?project=%s&env=%s",
		cfg.URL, escape(cfg.Project), escape(cfg.Env))
	if cfg.Group != "" {
		url += "&group=" + escape(cfg.Group)
	}
	var res secretsResponse
	if err := get(url, access, &res); err != nil {
		return nil, err
	}
	// Значения e2e-проекта раскрываются здесь, на ноде: панель их такими
	// никогда не видела и увидеть не могла.
	fingerprint, err := openAll(cfg.path, &res)
	if err != nil {
		return nil, err
	}
	if err := checkE2E(cfg, fingerprint); err != nil {
		return nil, err
	}
	return &res, nil
}

func escape(s string) string {
	return strings.NewReplacer(" ", "%20", "&", "%26", "?", "%3F", "#", "%23").Replace(s)
}

// cmdConfig - второй (третий, десятый) конфиг на том же сервере.
//
// Одна машина в панели - одна личность, но приложений на сервере бывает
// несколько, и каждому нужно свое окружение. Личность при этом та же: заводить
// новую ради соседнего контейнера значит плодить сущности, которые потом никто
// не соотнесет с сервером.
//
// Почему командой агента, а не правкой JSON в установщике: конфиг должен
// собирать тот, кто знает его формат. Первая попытка сделать это через sed
// оставила в новом файле группу от старого проекта, и агент честно не нашел
// окружение.
func cmdConfig(args []string) error {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	from := fs.String("from", defaultConfig, tr("откуда взять личность", "where to take the identity from"))
	out := fs.String("o", "", tr("куда записать новый конфиг", "where to write the new config"))
	project := fs.String("project", "", tr("проект в панели", "project in the panel"))
	env := fs.String("env", "", tr("окружение проекта", "project environment"))
	group := fs.String("group", "", tr("группа проекта, если она есть", "project group, if it has one"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *project == "" || *env == "" {
		return errors.New(tr("нужны --project, --env и -o", "--project, --env and -o are required"))
	}
	if err := (App{Project: *project, Env: *env, Group: *group}).checkNames(); err != nil {
		return err
	}
	cfg, err := loadConfig(*from)
	if err != nil {
		return err
	}
	cfg.Project = *project
	cfg.Env = *env
	// Список приложений принадлежит исходному конфигу: во втором он означал бы
	// "то же самое обслуживают двое", и файл писали бы два агента наперегонки.
	cfg.Apps = nil
	// Группу перезаписываем всегда, в том числе пустым значением: она была от
	// прежнего проекта, и "оставить как есть" здесь означает искать чужое место.
	cfg.Group = *group
	if err := saveConfig(*out, cfg); err != nil {
		return err
	}
	fmt.Printf(tr("sekvyr: конфиг %s готов (%s/%s)\n", "sekvyr: config %s is ready (%s/%s)\n"), *out, *project, *env)
	return nil
}

// --- enroll ----------------------------------------------------------------

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	url := fs.String("url", "", tr("адрес панели", "panel address"))
	one := fs.String("token", "", tr("одноразовый токен подключения", "one-time enrollment token"))
	config := fs.String("config", defaultConfig, tr("куда положить конфиг", "where to put the config"))
	name := fs.String("name", "", tr("имя сервера в панели (по умолчанию hostname)", "server name in the panel (hostname by default)"))
	lang := fs.String("lang", "", tr("язык вывода агента: ru или en", "agent output language: ru or en"))
	force := fs.Bool("force", false, tr("переписать конфиг уже подключенного сервера", "overwrite the config of a server that is already connected"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *one == "" {
		return errors.New(tr("нужны --url и --token", "--url and --token are required"))
	}
	// Команду "новый сервер" берут из панели и для сервера, который уже
	// подключен. Новый конфиг заменил бы личность: старая осталась бы в панели
	// с правами, а приложения, добавленные через sekvyr add, пропали бы из
	// списка, и их файлы молча перестали бы обновляться. Проверка - до
	// обращения к панели, чтобы токен остался неиспользованным.
	if _, err := os.Stat(*config); err == nil && !*force {
		return fmt.Errorf(tr(
			"сервер уже подключен (конфиг %s): окружение ему выдается в панели на странице сервера, кнопкой \"Подключить приложение\". Подключить заново с новой личностью: --force",
			"this server is already connected (config %s): grant it an environment in the panel, on the server page, with \"Connect an application\". To connect again with a new identity: --force"), *config)
	}
	host := *name
	if host == "" {
		host, _ = os.Hostname()
	}

	var res struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Name         string `json:"name"`
		Project      string `json:"project"`
		Group        string `json:"group"`
		Env          string `json:"env"`
	}
	err := post(strings.TrimRight(*url, "/")+"/api/v1/machine/enroll", map[string]string{
		"token":         *one,
		"hostname":      host,
		"agent_version": Version,
	}, "", &res)
	if err != nil {
		return err
	}
	if res.Project != "" {
		if err := (App{Project: res.Project, Env: res.Env, Group: res.Group}).checkNames(); err != nil {
			return fmt.Errorf(tr("панель выдала окружение под чужим именем: %w", "the panel granted an environment with a foreign name: %w"), err)
		}
	}
	cfg := &Config{
		URL:          strings.TrimRight(*url, "/"),
		ClientID:     res.ClientID,
		ClientSecret: res.ClientSecret,
	}
	if *lang == "ru" || *lang == "en" {
		cfg.Lang = *lang
		useConfigLang(cfg.Lang)
	}
	// Выданное окружение - сразу приложение в списке, а не поля на верхнем
	// уровне: иначе конфиг новой ноды выглядит заполненным дважды (сверху и в
	// списке), и `sekvyr ls` показывает один проект двумя строками.
	if res.Project != "" {
		cfg.Apps = []App{App{Project: res.Project, Env: res.Env, Group: res.Group}.defaults()}
	}
	// Подключение заново (--force) меняет личность, но не список приложений:
	// иначе все, что добавляли через sekvyr add, пропадало бы, и их файлы
	// молча переставали бы обновляться.
	kept := 0
	if *force {
		if old, err := loadConfig(*config); err == nil {
			// Совпавшее с новой выдачей приложение остается со своими файлом,
			// командой и правами: умолчания выдачи молча переводили его в
			// /run/sekvyr и запускали compose, которого на ноде нет.
			granted := cfg.Apps
			cfg.Apps = nil
			for _, app := range old.Apps {
				cfg.Apps = append(cfg.Apps, app)
				same := false
				for _, mine := range granted {
					same = same || mine.same(app)
				}
				if !same {
					kept++
				}
			}
			for _, mine := range granted {
				present := false
				for _, app := range cfg.Apps {
					present = present || app.same(mine)
				}
				if present {
					continue
				}
				// Новое окружение того же проекта получило бы тот же файл по
				// умолчанию, что у сохраненного приложения: два окружения в
				// одном файле. Тогда - свой файл с именем окружения.
				taken := cfg.Apps
				if old.Project != "" {
					// Проект старого вида тоже пишет файл по умолчанию.
					legacy := App{Project: old.Project, Env: old.Env, Group: old.Group}
					if !legacy.same(mine) {
						taken = append(append([]App(nil), taken...), legacy)
					}
				}
				for _, app := range taken {
					if app.withFile().Out == mine.Out {
						mine.Out = runDir + "/" + mine.Project + "-" + mine.Env + ".env"
						fmt.Printf(tr("файл по умолчанию уже занят, новое окружение пишет %s\n",
							"the default file is taken, the new environment writes %s\n"), mine.Out)
						break
					}
				}
				cfg.Apps = append([]App{mine}, cfg.Apps...)
			}
			// Проект старого вида (на верхнем уровне, путь знает только флаг
			// службы) остается там же: его перенесет normalize при старте
			// службы, с настоящим путем.
			if old.Project != "" {
				cfg.Project, cfg.Env, cfg.Group = old.Project, old.Env, old.Group
				legacy := App{Project: old.Project, Env: old.Env, Group: old.Group}
				same := false
				for _, mine := range granted {
					same = same || mine.same(legacy)
				}
				if !same {
					kept++
				}
			}
			if cfg.Lang == "" {
				cfg.Lang = old.Lang
			}
			cfg.BoundOut = old.BoundOut
		}
	}
	if err := saveConfig(*config, cfg); err != nil {
		return err
	}
	if kept > 0 {
		fmt.Printf(tr("приложения прежней личности сохранены (%d): выдайте их окружения новой машине в панели\n",
			"the applications of the previous identity were kept (%d): grant their environments to the new machine in the panel\n"), kept)
	}
	fmt.Printf(tr("сервер подключён как %q\n", "server connected as %q\n"), res.Name)
	if res.Project != "" {
		fmt.Printf(tr("выдано окружение: %s\n", "granted environment: %s\n"), App{Project: res.Project, Env: res.Env, Group: res.Group}.name())
	} else {
		fmt.Println(tr("окружение еще не выдано: в панели на странице сервера нажмите \"Подключить приложение\", она выдаст доступ и покажет команду",
			"no environment granted yet: press \"Connect an application\" on the server page in the panel, it grants access and shows the command"))
	}
	fmt.Println(tr("конфиг:", "config:"), *config)
	return nil
}

// --- render ----------------------------------------------------------------

// badName - имя ключа, которое сломает файл окружения: пробел docker compose
// не принимает вовсе и не поднимает приложение, знак = отрезал бы имя,
// перенос строки разорвал бы файл, а # в начале сделал бы строку
// комментарием. Панель такие имена больше не заводит, но старые данные могли
// остаться, и один такой ключ не должен ломать весь файл.
func badName(name string) bool {
	if name == "" || strings.HasPrefix(name, "#") {
		return true
	}
	for _, r := range name {
		if r == '=' || unicode.IsSpace(r) || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// fileBadName - имя, которое не прочтет docker compose. Кроме badName, это
// все, что не буква, цифра, _, точка, дефис и квадратные скобки: на таком
// символе (/, @, $, кавычки) compose не разбирает env_file целиком, и не
// поднимается приложение, а двоеточие считает разделителем и молча режет имя
// (из a:b выходит a со значением "b=..."). Панель такие имена больше не
// заводит, но они могли остаться от переноса из Vault (smtp/host).
func fileBadName(name string) bool {
	if badName(name) {
		return true
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || strings.ContainsRune("_.-[]", r) {
			continue
		}
		return true
	}
	return false
}

// renderEnv - файл окружения и имена, которые пришлось пропустить.
// effective - значения в порядке файла, по одному на имя. Папки в файле
// окружения нет, и HOST из / и HOST из /db дали бы две строки: compose и
// systemd берут последнюю, а getenv в run - первую, и разные потребители
// получали бы разное. Теперь везде действует последняя по порядку папок, а
// о совпадении агент говорит.
func effective(values []value) ([]value, []string) {
	sorted := append([]value(nil), values...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Path != sorted[j].Path {
			return sorted[i].Path < sorted[j].Path
		}
		return sorted[i].Name < sorted[j].Name
	})
	last := map[string]int{}
	for i, v := range sorted {
		last[v.Name] = i
	}
	out := make([]value, 0, len(sorted))
	var shadowed []string
	for i, v := range sorted {
		if last[v.Name] != i {
			shadowed = append(shadowed, v.Path+"/"+v.Name)
			continue
		}
		out = append(out, v)
	}
	return out, shadowed
}

func renderEnv(values []value) (string, []string) {
	values, shadowed := effective(values)
	for _, name := range shadowed {
		fmt.Fprintf(os.Stderr, tr("sekvyr: ключ %s перекрыт одноименным из другой папки: в файле окружения папок нет\n",
			"sekvyr: key %s is shadowed by a key with the same name in another folder: an environment file has no folders\n"), name)
	}
	var b strings.Builder
	var skipped []string
	for _, v := range values {
		if fileBadName(v.Name) {
			skipped = append(skipped, v.Name)
			continue
		}
		b.WriteString(v.Name)
		b.WriteString("=")
		b.WriteString(quote(v.Value))
		b.WriteString("\n")
	}
	return b.String(), skipped
}

// warnSkipped говорит о пропущенных ключах. Зовется только при записи файла,
// а не на каждом круге: иначе журнал службы заполнили бы одни повторы.
func warnSkipped(app string, names []string) {
	for _, name := range names {
		fmt.Fprintf(os.Stderr, tr("sekvyr: %s: ключ %q пропущен - такое имя сломало бы файл; переименуйте его в панели\n",
			"sekvyr: %s: key %q skipped, such a name would break the file; rename it in the panel\n"), app, name)
	}
}

// quote повторяет правила панели (secrets_store._quote в бэкенде): файл
// читают docker compose (env_file) и systemd (EnvironmentFile), и значение
// должно дойти до приложения ровно таким, каким его задали.
//
//   - Без кавычек пишется только то, что везде читается одинаково: латиница,
//     цифры и _-.,:/@%+=. Остальное в shell значило бы что-то свое, а
//     "a;rm -rf /" без кавычек при source выполнился бы.
//   - Все прочее - в одинарных кавычках. Внутри них compose не подставляет
//     переменные и не трогает обратные слеши, shell тоже. Двойные так не
//     умеют: из "P@ss$word1" compose подставит пустую $word1, и приложение
//     получит P@ss.
//   - Одинарные не годятся, если в значении есть апостроф, возврат каретки
//     или оно кончается обратным слешем: compose примет \' за экранированную
//     кавычку и не найдет конец значения. Тогда двойные кавычки с
//     экранированием \, ", $ и \r. Обратный апостроф не экранируем: compose
//     оставил бы \` как есть (проверено вживую вместе с systemd и sh). Shell
//     же выполнил бы его, поэтому подключать файл через source нельзя, и
//     docs/app-docker говорит это прямо: значение с апострофом и обратным
//     апострофом одинаково для compose и shell не записать вовсе.
//
// Переносы строк остаются переносами: конфиг должен читаться и в файле на ноде.
func quote(v string) string {
	if v == "" {
		return `""`
	}
	if bareSafe(v) {
		return v
	}
	if !strings.ContainsAny(v, "'\r") && !strings.HasSuffix(v, `\`) {
		return "'" + v + "'"
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "\r", `\r`)
	return `"` + r.Replace(v) + `"`
}

// bareSafe - можно ли записать значение без кавычек.
func bareSafe(v string) bool {
	for _, c := range v {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune("_-.,:/@%+=", c):
		default:
			return false
		}
	}
	return true
}

func cmdRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	config := fs.String("config", defaultConfig, tr("конфиг агента", "agent config"))
	out := fs.String("o", "", tr("куда писать (по умолчанию на стандартный вывод)", "where to write (standard output by default)"))
	modeText := fs.String("mode", "0400", tr("права файла, восьмеричные", "file mode, octal"))
	app := fs.String("app", "", tr("какое приложение, если их несколько", "which application, if there are several"))
	noCache := fs.Bool("no-cache", false, tr("не хранить копию значений на диске", "do not keep a copy of the values on disk"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	mode, err := parseMode(*modeText)
	if err != nil {
		return err
	}
	loaded, err := loadConfig(*config)
	if err != nil {
		return err
	}
	cfg, err := pick(loaded, *app)
	if err != nil {
		return err
	}
	shared := sharedKeyPresent()
	res, err := fetchOrCache(cfg, !*noCache)
	if err != nil {
		reportSharedKey(cfg, shared)
		return err
	}
	text, skipped := renderEnv(res.Values)
	warnSkipped("render", skipped)
	if *out == "" {
		fmt.Print(text)
		return nil
	}
	return writeFile(*out, text, mode)
}

func writeFile(path, text string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sweepTemps(dir, filepath.Base(path))
	// Пишем во временный файл рядом и переименовываем: сервис, читающий файл в
	// этот момент, не должен увидеть половину. Имя временного файла случайное, и
	// создается он только новым (O_EXCL): в общем каталоге вроде /tmp ссылка,
	// заранее подложенная под предсказуемое имя, увела бы запись root куда угодно.
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	done := false
	defer func() {
		if !done {
			_ = os.Remove(tmp)
		}
	}()
	// Права ставим до содержимого и по дескриптору: значения ни мгновения не
	// лежат шире, чем просили.
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	// Данные - на диск до переименования: на XFS после сбоя питания
	// переименование успевало в журнал раньше данных, и на месте файла
	// оставался пустой (на ext4 это прикрывает auto_da_alloc).
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(dir)
	done = true
	return nil
}

// syncDir закрепляет на диске само переименование.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// staleTemp - сколько временному файлу жить, чтобы считаться брошенным: более
// свежий может быть записью, которая идет прямо сейчас (render рядом с агентом).
const staleTemp = 10 * time.Minute

// sweepTemps убирает временные файлы, брошенные оборванной записью (kill -9,
// OOM, сбой питания). В них значения, и вне tmpfs они лежали бы вечно.
func sweepTemps(dir, base string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := "." + base + "."
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".tmp") || !entry.Type().IsRegular() {
			continue
		}
		// Середину os.CreateTemp делает из одних цифр: .env.local.tmp
		// человека рядом с файлом .env - не наш.
		middle := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".tmp")
		if middle == "" || strings.Trim(middle, "0123456789") != "" {
			continue
		}
		if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) > staleTemp {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

// --- run -------------------------------------------------------------------

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	config := fs.String("config", defaultConfig, tr("конфиг агента", "agent config"))
	app := fs.String("app", "", tr("какое приложение, если их несколько", "which application, if there are several"))
	noCache := fs.Bool("no-cache", false, tr("не хранить копию значений на диске", "do not keep a copy of the values on disk"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New(tr("нечего запускать: sekvyr run -- ./app", "nothing to run: sekvyr run -- ./app"))
	}
	loaded, err := loadConfig(*config)
	if err != nil {
		return err
	}
	cfg, err := pick(loaded, *app)
	if err != nil {
		return err
	}
	shared := sharedKeyPresent()
	res, err := fetchOrCache(cfg, !*noCache)
	if err != nil {
		reportSharedKey(cfg, shared)
		return err
	}
	env, err := withValues(os.Environ(), res.Values)
	if err != nil {
		return err
	}
	binary, err := exec.LookPath(rest[0])
	if err != nil {
		return err
	}
	// Заменяем собой процесс: секреты остаются в его окружении и не проходят
	// через диск, а сигналы и код возврата достаются сервису напрямую.
	err = syscall.Exec(binary, rest, env)
	if errors.Is(err, syscall.E2BIG) {
		return fmt.Errorf(tr(
			"значения в сумме не помещаются в окружение процесса (%v): положите их в файл через sekvyr render",
			"the values together do not fit into the process environment (%v): put them into a file with sekvyr render"), err)
	}
	return err
}

// maxEnvString - предел ядра на одну строку окружения (MAX_ARG_STRLEN, 32
// страницы). Длиннее execve не примет и упадет с невнятным "argument list too
// long", а панель пускает значения до 200 000 символов.
const maxEnvString = 128 << 10

// withValues - окружение процесса со значениями из панели. Одноименная
// переменная родителя убирается: getenv в glibc, Go и Node берет первую копию,
// и ENV DATABASE_URL из образа или Environment= юнита молча перекрывали секрет.
func withValues(parent []string, values []value) ([]string, error) {
	values, _ = effective(values)
	ours := map[string]bool{}
	for _, v := range values {
		if !badName(v.Name) {
			ours[v.Name] = true
		}
	}
	env := make([]string, 0, len(parent)+len(values))
	for _, kv := range parent {
		name, _, _ := strings.Cut(kv, "=")
		if !ours[name] {
			env = append(env, kv)
		}
	}
	for _, v := range values {
		if badName(v.Name) {
			warnSkipped("run", []string{v.Name})
			continue
		}
		line := v.Name + "=" + v.Value
		// Строка окружения кончается нулевым символом, и execve отвечал бы
		// "invalid argument" без имени ключа. Панель такое значение принять
		// может: значение e2e-проекта запечатывает браузер.
		if strings.ContainsRune(v.Value, 0) {
			return nil, fmt.Errorf(tr(
				"%s: в значении нулевой символ, в переменную окружения его не передать: положите значение в файл через sekvyr render",
				"%s: the value contains a NUL character and cannot go into an environment variable: put it into a file with sekvyr render"), v.Name)
		}
		if len(line) >= maxEnvString {
			return nil, fmt.Errorf(tr(
				"%s длиннее 128 КиБ и не поместится в переменную окружения: положите его в файл через sekvyr render",
				"%s is longer than 128 KiB and will not fit into an environment variable: put it into a file with sekvyr render"), v.Name)
		}
		env = append(env, line)
	}
	return env, nil
}

// --- agent -----------------------------------------------------------------

func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	config := fs.String("config", defaultConfig, tr("конфиг агента", "agent config"))
	out := fs.String("o", "", tr("файл, который поддерживать в актуальном виде", "file to keep up to date"))
	modeText := fs.String("mode", "0400", tr("права файла, восьмеричные", "file mode, octal"))
	interval := fs.Duration("interval", time.Minute, tr("как часто спрашивать панель", "how often to ask the panel"))
	onChange := fs.String("on-change", "", tr("что выполнить после изменения", "command to run after a change"))
	updateEvery := fs.Duration("update-interval", 6*time.Hour, tr("как часто искать новую версию агента", "how often to look for a new agent release"))
	noUpdate := fs.Bool("no-update", false, tr("не обновлять себя", "do not update itself"))
	noCache := fs.Bool("no-cache", false, tr("не хранить копию значений на диске", "do not keep a copy of the values on disk"))
	// Флаг юнитов прежних версий: после обновления агент теперь перезапускает
	// себя сам (reexec), но старый ExecStart с ним должен по-прежнему читаться.
	_ = fs.String("restart-unit", "sekvyr-agent", tr("что перезапустить после обновления", "unit to restart after an update"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	mode, err := parseMode(*modeText)
	if err != nil {
		return err
	}
	base, err := loadConfig(*config)
	if err != nil {
		return err
	}
	// Флаги -o и --on-change остаются: так агент ставили раньше, и обновление
	// не должно ломать работающие ноды. Приложение из них живет рядом со
	// списком, а не вместо него: иначе `sekvyr add` на такой ноде ничего бы не
	// дал, а это и есть главный сценарий.
	//
	// Только пока проект указан на верхнем уровне конфига. После переноса в
	// список (normalize ниже) верхний уровень пуст, и раньше со следующего же
	// старта флаги давали приложение без проекта: оно получало от панели 422,
	// а настоящее приложение с тем же файлом пропускалось как "файл уже
	// пишет". Файл переставал обновляться после первого перезапуска.
	var legacyApp *App
	// Приложение, которому флаг -o достался только в памяти (конфиг только для
	// чтения): каждый круг ему возвращаются файл и команда из флагов, а другим
	// приложениям - нет.
	var memBound *App
	if *out != "" && base.Project != "" {
		app := App{
			Project: base.Project, Env: base.Env, Group: base.Group,
			Out: *out, OnChange: *onChange, Mode: fmt.Sprintf("%o", mode),
		}
		legacyApp = &app
	}
	// Один раз приводим конфиг к нынешнему виду: проект с верхнего уровня
	// переезжает в список с тем путем, по которому файл уже пишется. Пока этого
	// не сделано, `sekvyr ls` показывает не тот файл, а `sekvyr add` того же
	// проекта заводит вторую запись - так и вышло на первой живой ноде.
	// Конфига может не быть вовсе: в кластере агент берет личность из окружения
	// (см. loadConfig). Писать туда файл незачем - переносить нечего.
	if _, err := os.Stat(*config); err == nil && base.Project != "" {
		if err := normalize(*config, base, legacyApp); err != nil {
			fmt.Fprintln(os.Stderr, tr("sekvyr: конфиг не переписан:", "sekvyr: the config was not rewritten:"), err)
		} else if fresh, err := loadConfig(*config); err == nil {
			base = fresh
			// Приложение уже в списке, и дальше его ведет конфиг: иначе после
			// sekvyr rm этот процесс продолжал бы писать удаленный файл.
			legacyApp = nil
		}
	} else if err == nil && *out != "" {
		if err := bindOut(*config, base, *out, *onChange, fmt.Sprintf("%o", mode)); err != nil {
			fmt.Fprintln(os.Stderr, "sekvyr:", err)
			// Конфиг только для чтения (Secret, том :ro): сохранить привязку
			// нельзя, но держать ее можно в памяти. Иначе конфиг, перечитанный
			// на следующем круге, терял -o, и файл писался не туда, куда просили.
			if _, again := bindApps(base, *out, *onChange, fmt.Sprintf("%o", mode)); again == nil {
				for _, app := range base.Apps {
					if app.Out == *out {
						bound := app
						memBound = &bound
					}
				}
			}
		} else if fresh, err := loadConfig(*config); err == nil {
			base = fresh
		}
	}

	// Остановка службы не ждет конца круга: зависшая команда после изменения
	// снимается сразу, а не через полчаса, когда systemd уже добил бы агента.
	ctx, stopped := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopped()

	// Файлы, команда после изменения которых не прошла. Она повторяется каждый
	// круг, пока не пройдет, даже если значения больше не менялись: иначе
	// разовый сбой docker оставлял приложение на старых значениях до следующей
	// правки, а панель при этом видела свежий файл.
	failedHook := map[string]bool{}
	// Пауза перед повтором: минута, потом вдвое больше, но не реже раза в час.
	// Без нее падающая команда запускалась каждую минуту вечно, а зависающая
	// занимала каждый круг на полчаса, и остальные приложения ждали.
	hookDelay := map[string]time.Duration{}
	hookNext := map[string]time.Time{}
	// Для какой команды набрана пауза: исправленную команду (add --on-change)
	// незачем ждать до часа, она пробуется сразу.
	hookCmd := map[string]string{}

	lastUpdateCheck := time.Now()
	for {
		// Конфиг перечитываем каждый круг: `sekvyr add` дописывает приложение
		// и ничего не перезапускает - значения просто приезжают следующей
		// минутой. Перезапуск службы ради новой строки в списке был бы лишним
		// шагом ровно там, где мы их убираем.
		cfg := base
		if fresh, err := loadConfig(*config); err == nil {
			if memBound != nil {
				for i, app := range fresh.Apps {
					if app.same(*memBound) && app.defaults().Out == (App{Project: app.Project}).defaults().Out {
						fresh.Apps[i].Out, fresh.Apps[i].OnChange, fresh.Apps[i].Mode = memBound.Out, memBound.OnChange, memBound.Mode
					}
				}
			}
			cfg = fresh
		} else {
			fmt.Fprintln(os.Stderr, tr("sekvyr: конфиг не перечитался:", "sekvyr: could not re-read the config:"), err)
		}
		var list []App
		if legacyApp != nil {
			list = append(list, *legacyApp)
		} else if app, ok := cfg.legacy(""); ok {
			list = append(list, app)
		}
		for _, app := range cfg.apps() {
			// Приложение, описанное флагами службы, главнее одноименного из
			// списка: файл у него уже открыт работающим сервисом.
			if len(list) > 0 && list[0].same(app) {
				continue
			}
			list = append(list, app)
		}
		// Конфиг правят и руками, а `add` проверяет общий файл только у
		// себя. Пропущенное приложение называется каждый круг, как и любая
		// другая ошибка: молчание здесь выглядело бы как работа.
		list, clashes := splitShared(list)
		for _, clash := range clashes {
			fmt.Fprintln(os.Stderr, clash)
		}
		if len(list) == 0 {
			fmt.Fprintln(os.Stderr, tr("sekvyr: приложений нет — sekvyr add проект/окружение", "sekvyr: no applications yet: sekvyr add project/environment"))
		}
		for _, app := range list {
			if ctx.Err() != nil {
				return nil
			}
			appCfg := cfg.forApp(app)
			if *noCache {
				// "Без копии на диске" - и без той, что осталась с тех пор,
				// когда копия была включена. Только у службы: разовый render
				// --no-cache стирал бы копию, на которую служба рассчитывает.
				removeCache(appCfg)
			}
			res, err := fetchOrCache(appCfg, !*noCache)
			if err != nil {
				// Ни панели, ни копии - оставляем файл как есть. Сервис
				// переживает перезагрузку панели, а не падает вместе с ней.
				fmt.Fprintf(os.Stderr, tr("sekvyr: %s: не получилось забрать значения: %v\n", "sekvyr: %s: could not fetch the values: %v\n"), app.name(), err)
				// Ключ ноды панель узнает только из отчета. Для e2e-проекта,
				// которому ключ еще не выдан, значения не приходят никогда, и
				// без этого отчета выдать ключ было бы нельзя вовсе.
				reportKey(appCfg)
				continue
			}
			text, skipped := renderEnv(res.Values)
			// Сравниваем с тем, что лежит на диске, а не с тем, что агент писал
			// в прошлый раз: файл могли удалить (`sekvyr rm` и снова `add`,
			// уборка /run, руки человека), и агент обязан его вернуть. Память о
			// прошлом значении такую пропажу как раз скрывала - проверено на
			// живой ноде: файла нет, а агент считает, что все на месте.
			// Пустой файл и отсутствующий - не одно и то же: окружение без
			// ключей должно дать файл, иначе compose не найдет env_file.
			was, readErr := os.ReadFile(app.Out)
			marker := hookMarker(appCfg)
			if hookCmd[app.Out] != app.OnChange {
				delete(hookDelay, app.Out)
				delete(hookNext, app.Out)
				hookCmd[app.Out] = app.OnChange
			}
			hook := (failedHook[app.Out] || exists(marker)) && !time.Now().Before(hookNext[app.Out])
			written := true
			if readErr != nil || text != string(was) {
				if err := writeFile(app.Out, text, app.fileMode()); err != nil {
					fmt.Fprintf(os.Stderr, tr("sekvyr: %s: файл не записан: %v\n", "sekvyr: %s: the file was not written: %v\n"), app.name(), err)
					written = false
				} else {
					fmt.Printf(tr("sekvyr: %s — значения обновлены (%s)\n", "sekvyr: %s: values updated (%s)\n"), app.name(), keysCount(len(res.Values)-len(skipped)))
					warnSkipped(app.name(), skipped)
					hook = true
				}
			}
			if hook && app.OnChange != "" && written {
				// Отметка - до запуска: агента могут убить посреди команды
				// (OOM, kill -9), и тогда о несделанной команде помнит только
				// она.
				_ = os.WriteFile(marker, nil, 0o600)
				if runHook(ctx, app.OnChange) {
					delete(failedHook, app.Out)
					delete(hookDelay, app.Out)
					delete(hookNext, app.Out)
					_ = os.Remove(marker)
				} else {
					// Отметка на диске: перезапуск агента посреди упавшей или
					// прерванной команды (повторный запуск установщика,
					// остановка службы) не должен терять повтор, раз файл уже
					// свежий.
					_ = os.WriteFile(marker, nil, 0o600)
					if ctx.Err() == nil {
						failedHook[app.Out] = true
						delay := hookDelay[app.Out] * 2
						if delay < time.Minute {
							delay = time.Minute
						}
						if delay > time.Hour {
							delay = time.Hour
						}
						hookDelay[app.Out] = delay
						hookNext[app.Out] = time.Now().Add(delay)
					}
				}
			} else if app.OnChange == "" {
				delete(failedHook, app.Out)
				_ = os.Remove(marker)
			}
			if written {
				report(appCfg, res, app.Out)
			} else {
				// Файл не записан: зеленая точка и свежее время на странице
				// окружения были бы неправдой. Панель узнает только, что агент
				// жив.
				reportKey(appCfg)
			}
		}

		// Обновление ищем редко и молча: новая версия агента - событие раз в
		// месяц, а лишний запрос каждую минуту с сотни нод панели ни к чему.
		if !*noUpdate && time.Since(lastUpdateCheck) >= *updateEvery {
			lastUpdateCheck = time.Now()
			if m, err := fetchManifest(cfg); err != nil {
				fmt.Fprintln(os.Stderr, tr("sekvyr: проверка обновления:", "sekvyr: update check:"), err)
			} else if newer(m.Version, Version) {
				// Именно "новее", а не "другая": сам агент назад не ходит
				// никогда - старую версию ставит только человек руками.
				if err := applyUpdate(cfg, m); err != nil {
					fmt.Fprintln(os.Stderr, tr("sekvyr: обновление не поставлено:", "sekvyr: the update was not installed:"), err)
				} else {
					fmt.Printf(tr("sekvyr: обновлён до %s, перезапускаюсь\n", "sekvyr: updated to %s, restarting\n"), m.Version)
					if ctx.Err() != nil {
						// Службу останавливают: новый бинарь возьмет следующий запуск.
						return nil
					}
					// Новый бинарь встает на место процесса сам, под чем бы
					// агент ни работал. Выход с кодом 0 и перезапуск через
					// systemctl годились только для собственной службы:
					// supervisord и контейнер без restart после него агента не
					// поднимали, а признак "я служба" (INVOCATION_ID) достается
					// и детям чужой службы. Не вышло - выход с ошибкой, чтобы
					// systemd или политика on-failure подняли агента заново.
					return reexec()
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*interval):
		}
	}
}

// reexec заменяет процесс новым бинарем с теми же аргументами и окружением.
func reexec() error {
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err == nil {
		err = syscall.Exec(self, os.Args, os.Environ())
	}
	return fmt.Errorf(tr("новая версия поставлена, но не запустилась: %v", "the new version is installed but did not start: %v"), err)
}

// hookTimeout - сколько ждать команду после изменения. Цикл агента ждет ее
// целиком, и зависшая команда (docker, который не отвечает) иначе остановила
// бы на этой ноде и доставку значений, и самообновление.
var hookTimeout = 30 * time.Minute

// runHook выполняет команду после изменения и говорит, прошла ли она.
func runHook(ctx context.Context, command string) bool {
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Своя группа процессов: по истечении времени снимаем и sh, и все, что он
	// запустил, а не только сам sh.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, tr("sekvyr: команда после изменения не выполнилась:", "sekvyr: the command after the change failed:"), err)
		return false
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			fmt.Fprintln(os.Stderr, tr("sekvyr: команда после изменения не выполнилась:", "sekvyr: the command after the change failed:"), err)
			return false
		}
		return true
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return false
	case <-time.After(hookTimeout):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		fmt.Fprintf(os.Stderr, tr("sekvyr: команда после изменения не уложилась в %s и остановлена\n",
			"sekvyr: the command after the change did not finish in %s and was stopped\n"), hookTimeout)
		return false
	}
}

// osName - название системы из /etc/os-release: "Ubuntu 24.04.2 LTS". Панель
// показывает его в списке серверов; по соединению такое не узнать.
func osName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

// localIP - адрес, которым сервер дотягивается до панели. UDP-Dial не шлет ни
// одного пакета, но ядро выбирает исходящий интерфейс по таблице маршрутизации
// - то есть отвечает ровно на вопрос "под каким адресом меня видно в своей
// сети". Перебирать интерфейсы бессмысленно: их бывает десяток, и какой из них
// "тот самый", знает только маршрутизация.
func localIP(panelURL string) string {
	host := panelURL
	if u, err := url.Parse(panelURL); err == nil && u.Host != "" {
		host = u.Hostname()
		if u.Port() != "" {
			host = net.JoinHostPort(host, u.Port())
		} else if u.Scheme == "http" {
			host = net.JoinHostPort(host, "80")
		} else {
			host = net.JoinHostPort(host, "443")
		}
	}
	c, err := net.Dial("udp", host)
	if err != nil {
		return ""
	}
	defer c.Close()
	if addr, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// report рассказывает панели о себе: версия агента и что применено. По этому в
// панели видно, доехала ли правка до сервера, а не только то, что она сохранена.
func report(cfg *Config, res *secretsResponse, out string) {
	access, err := token(cfg)
	if err != nil {
		return
	}
	// Итог для панели - данные, а не вывод для человека: пишем без привязки к
	// языку агента, иначе в журнале английской панели появлялся бы русский.
	applied := fmt.Sprintf("keys %d", len(res.Values))
	// Публичный ключ ноды: по нему человек в браузере запечатывает ключ
	// e2e-проекта. Секретом он не является, поэтому едет обычным отчетом.
	pub, err := nodePublicKey(cfg.path)
	if err != nil {
		pub = ""
	}
	// Про какое приложение отчет и куда приезжают значения. Панель показывает
	// это на странице окружения: сервер, файл, время. Иначе там видно только
	// имя сервера, а какое из его приложений читает эти переменные - нет.
	_ = post(cfg.URL+"/api/v1/machine/report", map[string]string{
		"agent_version": Version,
		"applied":       applied,
		"public_key":    pub,
		"project":       res.Project,
		"env":           res.Environment,
		"group":         cfg.Group,
		"path":          out,
		// Система и адрес во внутренней сети: секретом не являются, а в панели
		// отвечают на вопрос "куда я сейчас зайду и что там за машина".
		"os":       osName(),
		"local_ip": localIP(cfg.URL),
	}, access, nil)
}

// reportKey - отчет без приложения: агент жив, вот его версия и ключ ноды.
// Нужен там, где значений нет (e2e-проект без выданного ключа, отказ панели,
// файл не записан): о приложении панель в этот раз не узнает ничего.
func reportKey(cfg *Config) {
	access, err := token(cfg)
	if err != nil {
		return
	}
	pub, err := nodePublicKey(cfg.path)
	if err != nil {
		pub = ""
	}
	_ = post(cfg.URL+"/api/v1/machine/report", map[string]string{
		"agent_version": Version,
		"public_key":    pub,
		"os":            osName(),
		"local_ip":      localIP(cfg.URL),
	}, access, nil)
}

// reportSharedKey - ключ ноды из render и run, только когда он задан явно
// (SEKVYR_NODE_KEY): так делают в Kubernetes, где у подов одной личности
// общий ключ, а первым идет init-контейнер render. Без отчета оттуда ключ
// e2e-проекта нельзя было выдать никогда: render падал без значений, а
// сайдкар, который шлет ключ в своем цикле, без init не стартовал. Ключ из
// случайного каталога состояния (sekvyr run в контейнере с чужим agent.json)
// не шлем: получив другой ключ, панель снимала бы все обертки машины.
//
// Лежал ли ключ, решается до получения значений (sharedKeyPresent): само
// получение может его завести (раскрытие e2e-обертки, копия значений), и
// проверка после него отправила бы только что созданный ключ.
func reportSharedKey(cfg *Config, present bool) {
	if present {
		reportKey(cfg)
	}
}

// sharedKeyPresent - общий ключ задан и уже лежит по своему пути. Переменная,
// указывающая не туда, куда у службы, - ошибка настройки: ключ по ней агент
// не шлет, пока его там нет.
func sharedKeyPresent() bool {
	path := os.Getenv("SEKVYR_NODE_KEY")
	return path != "" && exists(path)
}

// hookMarker - отметка о команде после изменения, которая не прошла. Лежит
// рядом с копиями значений и переживает перезапуск агента.
func hookMarker(cfg *Config) string {
	name := cfg.Project + "+" + cfg.Env
	if cfg.Group != "" {
		name = cfg.Group + "+" + name
	}
	return filepath.Join(cacheDir(cfg), "hook-"+name+".pending")
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// parseMode - права файла строкой: всегда восьмеричные. "644" без нуля
// впереди раньше читалось десятичным 644 = 0o1204, и файл со значениями
// становился читаем всем.
func parseMode(text string) (os.FileMode, error) {
	digits := strings.TrimSpace(text)
	// 0o440 принимал прежний разбор флага: юнит с такой записью после
	// самообновления не должен перестать запускаться.
	digits = strings.TrimPrefix(strings.TrimPrefix(digits, "0o"), "0O")
	parsed, err := strconv.ParseUint(digits, 8, 32)
	if err != nil || parsed == 0 || parsed > 0o777 {
		return 0, fmt.Errorf(tr("права %q не разобрались: нужно восьмеричное число, например 0440",
			"cannot parse the mode %q: an octal number is expected, for example 0440"), text)
	}
	return os.FileMode(parsed), nil
}

// --- самообновление --------------------------------------------------------

// manifest - что панель рассказывает о доступной версии. Подпись покрывает
// версию и хеши: подменить бинарь или подсунуть старую версию под видом новой
// нельзя, не имея закрытого ключа.
type manifest struct {
	Version string `json:"version"`
	Files   map[string]struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"files"`
	Signature string `json:"signature"`
}

func signedText(m *manifest) []byte {
	arches := make([]string, 0, len(m.Files))
	for arch := range m.Files {
		arches = append(arches, arch)
	}
	sort.Strings(arches)
	var b strings.Builder
	b.WriteString("sekvyr-agent\n")
	fmt.Fprintf(&b, "version %s\n", m.Version)
	for _, arch := range arches {
		fmt.Fprintf(&b, "%s %s\n", arch, m.Files[arch].SHA256)
	}
	return []byte(b.String())
}

// parseVersion разбирает "0.26.0" в числа. Хвост вроде "-rc1" отбрасываем: до
// сравнения предвыпусков дело здесь не доходит, а гадать о них не нужно.
func parseVersion(s string) []int {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		n := 0
		if part == "" {
			return nil
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return nil
			}
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
	}
	return out
}

// newer - строго ли версия a новее b. Сравниваем числами: как строки "0.9.0"
// оказалась бы новее "0.10.0". Непонятную версию считаем не новее - агент
// скорее не обновится, чем поставит неизвестно что.
func newer(a, b string) bool {
	x, y := parseVersion(a), parseVersion(b)
	if x == nil || y == nil {
		return false
	}
	for i := 0; i < len(x) || i < len(y); i++ {
		var xi, yi int
		if i < len(x) {
			xi = x[i]
		}
		if i < len(y) {
			yi = y[i]
		}
		if xi != yi {
			return xi > yi
		}
	}
	return false
}

func fetchManifest(cfg *Config) (*manifest, error) {
	var m manifest
	if err := get(cfg.URL+"/api/v1/machine/agent/manifest", "", &m); err != nil {
		return nil, err
	}
	if PublicKey == "" {
		return nil, errors.New(tr("агент собран без публичного ключа — обновление невозможно", "the agent was built without a public key, updates are impossible"))
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(PublicKey))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New(tr("публичный ключ в бинаре испорчен", "the public key in the binary is damaged"))
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return nil, errors.New(tr("подпись описания не разобралась", "the release signature could not be parsed"))
	}
	if !ed25519.Verify(ed25519.PublicKey(key), signedText(&m), sig) {
		// Именно здесь и стоит вся защита: панель могла бы раздать что угодно,
		// но без закрытого ключа подпись не сходится, и нода ничего не поставит.
		return nil, errors.New(tr("подпись версии не сходится — обновление отклонено", "the release signature does not match, the update is rejected"))
	}
	return &m, nil
}

func cmdUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	config := fs.String("config", defaultConfig, tr("конфиг агента", "agent config"))
	check := fs.Bool("check", false, tr("только проверить, не ставить", "only check, do not install"))
	restart := fs.String("restart", "", tr("что перезапустить после обновления", "unit to restart after an update"))
	down := fs.Bool("allow-downgrade", false, tr("поставить версию старее текущей", "install a version older than the current one"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*config)
	if err != nil {
		return err
	}
	m, err := fetchManifest(cfg)
	if err != nil {
		return err
	}
	if m.Version == Version {
		fmt.Printf(tr("уже последняя версия: %s\n", "already the latest version: %s\n"), Version)
		return nil
	}
	if !newer(m.Version, Version) && !*down {
		// Откат - решение человека, а не панели: у захваченной панели это был бы
		// способ вернуть ноды на версию с известной дырой, не подделывая подпись.
		return fmt.Errorf(
			tr("панель предлагает %s — не новее текущей %s; откат делается руками: sekvyr update --allow-downgrade",
				"the panel offers %s, which is not newer than the current %s; a downgrade is done by hand: sekvyr update --allow-downgrade"),
			m.Version, Version,
		)
	}
	fmt.Printf(tr("доступна версия %s (сейчас %s)\n", "version %s is available (current %s)\n"), m.Version, Version)
	if *check {
		return nil
	}
	if err := applyUpdate(cfg, m); err != nil {
		return err
	}
	fmt.Println(tr("обновлено до", "updated to"), m.Version)
	if *restart != "" {
		runHook(context.Background(), "systemctl restart "+*restart)
	} else if _, err := exec.LookPath("systemctl"); err == nil {
		fmt.Println(tr("работающая служба остается на прежней версии до перезапуска: sudo systemctl restart sekvyr-agent (или sekvyr update --restart sekvyr-agent)",
			"the running service stays on the previous version until it restarts: sudo systemctl restart sekvyr-agent (or sekvyr update --restart sekvyr-agent)"))
	} else {
		fmt.Println(tr("работающий агент остается на прежней версии до перезапуска", "the running agent stays on the previous version until it restarts"))
	}
	return nil
}

// applyUpdate качает бинарь, сверяет хеш с подписанным описанием и заменяет
// себя. Сначала проверка, потом запись: файл, который не сошелся по хешу, не
// должен даже полежать на диске исполняемым.
func applyUpdate(cfg *Config, m *manifest) error {
	want, ok := m.Files[runtime.GOARCH]
	if !ok {
		return fmt.Errorf(tr("в описании нет сборки под %s", "the release has no build for %s"), runtime.GOARCH)
	}
	// Свой клиент с пределом: у http.Get его нет вовсе, а проверка обновления
	// идет в том же цикле, что и раздача значений. Соединение, зависшее без
	// обрыва, остановило бы агента навсегда, и значения на ноде перестали бы
	// обновляться.
	client := &http.Client{Timeout: 5 * time.Minute}
	res, err := client.Get(cfg.URL + "/api/v1/machine/agent?arch=" + runtime.GOARCH)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf(tr("панель ответила %d", "the panel answered %d"), res.StatusCode)
	}
	blob, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(blob)
	if hex.EncodeToString(sum[:]) != want.SHA256 {
		return errors.New(tr("хеш скачанного бинаря не совпал с подписанным описанием", "the hash of the downloaded binary does not match the signed release"))
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return err
	}
	tmp := self + ".new"
	// Файл с таким именем мог остаться от оборванной установки (curl -o, 0644):
	// его права сохранились бы, и новый бинарь стал бы неисполняемым.
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			// Недописанный бинарь (кончилось место) не должен лежать рядом.
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return err
	}
	// На диск до переименования, как и файл со значениями: на XFS после сбоя
	// питания на месте агента оставался файл нулевой длины, и служба больше не
	// поднималась вовсе.
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	// Переименование атомарно: работающий процесс продолжает жить со старым
	// файлом, а следующий запуск берет новый.
	if err := os.Rename(tmp, self); err != nil {
		return err
	}
	syncDir(filepath.Dir(self))
	done = true
	return nil
}
