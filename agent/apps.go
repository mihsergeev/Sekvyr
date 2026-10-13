package main

// Несколько приложений под одним агентом.
//
// Раньше каждое приложение на сервере требовало своей службы, своего конфига и
// команды из пяти флагов. На третьем приложении это перестает помещаться в
// голову, а на десятом превращается в десять служб, за которыми никто не
// следит.
//
// Теперь агент один, а приложения - список в его конфиге. Добавить приложение
// это одна короткая команда:
//
//	sekvyr add checkout/prod
//
// Пути при этом выводятся из имени проекта: файл `/run/sekvyr/checkout.env`,
// команда после изменения `docker compose -f /app/checkout/compose.yml up -d`.
// Все это можно переопределить флагами, но по умолчанию угадывать нечего.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// App - одно приложение на сервере: какое окружение забирать, куда класть и что
// после этого выполнить.
type App struct {
	Project  string `json:"project"`
	Env      string `json:"env"`
	Group    string `json:"group,omitempty"`
	Out      string `json:"out"`
	OnChange string `json:"on_change,omitempty"`
	Mode     string `json:"mode,omitempty"`
}

// name - как приложение выглядит в выводе и в ошибках.
func (a App) name() string {
	if a.Group != "" {
		return a.Group + "/" + a.Project + "/" + a.Env
	}
	return a.Project + "/" + a.Env
}

// nameRe - имена в том виде, в каком их заводит панель: строчные латинские,
// цифры и дефис. Имя проекта уходит в путь файла и в команду после изменения,
// которые агент выполняет от root, поэтому другого имени агент не примет ни от
// панели, ни из командной строки: подмененная панель не должна дописывать в
// эту команду свое.
var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

func (a App) checkNames() error {
	if nameRe.MatchString(a.Project) && nameRe.MatchString(a.Env) &&
		(a.Group == "" || nameRe.MatchString(a.Group)) {
		return nil
	}
	return fmt.Errorf(tr("недопустимое имя %q: только строчные латинские буквы, цифры и дефис",
		"invalid name %q: only lowercase latin letters, digits and hyphens"), a.name())
}

// same - то же ли это приложение. Группа входит в имя: проект frontend бывает
// и у globex, и у initech, и без группы второй молча заменял первый.
func (a App) same(b App) bool {
	return a.Group == b.Group && a.Project == b.Project && a.Env == b.Env
}

// splitShared оставляет по одному приложению на файл. Два приложения в одном
// файле затирали бы его друг другу каждую минуту и каждый раз дергали бы
// перезапуск. Первое по списку обслуживается, про остальные - строка в ответе.
func splitShared(list []App) ([]App, []string) {
	kept := make([]App, 0, len(list))
	var clashes []string
	owner := map[string]string{}
	for _, app := range list {
		if first, ok := owner[app.Out]; ok {
			clashes = append(clashes, fmt.Sprintf(tr(
				"sekvyr: %s пропущено: файл %s уже пишет %s, задайте свой: sekvyr add %s -o ДРУГОЙ_ФАЙЛ",
				"sekvyr: %s skipped: %s is already written by %s, give it its own: sekvyr add %s -o OTHER_FILE"),
				app.name(), app.Out, first, app.name()))
			continue
		}
		owner[app.Out] = app.name()
		kept = append(kept, app)
	}
	return kept, clashes
}

// mode - права файла. Строкой в конфиге, потому что 0400 в JSON выглядит как
// 256, и человек, открывший файл, не поймет, что он читает.
func (a App) fileMode() os.FileMode {
	if a.Mode == "" {
		return 0o400
	}
	var parsed uint32
	if _, err := fmt.Sscanf(a.Mode, "%o", &parsed); err != nil || parsed == 0 {
		return 0o400
	}
	return os.FileMode(parsed)
}

// defaults достраивает то, что можно вывести из имени проекта.
func (a App) defaults() App {
	if a.Out == "" {
		a.Out = "/run/sekvyr/" + a.Project + ".env"
	}
	if a.OnChange == "" {
		a.OnChange = "docker compose -f /app/" + a.Project + "/compose.yml up -d"
	}
	return a
}

// apps - что агенту обслуживать. Старый конфиг с одним проектом на верхнем
// уровне читается как одно приложение: агенты, поставленные раньше, продолжают
// работать без правок.
func (c *Config) apps() []App {
	if len(c.Apps) > 0 {
		out := make([]App, 0, len(c.Apps))
		for _, app := range c.Apps {
			out = append(out, app.withFile())
		}
		return out
	}
	return nil
}

// withFile достраивает только путь файла. Команду после изменения add и
// enroll записывают в конфиг явно, поэтому ее отсутствие в списке значит "не
// выполнять ничего": так ноды, перенесенные прежними версиями из режима -o без
// --on-change, и записаны. Подставлять туда docker compose значило бы впервые
// выполнить на ноде команду, которой она никогда не выполняла.
func (a App) withFile() App {
	if a.Out == "" {
		a.Out = "/run/sekvyr/" + a.Project + ".env"
	}
	return a
}

// runDir - каталог файлов, которые агент заводит сам (tmpfs службы). Только
// отсюда add убирает прежний файл приложения: все остальное мог написать
// человек, и удалять его от root нельзя. Переменная - ради тестов.
var runDir = "/run/sekvyr"

// legacy - приложение из старого конфига, где проект указан на верхнем уровне.
//
// Путь к его файлу задан флагом службы (`-o`), а не конфигом, поэтому
// подставлять сюда значение по умолчанию нельзя: на ноде по этому файлу уже
// живет работающий сервис, и переименование сломало бы его молча.
func (c *Config) legacy(out string) (App, bool) {
	if c.Project == "" {
		return App{}, false
	}
	app := App{Project: c.Project, Env: c.Env, Group: c.Group, Out: out}
	return app.defaults(), true
}

// forApp - конфиг для одного приложения: личность общая, окружение свое.
func (c *Config) forApp(app App) *Config {
	copy := *c
	copy.Project = app.Project
	copy.Env = app.Env
	copy.Group = app.Group
	return &copy
}

// reorder переставляет позиционный аргумент в конец.
//
// Стандартный разбор флагов останавливается на первом не-флаге, поэтому
// `sekvyr add app/prod --on-change ...` молча терял хвост. Человек пишет имя
// первым, и спорить с этим бессмысленно.
func reorder(args []string) []string {
	flags := make([]string, 0, len(args))
	rest := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			// Флаг со значением через пробел: значение забираем следом, иначе
			// оно уедет в позиционные и станет "вторым приложением".
			if !strings.Contains(arg, "=") && i+1 < len(args) &&
				!strings.HasPrefix(args[i+1], "-") && needsValue(arg) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		rest = append(rest, arg)
	}
	return append(flags, rest...)
}

// needsValue - какие флаги берут значение. Список короткий и свой: разбирать
// чужие определения флагов ради этого незачем.
func needsValue(flag string) bool {
	switch strings.TrimLeft(flag, "-") {
	case "config", "o", "on-change", "mode":
		return true
	}
	return false
}

// parseTarget разбирает "checkout/prod" и "группа/checkout/prod".
func parseTarget(raw string) (App, error) {
	parts := strings.Split(strings.Trim(raw, "/"), "/")
	var app App
	switch len(parts) {
	case 2:
		app = App{Project: parts[0], Env: parts[1]}
	case 3:
		app = App{Group: parts[0], Project: parts[1], Env: parts[2]}
	default:
		return App{}, fmt.Errorf(tr("не разобрал %q: нужно «проект/окружение»", "cannot parse %q: expected project/environment"), raw)
	}
	return app, app.checkNames()
}

func cmdAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	args = reorder(args)
	config := fs.String("config", defaultConfig, tr("конфиг агента", "agent config"))
	out := fs.String("o", "", tr("куда писать файл (по умолчанию /run/sekvyr/ПРОЕКТ.env)", "where to write the file (/run/sekvyr/PROJECT.env by default)"))
	onChange := fs.String("on-change", "", tr("что выполнить после изменения", "command to run after a change"))
	mode := fs.String("mode", "", tr("права файла, например 0440", "file mode, for example 0440"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New(tr("укажите приложение: sekvyr add проект/окружение", "name the application: sekvyr add project/environment"))
	}
	app, err := parseTarget(fs.Arg(0))
	if err != nil {
		return err
	}
	if *mode != "" {
		// Опечатка в правах раньше молча превращалась в 0400.
		var parsed uint32
		if _, err := fmt.Sscanf(*mode, "%o", &parsed); err != nil || parsed == 0 || parsed > 0o777 ||
			strings.TrimLeft(*mode, "01234567") != "" {
			return fmt.Errorf(tr("права %q не разобрались: нужно восьмеричное число, например 0440",
				"cannot parse the mode %q: an octal number is expected, for example 0440"), *mode)
		}
	}

	cfg, err := loadConfig(*config)
	if err != nil {
		return err
	}
	app.Out, app.OnChange, app.Mode = *out, *onChange, *mode
	// Повторный add без флагов не сбрасывает заданное раньше: панель при
	// повторной выдаче показывает ровно такую команду, и файл с командой,
	// заданные через -o и --on-change, молча возвращались к умолчаниям.
	for _, existing := range cfg.Apps {
		if existing.same(app) {
			if *out == "" {
				app.Out = existing.Out
			}
			if *onChange == "" {
				app.OnChange = existing.OnChange
				if app.OnChange == "" {
					// Пустая команда в списке значит "не выполнять" (withFile).
					// defaults ниже подставил бы docker compose - записываем
					// "ничего" явно.
					app.OnChange = noHook
				}
			}
			if *mode == "" {
				app.Mode = existing.Mode
			}
		}
	}
	app = app.defaults()
	// Команда по умолчанию рассчитана на /app/ПРОЕКТ/compose.yml. Если его нет,
	// она будет падать после каждого изменения, и узнают об этом только из
	// журнала службы. Лучше сказать сразу.
	warning := ""
	if app.OnChange == (App{Project: app.Project}).defaults().OnChange {
		compose := "/app/" + app.Project + "/compose.yml"
		if _, err := os.Stat(compose); err != nil {
			warning = fmt.Sprintf(tr(
				"sekvyr: нет %s, и команда после изменения не выполнится: задайте --on-change или положите туда compose.yml\n",
				"sekvyr: there is no %s, so the command after a change will fail: pass --on-change or put a compose.yml there\n"), compose)
		}
	}
	// Служба идет с ProtectSystem=strict и пишет только в свои каталоги: файл
	// вне /run/sekvyr она не запишет, а в журнале раз в минуту будет "файл не
	// записан". Лучше сказать сразу и подсказать, как разрешить каталог.
	if dir := filepath.Dir(app.Out); *out != "" && dir != "/run/sekvyr" && !strings.HasPrefix(dir, "/run/sekvyr/") {
		warning += fmt.Sprintf(tr(
			"sekvyr: служба пишет только в /run/sekvyr: разрешите ей %s (sudo systemctl edit sekvyr-agent, в [Service] строка ReadWritePaths=-%s; минус - чтобы служба поднималась и без этого каталога)\n",
			"sekvyr: the service writes only to /run/sekvyr: allow it %s (sudo systemctl edit sekvyr-agent, under [Service] the line ReadWritePaths=-%s; the dash lets the service start without that directory)\n"), dir, dir)
	}

	// Путь по умолчанию выводится из имени проекта, поэтому второе окружение
	// того же проекта (или одноименный проект другой группы) попало бы в тот же
	// файл. Старый верхний уровень здесь не проверяем: его настоящий путь задан
	// флагом службы, и о нем скажет сама служба.
	for _, existing := range cfg.apps() {
		if !existing.same(app) && existing.Out == app.Out {
			return fmt.Errorf(tr(
				"файл %s уже пишет %s: два приложения в одном файле затирали бы друг друга, задайте этому свой через -o (и, скорее всего, --on-change)",
				"%s is already written by %s: two applications in one file would overwrite each other, give this one its own with -o (and most likely --on-change)"),
				app.Out, existing.name())
		}
	}
	// Старый верхний уровень не трогаем: путь к его файлу знает только служба,
	// и перенос сюда переименовал бы файл работающего сервиса.
	for i, existing := range cfg.Apps {
		if existing.same(app) {
			// Установщик зовет add сразу после enroll, который приложение уже
			// записал: "обновлено" на свежей ноде звучало как правка, которой
			// не было.
			if existing.defaults() == app {
				fmt.Printf(tr("sekvyr: %s уже подключено (файл %s)\n", "sekvyr: %s is already connected (file %s)\n"), app.name(), app.Out)
				fmt.Print(warning)
				return nil
			}
			cfg.Apps[i] = app
			if err := saveConfig(*config, cfg); err != nil {
				return err
			}
			if cfg.BoundOut != "" && cfg.BoundOut == existing.defaults().Out && app.Out != cfg.BoundOut {
				warning += fmt.Sprintf(tr(
					"sekvyr: в юните службы остался флаг -o %s: запустите установщик заново без --out, иначе служба будет напоминать об этом при каждом старте\n",
					"sekvyr: the service unit still has the flag -o %s: run the installer again without --out, or the service will remind you on every start\n"), cfg.BoundOut)
			}
			// Файл переехал: прежний со значениями больше некому обновлять, и
			// протухшая копия секретов осталась бы лежать рядом. Файл, который
			// пишет и другое приложение, остается ему.
			if was := existing.withFile().Out; was != app.Out {
				shared := false
				for _, other := range cfg.apps() {
					shared = shared || other.Out == was
				}
				switch {
				case shared:
				case filepath.Dir(was) == runDir:
					_ = os.Remove(was)
				default:
					// Вне каталога агента файл мог быть чьим угодно (опечатка в
					// -o указала на compose.yml) - не трогаем, только говорим.
					warning += fmt.Sprintf(tr(
						"sekvyr: прежний файл %s оставлен на месте: если в нем значения, удалите его сами\n",
						"sekvyr: the previous file %s was left in place: if it holds values, delete it yourself\n"), was)
				}
			}
			fmt.Printf(tr("sekvyr: %s обновлено (файл %s)\n", "sekvyr: %s updated (file %s)\n"), app.name(), app.Out)
			fmt.Print(warning)
			return nil
		}
	}
	cfg.Apps = append(cfg.Apps, app)
	if err := saveConfig(*config, cfg); err != nil {
		return err
	}
	fmt.Printf(tr("sekvyr: %s добавлено (файл %s)\n", "sekvyr: %s added (file %s)\n"), app.name(), app.Out)
	fmt.Println(tr("sekvyr: значения приедут в течение минуты, перезапускать ничего не нужно",
		"sekvyr: the values arrive within a minute, nothing needs a restart"))
	fmt.Print(warning)
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	args = reorder(args)
	config := fs.String("config", defaultConfig, tr("конфиг агента", "agent config"))
	paths := fs.Bool("paths", false, tr("только файлы приложений, по строке (для установщика)", "only the application files, one per line (for the installer)"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*config)
	if err != nil {
		return err
	}
	list := cfg.apps()
	if *paths {
		// Установщик по этому списку открывает службе каталоги файлов: юнит
		// переписывается при каждом запуске, и каталог файла, заданного
		// раньше флагом -o, иначе пропадал из ReadWritePaths.
		for _, app := range list {
			fmt.Println(app.Out)
		}
		return nil
	}
	legacyNote := ""
	if app, ok := cfg.legacy(""); ok {
		list = append([]App{app}, list...)
		// У конфига старого вида файл задан флагом службы -o, а не здесь:
		// показанный путь - только предположение до первого запуска агента.
		legacyNote = tr("sekvyr: путь первого приложения задан флагом службы (-o), до первого запуска новой версии агента он может отличаться",
			"sekvyr: the path of the first application is set by the service flag (-o) and may differ until the new agent version first runs")
	}
	if len(list) == 0 {
		fmt.Println(tr("sekvyr: приложений нет — добавьте: sekvyr add проект/окружение", "sekvyr: no applications yet, add one: sekvyr add project/environment"))
		return nil
	}
	for _, app := range list {
		state := tr("нет файла", "no file")
		if info, err := os.Stat(app.Out); err == nil {
			state = fmt.Sprintf(tr("%d байт, %s", "%d bytes, %s"), info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
		}
		fmt.Printf("%-28s %-32s %s\n", app.name(), app.Out, state)
	}
	if legacyNote != "" {
		fmt.Println(legacyNote)
	}
	return nil
}

func cmdRemove(args []string) error {
	fs := flag.NewFlagSet("rm", flag.ExitOnError)
	args = reorder(args)
	config := fs.String("config", defaultConfig, tr("конфиг агента", "agent config"))
	keep := fs.Bool("keep-file", false, tr("оставить файл со значениями на месте", "keep the values file in place"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New(tr("укажите приложение: sekvyr rm проект/окружение", "name the application: sekvyr rm project/environment"))
	}
	want, err := parseTarget(fs.Arg(0))
	if err != nil {
		return err
	}
	cfg, err := loadConfig(*config)
	if err != nil {
		return err
	}
	kept := make([]App, 0, len(cfg.Apps))
	var removed *App
	names := make([]string, 0, len(cfg.Apps))
	for _, app := range cfg.Apps {
		names = append(names, app.name())
		if app.same(want) {
			copy := app
			removed = &copy
			continue
		}
		kept = append(kept, app)
	}
	// Конфиг старого вида: приложение на верхнем уровне, а не в списке.
	if removed == nil && cfg.Project != "" && (App{Project: cfg.Project, Env: cfg.Env, Group: cfg.Group}).same(want) {
		legacy, _ := cfg.legacy("")
		removed = &legacy
		cfg.Project, cfg.Env, cfg.Group = "", "", ""
	}
	if removed == nil {
		if len(names) == 0 {
			return fmt.Errorf(tr("приложения %s у агента нет", "the agent has no application %s"), want.name())
		}
		// Чаще всего это имя без группы: показываем, как приложения названы.
		return fmt.Errorf(tr("приложения %s у агента нет (есть: %s)", "the agent has no application %s (it has: %s)"),
			want.name(), strings.Join(names, ", "))
	}
	cfg.Apps = kept
	if err := saveConfig(*config, cfg); err != nil {
		return err
	}
	out := removed.defaults().Out
	shared := false
	for _, app := range cfg.apps() {
		shared = shared || app.Out == out
	}
	if !*keep && !shared {
		// Файл со значениями больше некому обновлять, а приложение, читающее
		// протухший файл, - худший из исходов. Файл, который пишет и другое
		// приложение (конфиг со старых версий), остается ему.
		_ = os.Remove(out)
	}
	// Копия значений и отметка о несделанной команде уходят вместе с
	// приложением: обещание rm - "значений этого приложения на сервере нет".
	gone := cfg.forApp(*removed)
	removeCache(gone)
	_ = os.Remove(hookMarker(gone))
	fmt.Printf(tr("sekvyr: %s убрано\n", "sekvyr: %s removed\n"), removed.name())
	if cfg.BoundOut != "" && cfg.BoundOut == out {
		fmt.Printf(tr(
			"sekvyr: файл этого приложения задавал флаг службы -o %s: запустите установщик заново без --out\n",
			"sekvyr: this application's file came from the service flag -o %s: run the installer again without --out\n"), out)
	}
	return nil
}

// normalize переносит проект с верхнего уровня конфига в список приложений.
//
// Путь берется тот, по которому агент уже пишет файл (флаг службы), а не
// вычисляется заново: по нему живет работающий сервис. Если запись о том же
// проекте в списке уже есть, она поправляется, а не задваивается.
func normalize(path string, cfg *Config, running *App) error {
	if cfg.Project == "" {
		return nil
	}
	moved := App{Project: cfg.Project, Env: cfg.Env, Group: cfg.Group}
	if running != nil {
		// Ровно то, с чем служба работает сейчас, включая пустую команду:
		// достраивать её здесь нельзя, иначе агент начнет дергать compose,
		// которого на этой ноде нет.
		moved.Out, moved.OnChange, moved.Mode = running.Out, running.OnChange, running.Mode
		cfg.BoundOut = running.Out
		if moved.OnChange == "" {
			// В списке пустая команда значит "по умолчанию" (defaults), и
			// при следующем чтении конфига превратилась бы в docker compose.
			// "Ничего не делать" в списке записывается как true.
			moved.OnChange = noHook
		}
	} else {
		// Флага службы нет, а запись о том же окружении в списке уже есть
		// (второй экземпляр: config оставил проект наверху, add записал свой
		// файл): она и есть настоящая. Умолчания поверх нее отправили бы два
		// агента писать один файл по очереди.
		for _, app := range cfg.Apps {
			if app.same(moved) {
				cfg.Project, cfg.Env, cfg.Group = "", "", ""
				return saveConfig(path, cfg)
			}
		}
		moved = moved.defaults()
	}

	kept := make([]App, 0, len(cfg.Apps)+1)
	replaced := false
	for _, app := range cfg.Apps {
		if app.same(moved) {
			if !replaced {
				kept = append(kept, moved)
				replaced = true
			}
			continue
		}
		kept = append(kept, app)
	}
	if !replaced {
		kept = append([]App{moved}, kept...)
	}
	cfg.Apps = kept
	cfg.Project, cfg.Env, cfg.Group = "", "", ""
	return saveConfig(path, cfg)
}

// noHook - команда после изменения, которая ничего не делает. В списке пустая
// команда означает "по умолчанию", поэтому "не выполнять ничего" записывается
// так же, как это советует документация: --on-change true.
const noHook = "true"

// bindOut относит флаг службы -o к приложению из списка.
//
// Проекта на верхнем уровне конфига нет, а служба запущена с -o. Так бывает
// после переноса (normalize уже записал приложение с этим файлом) и на свежей
// установке с --out: enroll записал выданное окружение в список с путем по
// умолчанию, а юнит пишет другой файл. Раньше в обоих случаях флаг давал
// приложение без проекта, и файл не писался никогда. Флаг относится к
// приложению, которое уже пишет этот файл; если такого нет, а приложение одно,
// - это оно, и путь из флага записывается в конфиг. Иначе флагу не к чему
// относиться, и об этом говорится, а не угадывается.
func bindOut(path string, cfg *Config, out, onChange, mode string) error {
	changed, err := bindApps(cfg, out, onChange, mode)
	if err != nil || !changed {
		return err
	}
	return saveConfig(path, cfg)
}

// bindApps - то же без записи на диск: меняет конфиг в памяти и говорит,
// изменилось ли что-нибудь.
func bindApps(cfg *Config, out, onChange, mode string) (bool, error) {
	for _, app := range cfg.Apps {
		if app.defaults().Out == out {
			if cfg.BoundOut != out {
				cfg.BoundOut = out
				return true, nil
			}
			return false, nil
		}
	}
	// Флаг уже был отнесен раньше, а теперь его файл никто не пишет:
	// приложение убрали (sekvyr rm) или перенесли в другой файл (add -o).
	// Привязывать его заново к оставшемуся приложению нельзя - его значения
	// поехали бы в чужой файл с чужой командой после изменения.
	if cfg.BoundOut == out {
		return false, fmt.Errorf(tr(
			"флаг службы -o %s больше ни к чему не относится (приложение убрано или переехало в другой файл): уберите его из юнита - запустите установщик заново без --out",
			"the service flag -o %s no longer belongs to anything (the application was removed or moved to another file): drop it from the unit by running the installer again without --out"),
			out)
	}
	if len(cfg.Apps) != 1 {
		return false, fmt.Errorf(tr(
			"флаг службы -o %s не к чему отнести: ни одно из приложений (%d) не пишет этот файл. Задайте его нужному: sekvyr add ПРОЕКТ/ОКРУЖЕНИЕ -o %s",
			"the service flag -o %s has nothing to belong to: none of the applications (%d) writes this file. Give it to the right one: sekvyr add PROJECT/ENVIRONMENT -o %s"),
			out, len(cfg.Apps), out)
	}
	// Единственное приложение со своим файлом (add -o) - тоже не наше: человек
	// задал ему путь сам, и флаг юнита его не перебивает.
	only := cfg.Apps[0]
	if only.defaults().Out != (App{Project: only.Project}).defaults().Out {
		return false, fmt.Errorf(tr(
			"флаг службы -o %s не к чему отнести: у %s свой файл %s. Уберите флаг из юнита - запустите установщик заново без --out",
			"the service flag -o %s has nothing to belong to: %s has its own file %s. Drop the flag from the unit by running the installer again without --out"),
			out, only.name(), only.defaults().Out)
	}
	if onChange == "" {
		onChange = noHook
	}
	cfg.Apps[0].Out, cfg.Apps[0].OnChange, cfg.Apps[0].Mode = out, onChange, mode
	cfg.BoundOut = out
	return true, nil
}

// pick - какое приложение имеется в виду в разовых командах (`render`, `run`).
//
// Одно приложение - вопроса нет. Несколько - угадывать нельзя: человек получит
// чужие значения и заметит это не сразу, поэтому просим назвать явно.
func pick(cfg *Config, target string) (*Config, error) {
	if target != "" {
		app, err := parseTarget(target)
		if err != nil {
			return nil, err
		}
		return cfg.forApp(app), nil
	}
	if cfg.Project != "" {
		return cfg, nil
	}
	list := cfg.apps()
	switch len(list) {
	case 0:
		return nil, errors.New(tr("приложений нет — добавьте: sekvyr add проект/окружение", "no applications yet, add one: sekvyr add project/environment"))
	case 1:
		return cfg.forApp(list[0]), nil
	default:
		names := make([]string, 0, len(list))
		for _, app := range list {
			names = append(names, app.name())
		}
		return nil, fmt.Errorf(tr("приложений несколько (%s) — укажите --app", "there are several applications (%s): choose one with --app"), strings.Join(names, ", "))
	}
}
