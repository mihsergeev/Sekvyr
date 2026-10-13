package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Нода, поставленная с -o FILE: после переноса проекта в список верхний
// уровень конфига пуст, и флаг больше не должен давать приложение без проекта.
// Пустая команда при переносе остается пустой, а не превращается в docker
// compose при следующем чтении.
func TestLegacyOutSurvivesRestart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "app.env")
	path := testConfig(t)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Project, cfg.Env = "shop", "prod"
	running := &App{Project: "shop", Env: "prod", Out: file, Mode: "400"}
	if err := normalize(path, cfg, running); err != nil {
		t.Fatal(err)
	}
	after, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Project != "" {
		t.Fatalf("проект остался наверху: %+v", after)
	}
	apps := after.apps()
	if len(apps) != 1 || apps[0].Out != file || apps[0].OnChange != noHook {
		t.Fatalf("после переноса: %+v", apps)
	}
	// Второй старт с тем же -o: приложение уже пишет этот файл, конфиг не
	// трогается.
	before, _ := os.ReadFile(path)
	if err := bindOut(path, after, file, "", "400"); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(path); string(again) != string(before) {
		t.Fatalf("конфиг переписан на втором старте:\n%s\n---\n%s", before, again)
	}
}

// Свежая установка с --out: enroll записал выданное окружение с путем по
// умолчанию, а юнит пишет другой файл. Флаг относится к этому приложению.
func TestOutFlagBindsTheOnlyApp(t *testing.T) {
	file := filepath.Join(t.TempDir(), "app.env")
	path := testConfig(t, App{Project: "shop", Env: "prod"}.defaults())
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindOut(path, cfg, file, "systemctl reload shop", "440"); err != nil {
		t.Fatal(err)
	}
	apps := savedApps(t, path)
	if len(apps) != 1 || apps[0].Out != file || apps[0].OnChange != "systemctl reload shop" || apps[0].Mode != "440" {
		t.Fatalf("флаг не привязан: %+v", apps)
	}
}

// Приложений несколько, и ни одно не пишет файл из флага: угадывать нельзя.
func TestOutFlagWithSeveralAppsIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := testConfig(t,
		App{Project: "shop", Env: "prod", Out: filepath.Join(dir, "shop.env")},
		App{Project: "blog", Env: "prod", Out: filepath.Join(dir, "blog.env")},
	)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := bindOut(path, cfg, filepath.Join(dir, "other.env"), "", "400"); err == nil {
		t.Fatal("флаг отнесен наугад")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("конфиг изменился после отказа")
	}
}

// Повторный add без флагов (так выглядит команда повторной выдачи в панели)
// не сбрасывает файл и команду, заданные раньше.
func TestAddAgainKeepsFlags(t *testing.T) {
	// Файл приложения - во временном каталоге, а не в настоящем /run/sekvyr
	// машины, где идут тесты: add умеет убирать прежний файл.
	dir := t.TempDir()
	runDir = dir
	defer func() { runDir = "/run/sekvyr" }()
	file := filepath.Join(dir, "shop.env")
	path := testConfig(t, App{Project: "shop", Env: "prod", Out: filepath.Join(dir, "old.env"), OnChange: "true"})
	if err := cmdAdd([]string{"--config", path, "shop/prod", "-o", file, "--on-change", "true", "--mode", "0440"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAdd([]string{"--config", path, "shop/prod"}); err != nil {
		t.Fatal(err)
	}
	apps := savedApps(t, path)
	if len(apps) != 1 || apps[0].Out != file || apps[0].OnChange != "true" || apps[0].Mode != "0440" {
		t.Fatalf("повторный add сбросил настройки: %+v", apps)
	}
}

// Файл приложения переехал через add -o: прежний со значениями не остается
// лежать протухшей копией.
func TestAddMovingTheFileRemovesTheOldOne(t *testing.T) {
	dir := t.TempDir()
	runDir = dir
	defer func() { runDir = "/run/sekvyr" }()
	old := filepath.Join(dir, "old.env")
	if err := os.WriteFile(old, []byte("A=1\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	path := testConfig(t, App{Project: "shop", Env: "prod", Out: old, OnChange: "true"})
	if err := cmdAdd([]string{"--config", path, "shop/prod", "-o", filepath.Join(dir, "new.env")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("прежний файл остался: %v", err)
	}
}

func TestAddRefusesBadMode(t *testing.T) {
	path := testConfig(t)
	for _, mode := range []string{"rw", "0999", "8", "0", "07777"} {
		if err := cmdAdd([]string{"--config", path, "shop/prod", "--mode", mode}); err == nil {
			t.Fatalf("права %q приняты", mode)
		}
	}
	if apps := savedApps(t, path); len(apps) != 0 {
		t.Fatalf("после отказов конфиг изменился: %+v", apps)
	}
}

// Копия значений одного приложения не отдается другому, даже если лежит под
// его именем: имя файла - не доказательство.
func TestCacheIsCheckedAgainstTheApp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("STATE_DIRECTORY", dir)
	t.Setenv("SEKVYR_NODE_KEY", filepath.Join(dir, "node.key"))
	shop := &Config{Project: "shop-eu", Env: "prod", path: filepath.Join(dir, "agent.json")}
	other := &Config{Project: "shop", Env: "eu-prod", path: shop.path}
	if err := saveCache(shop, &secretsResponse{Project: "shop-eu", Environment: "prod", Values: []value{{Name: "A", Value: "1"}}}); err != nil {
		t.Fatal(err)
	}
	if res, _, err := loadCache(shop); err != nil || len(res.Values) != 1 {
		t.Fatalf("своя копия не прочиталась: %v", err)
	}
	// Копия по прежнему имени, общему для shop-eu/prod и shop/eu-prod.
	raw, _ := os.ReadFile(cachePath(shop))
	if err := os.WriteFile(oldCachePath(other), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCache(other); err == nil {
		t.Fatal("чужая копия отдана приложению")
	}
}

// Копия заменяет ответ, только когда панели нет. Отозванный доступ или
// исчезнувшее окружение копией не лечатся.
func TestOnlyUnreachablePanelFallsBackToCopy(t *testing.T) {
	for code, want := range map[int]bool{
		http.StatusForbidden:           false,
		http.StatusNotFound:            false,
		http.StatusUnauthorized:        false,
		http.StatusUnprocessableEntity: false,
		http.StatusTooManyRequests:     false,
		http.StatusBadGateway:          true,
		http.StatusServiceUnavailable:  true,
	} {
		if got := unreachable(&panelError{code: code}); got != want {
			t.Fatalf("%d: %v", code, got)
		}
	}
	if !unreachable(&netError{errors.New("connection refused")}) {
		t.Fatal("сеть не считается недоступностью")
	}
	if unreachable(&json.SyntaxError{Offset: 1}) || unreachable(errors.New("unexpected end of JSON input")) {
		t.Fatal("испорченный ответ принят за недоступность")
	}
}

// sekvyr run: значение из панели главнее переменной родителя, а слишком
// длинное значение - понятная ошибка, а не E2BIG от execve.
func TestRunValuesWinOverParent(t *testing.T) {
	env, err := withValues([]string{"PATH=/bin", "DATABASE_URL=from-image"}, []value{{Name: "DATABASE_URL", Value: "from-panel"}})
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, kv := range env {
		if strings.HasPrefix(kv, "DATABASE_URL=") {
			found = append(found, kv)
		}
	}
	if len(found) != 1 || found[0] != "DATABASE_URL=from-panel" {
		t.Fatalf("окружение: %v", env)
	}
	if _, err := withValues(nil, []value{{Name: "BIG", Value: strings.Repeat("x", 200_000)}}); err == nil {
		t.Fatal("значение больше 128 КиБ пропущено в execve")
	}
}

// Конфиг пишется через временный файл: ни обрезанного файла, ни мусора рядом.
func TestSaveConfigIsAtomic(t *testing.T) {
	path := testConfig(t, App{Project: "shop", Env: "prod"})
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("рядом с конфигом остались файлы: %v", entries)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("права конфига %o", info.Mode().Perm())
	}
}

// Команда "новый сервер" на уже подключенном сервере не трогает конфиг и не
// тратит токен: отказ раньше обращения к панели.
func TestEnrollKeepsExistingConfig(t *testing.T) {
	path := testConfig(t, App{Project: "shop", Env: "prod"})
	before, _ := os.ReadFile(path)
	err := cmdEnroll([]string{"--url", "http://127.0.0.1:1", "--token", "t", "--config", path})
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("ожидали отказ с подсказкой --force, получили %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("конфиг переписан")
	}
}

// Команда после изменения сообщает, прошла ли она: упавшую агент повторяет.
// Остановка службы снимает зависшую команду сразу.
func TestHookReportsAndStops(t *testing.T) {
	if !runHook(context.Background(), "true") || runHook(context.Background(), "false") {
		t.Fatal("результат команды не тот")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if runHook(ctx, "sleep 5") {
		t.Fatal("прерванная команда считается прошедшей")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("остановка ждала команду %s", took)
	}
}

// Прежний файл вне каталога агента (опечатка в -o указала на чужой файл)
// add не удаляет: его мог написать человек.
func TestAddKeepsFilesOutsideItsDirectory(t *testing.T) {
	runDir = t.TempDir()
	defer func() { runDir = "/run/sekvyr" }()
	elsewhere := t.TempDir()
	typo := filepath.Join(elsewhere, "compose.yml")
	if err := os.WriteFile(typo, []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := testConfig(t, App{Project: "shop", Env: "prod", Out: typo, OnChange: "true"})
	if err := cmdAdd([]string{"--config", path, "shop/prod", "-o", filepath.Join(runDir, "shop.env")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(typo); err != nil {
		t.Fatalf("чужой файл удален: %v", err)
	}
}

// Приложение без команды в конфиге (так его записывали прежние версии при
// переносе из -o без --on-change) не получает docker compose ни при чтении
// списка, ни после повторного add без флагов.
func TestMissingCommandStaysMissing(t *testing.T) {
	file := filepath.Join(t.TempDir(), "shop.env")
	path := testConfig(t, App{Project: "shop", Env: "prod", Out: file})
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.apps()[0].OnChange; got != "" {
		t.Fatalf("подставлена команда %q", got)
	}
	if err := cmdAdd([]string{"--config", path, "shop/prod"}); err != nil {
		t.Fatal(err)
	}
	if got := savedApps(t, path)[0].OnChange; strings.Contains(got, "docker") {
		t.Fatalf("повторный add подставил %q", got)
	}
}

// Флаг службы -o, уже отнесенный к приложению, после rm не прилипает к
// оставшемуся приложению с чужой командой.
func TestBoundOutIsNotRebound(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "env")
	path := testConfig(t,
		App{Project: "shop", Env: "prod", Out: legacy, OnChange: "true"},
		App{Project: "blog", Env: "prod"}.defaults(),
	)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindOut(path, cfg, legacy, "systemctl reload shop", "400"); err != nil {
		t.Fatal(err)
	}
	if err := cmdRemove([]string{"--config", path, "--keep-file", "shop/prod"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindOut(path, cfg, legacy, "systemctl reload shop", "400"); err == nil {
		t.Fatal("флаг отнесен к другому приложению")
	}
	apps := savedApps(t, path)
	if len(apps) != 1 || apps[0].Project != "blog" || apps[0].Out == legacy {
		t.Fatalf("blog перепривязан: %+v", apps)
	}
}

// Права файла в render и agent - восьмеричные: "644" без нуля раньше давало
// 0o1204, то есть файл, читаемый всем.
func TestModeIsOctal(t *testing.T) {
	mode, err := parseMode("644")
	if err != nil || mode != 0o644 {
		t.Fatalf("644 -> %o, %v", mode, err)
	}
	for _, bad := range []string{"0", "999", "rw", "1777"} {
		if _, err := parseMode(bad); err == nil {
			t.Fatalf("%q принято", bad)
		}
	}
}

// Одноименные ключи из разных папок: и файл, и run получают одно значение -
// из последней папки, как его берет compose.
func TestDuplicateNamesResolveAlike(t *testing.T) {
	values := []value{{Name: "HOST", Path: "/", Value: "root"}, {Name: "HOST", Path: "/db", Value: "db"}}
	text, _ := renderEnv(append([]value(nil), values...))
	if strings.Count(text, "HOST=") != 1 || !strings.Contains(text, "HOST=db") {
		t.Fatalf("файл: %q", text)
	}
	env, err := withValues(nil, values)
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 1 || env[0] != "HOST=db" {
		t.Fatalf("run: %v", env)
	}
}

// 429 на входе машины - отказ ей, а не недоступность панели: копия значений
// отозванной машине не положена.
func TestTooManyIsARefusal(t *testing.T) {
	if unreachable(&panelError{code: http.StatusTooManyRequests}) {
		t.Fatal("429 принят за недоступность")
	}
}

// Второй экземпляр: config оставляет проект наверху, add записывает свой файл.
// Первый старт службы без -o не должен заменить эту запись умолчаниями -
// иначе два агента пишут /run/sekvyr/shop.env по очереди.
func TestNormalizeKeepsTheAddedApp(t *testing.T) {
	own := filepath.Join(t.TempDir(), "shop-stage.env")
	path := testConfig(t, App{Project: "shop", Env: "stage", Out: own, OnChange: "true"})
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Project, cfg.Env = "shop", "stage"
	if err := saveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	cfg, err = loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := normalize(path, cfg, nil); err != nil {
		t.Fatal(err)
	}
	apps := savedApps(t, path)
	if len(apps) != 1 || apps[0].Out != own || apps[0].OnChange != "true" {
		t.Fatalf("запись заменена: %+v", apps)
	}
}

// Права с префиксом 0o, как их принимал прежний разбор флага.
func TestModeAcceptsGoPrefix(t *testing.T) {
	mode, err := parseMode("0o440")
	if err != nil || mode != 0o440 {
		t.Fatalf("0o440 -> %o, %v", mode, err)
	}
}
