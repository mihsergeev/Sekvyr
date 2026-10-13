package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testConfig - конфиг агента во временном каталоге с заданными приложениями.
func testConfig(t *testing.T, apps ...App) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.json")
	cfg := Config{URL: "https://panel.example", ClientID: "id", ClientSecret: "secret", Apps: apps}
	if err := saveConfig(path, &cfg); err != nil {
		t.Fatal(err)
	}
	return path
}

func savedApps(t *testing.T, path string) []App {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Apps
}

func TestSameNeedsGroup(t *testing.T) {
	a := App{Group: "globex", Project: "frontend", Env: "prod"}
	if !a.same(App{Group: "globex", Project: "frontend", Env: "prod"}) {
		t.Fatal("одно и то же приложение не узнано")
	}
	if a.same(App{Group: "initech", Project: "frontend", Env: "prod"}) {
		t.Fatal("одноименные проекты разных групп приняты за одно приложение")
	}
	if a.same(App{Group: "globex", Project: "frontend", Env: "stage"}) {
		t.Fatal("разные окружения приняты за одно приложение")
	}
}

// Второе окружение того же проекта по умолчанию попало бы в тот же файл, и
// окружения затирали бы его друг другу каждую минуту.
func TestAddRefusesSharedFile(t *testing.T) {
	path := testConfig(t, App{Project: "shop", Env: "prod"})
	err := cmdAdd([]string{"--config", path, "shop/stage"})
	if err == nil || !strings.Contains(err.Error(), "/run/sekvyr/shop.env") {
		t.Fatalf("ожидали отказ с именем файла, получили %v", err)
	}
	if apps := savedApps(t, path); len(apps) != 1 {
		t.Fatalf("после отказа конфиг изменился: %+v", apps)
	}

	// Со своим файлом второе окружение заводится рядом с первым.
	own := filepath.Join(t.TempDir(), "shop-stage.env")
	if err := cmdAdd([]string{"--config", path, "shop/stage", "-o", own, "--on-change", "true"}); err != nil {
		t.Fatal(err)
	}
	if apps := savedApps(t, path); len(apps) != 2 {
		t.Fatalf("ожидали два приложения, получили %+v", apps)
	}
}

// Повторный add того же приложения - правка, а не конфликт с самим собой.
func TestAddUpdatesItself(t *testing.T) {
	path := testConfig(t, App{Project: "shop", Env: "prod"})
	if err := cmdAdd([]string{"--config", path, "shop/prod", "--on-change", "true"}); err != nil {
		t.Fatal(err)
	}
	apps := savedApps(t, path)
	if len(apps) != 1 || apps[0].OnChange != "true" {
		t.Fatalf("правка не легла: %+v", apps)
	}
}

// Установщик зовет add сразу после enroll: та же запись - не правка.
func TestAddSameIsNoop(t *testing.T) {
	app := App{Project: "shop", Env: "prod"}.defaults()
	path := testConfig(t, app)
	before, _ := os.ReadFile(path)
	if err := cmdAdd([]string{"--config", path, "shop/prod"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatalf("конфиг переписан без изменений:\n%s\n---\n%s", before, after)
	}
}

// Раньше add второго проекта с тем же именем из другой группы молча заменял
// первый, а rm одного удалял оба.
func TestGroupsStayApart(t *testing.T) {
	dir := t.TempDir()
	path := testConfig(t, App{Group: "globex", Project: "frontend", Env: "prod", Out: filepath.Join(dir, "globex.env")})
	if err := cmdAdd([]string{"--config", path, "initech/frontend/prod", "-o", filepath.Join(dir, "initech.env"), "--on-change", "true"}); err != nil {
		t.Fatal(err)
	}
	if apps := savedApps(t, path); len(apps) != 2 {
		t.Fatalf("второй проект заменил первый: %+v", apps)
	}
	if err := cmdRemove([]string{"--config", path, "--keep-file", "initech/frontend/prod"}); err != nil {
		t.Fatal(err)
	}
	apps := savedApps(t, path)
	if len(apps) != 1 || apps[0].Group != "globex" {
		t.Fatalf("rm задел чужую группу: %+v", apps)
	}
}

// Конфиг со старых версий мог держать два приложения на одном файле. Убирая
// лишнее, rm не должен удалять файл, который пишет оставшееся.
func TestRemoveKeepsSharedFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "shop.env")
	if err := os.WriteFile(file, []byte("A=1\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	path := testConfig(t,
		App{Project: "shop", Env: "prod", Out: file},
		App{Project: "shop", Env: "stage", Out: file},
	)
	if err := cmdRemove([]string{"--config", path, "shop/stage"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("rm удалил файл, который пишет shop/prod: %v", err)
	}
	if err := cmdRemove([]string{"--config", path, "shop/prod"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("файл последнего приложения остался: %v", err)
	}
}

func TestSplitSharedKeepsTheFirst(t *testing.T) {
	list := []App{
		{Project: "shop", Env: "prod", Out: "/run/sekvyr/shop.env"},
		{Project: "shop", Env: "stage", Out: "/run/sekvyr/shop.env"},
		{Project: "blog", Env: "prod", Out: "/run/sekvyr/blog.env"},
	}
	kept, clashes := splitShared(list)
	if len(kept) != 2 || kept[0].Env != "prod" || kept[1].Project != "blog" {
		t.Fatalf("не то оставлено: %+v", kept)
	}
	if len(clashes) != 1 || !strings.Contains(clashes[0], "shop/stage") {
		t.Fatalf("про пропущенное не сказано: %v", clashes)
	}
}

func TestCachePathHasGroup(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", t.TempDir())
	plain := cachePath(&Config{Project: "frontend", Env: "prod"})
	globex := cachePath(&Config{Group: "globex", Project: "frontend", Env: "prod"})
	initech := cachePath(&Config{Group: "initech", Project: "frontend", Env: "prod"})
	if globex == initech || globex == plain {
		t.Fatalf("у разных приложений общая копия: %s %s %s", plain, globex, initech)
	}
	// Склейка дефисом давала одно имя для shop-eu/prod и shop/eu-prod.
	if cachePath(&Config{Project: "shop-eu", Env: "prod"}) == cachePath(&Config{Project: "shop", Env: "eu-prod"}) {
		t.Fatal("shop-eu/prod и shop/eu-prod делят копию")
	}
	// Прежнее имя помнится: копии уже стоящих нод читаются, пока новая не
	// записана.
	if filepath.Base(oldCachePath(&Config{Project: "frontend", Env: "prod"})) != "cache-frontend-prod.bin" {
		t.Fatal("прежнее имя копии забыто")
	}
}
