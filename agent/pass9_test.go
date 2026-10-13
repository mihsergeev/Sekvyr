package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Имена, на которых docker compose не читает env_file целиком, пропускаются,
// а не ломают файл; двоеточие тоже - compose резал бы по нему имя.
func TestRenderSkipsNamesComposeCannotRead(t *testing.T) {
	text, skipped := renderEnv([]value{
		{Name: "spring.datasource.url", Value: "1", Path: "/"},
		{Name: "smtp/host", Value: "2", Path: "/"},
		{Name: "a:b", Value: "3", Path: "/"},
		{Name: "ключ-1", Value: "4", Path: "/"},
	})
	if text != "spring.datasource.url=1\nключ-1=4\n" {
		t.Fatalf("got %q", text)
	}
	if got := strings.Join(skipped, ","); got != "a:b,smtp/host" && got != "smtp/host,a:b" {
		t.Fatalf("skipped %q", skipped)
	}
}

// Проект, однажды пришедший зашифрованным, открытым или с другим ключом
// больше не принимается: так подмененная панель подсунула бы свои значения.
func TestE2EProjectStaysEncrypted(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", t.TempDir())
	cfg := &Config{URL: "https://panel", Project: "shop", Env: "prod", path: filepath.Join(t.TempDir(), "agent.json")}
	if err := checkE2E(cfg, ""); err != nil {
		t.Fatalf("an ordinary project must pass: %v", err)
	}
	real := keyPrint([]byte("project-key-0123456789abcdef0123"))
	if err := checkE2E(cfg, real); err != nil {
		t.Fatal(err)
	}
	if err := checkE2E(cfg, real); err != nil {
		t.Fatalf("the same key must pass: %v", err)
	}
	if err := checkE2E(cfg, ""); err == nil {
		t.Fatal("an encrypted project answered as plain must be refused")
	}
	if err := checkE2E(cfg, keyPrint([]byte("panel-own-key-0123456789abcdef01"))); err == nil {
		t.Fatal("another project key must be refused")
	}
	// Другая панель с проектом-тезкой - своя отметка.
	other := *cfg
	other.URL = "https://new-panel"
	if err := checkE2E(&other, ""); err != nil {
		t.Fatalf("a namesake on another panel must pass: %v", err)
	}
	// Отметку удалил человек - действует сразу.
	if err := os.Remove(e2eMarker(cfg)); err != nil {
		t.Fatal(err)
	}
	if err := checkE2E(cfg, ""); err != nil {
		t.Fatalf("a removed mark must not refuse: %v", err)
	}
}

// Временный файл, брошенный оборванной записью, убирается следующей записью;
// свежий (чужая запись прямо сейчас) остается.
func TestWriteFileSweepsAbandonedTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shop.env")
	old := filepath.Join(dir, ".shop.env.123.tmp")
	fresh := filepath.Join(dir, ".shop.env.456.tmp")
	human := filepath.Join(dir, ".shop.env.local.tmp")
	for _, p := range []string{old, fresh, human} {
		if err := os.WriteFile(p, []byte("SECRET=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	long := time.Now().Add(-time.Hour)
	for _, p := range []string{old, human} {
		if err := os.Chtimes(p, long, long); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeFile(path, "A=1\n", 0o400); err != nil {
		t.Fatal(err)
	}
	if exists(old) {
		t.Fatal("the abandoned temp file is still there")
	}
	if !exists(fresh) {
		t.Fatal("a fresh temp file must stay")
	}
	if !exists(human) {
		t.Fatal("a file that is not ours must stay")
	}
}

// Конфиг только для чтения: привязка -o держится в памяти.
func TestBindAppsWithoutSaving(t *testing.T) {
	cfg := &Config{Apps: []App{{Project: "shop", Env: "prod"}}}
	changed, err := bindApps(cfg, "/secrets/.env", "", "400")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if cfg.Apps[0].Out != "/secrets/.env" || cfg.BoundOut != "/secrets/.env" {
		t.Fatalf("not bound: %+v", cfg)
	}
	again, err := bindApps(cfg, "/secrets/.env", "", "400")
	if err != nil || again {
		t.Fatalf("second bind: changed=%v err=%v", again, err)
	}
}

// Нулевой символ в значении для run - понятная ошибка с именем ключа.
func TestRunNamesTheKeyWithNUL(t *testing.T) {
	_, err := withValues(nil, []value{{Name: "BLOB", Value: "a\x00b", Path: "/"}})
	if err == nil || !strings.Contains(err.Error(), "BLOB") {
		t.Fatalf("got %v", err)
	}
}

// Без копии на диске - и без прежней копии.
func TestRemoveCacheDropsTheCopy(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", t.TempDir())
	cfg := &Config{Project: "shop", Env: "prod"}
	for _, p := range []string{cachePath(cfg), oldCachePath(cfg)} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	removeCache(cfg)
	if exists(cachePath(cfg)) {
		t.Fatal("the copy is still on disk")
	}
	// Копия под старым именем не раскрылась этим приложением: она может быть
	// чужой (shop-eu/prod против shop/eu-prod) и остается.
	if !exists(oldCachePath(cfg)) {
		t.Fatal("a copy that is not ours was removed")
	}
}
