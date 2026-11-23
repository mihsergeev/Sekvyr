package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateCanRetryFailedRestart(t *testing.T) {
	m, _ := signedManifest(t)
	old := Version
	Version = m.Version
	t.Cleanup(func() { Version = old })
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/machine/agent/manifest" {
			t.Errorf("unexpected update request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(m)
	}))
	t.Cleanup(panel.Close)
	dir := t.TempDir()
	config := filepath.Join(dir, "agent.json")
	if err := saveConfig(config, &Config{URL: panel.URL, ClientID: "fixture", ClientSecret: "fixture"}); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "systemctl.log")
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$SEKVYR_TEST_SYSTEMCTL_LOG\"\nexit \"$SEKVYR_TEST_SYSTEMCTL_STATUS\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SEKVYR_TEST_SYSTEMCTL_LOG", log)
	t.Setenv("SEKVYR_TEST_SYSTEMCTL_STATUS", "1")
	args := []string{"--config", config, "--restart", "sample.service"}
	if err := cmdUpdate(append(args, "--check")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatalf("check-only update tried to restart the service: %v", err)
	}
	if err := cmdUpdate(args); err == nil {
		t.Fatal("updater reported success even though the requested restart did not succeed")
	}
	t.Setenv("SEKVYR_TEST_SYSTEMCTL_STATUS", "0")
	if err := cmdUpdate(args); err != nil {
		t.Fatalf("retrying the restart failed: %v", err)
	}
	if data, err := os.ReadFile(log); err != nil || string(data) != "restart\n--\nsample.service\nrestart\n--\nsample.service\n" {
		t.Fatalf("expected two restarts of the requested unit, got %q, %v", data, err)
	}
}

// Обновление вперед - можно, назад - нет. Подпись у старой версии настоящая, и
// без этой проверки захваченная панель вернула бы ноды на версию с известной
// дырой, ничего не подделывая.
func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.27.0", "0.26.0", true},
		{"0.26.0", "0.26.0", false},
		{"0.25.0", "0.26.0", false},
		// Как строки "0.9.0" больше "0.10.0" - потому и сравниваем числами.
		{"0.10.0", "0.9.0", true},
		{"0.9.0", "0.10.0", false},
		{"1.0.0", "0.99.99", true},
		// Разной длины: "0.26" и "0.26.0" - одно и то же.
		{"0.26", "0.26.0", false},
		{"0.26.1", "0.26", true},
		// Непонятную версию считаем не новее: агент скорее не обновится, чем
		// поставит неизвестно что.
		{"dev", "0.26.0", false},
		{"0.26.0", "dev", false},
		{"", "0.26.0", false},
		{"0.26.0-rc1", "0.26.0", false},
		// Предвыпуск раньше выпуска той же версии, как в ops/update.sh: нода на
		// rc должна сама дойти до выпуска, а не просить --allow-downgrade.
		{"1.1.0", "1.1.0-rc1", true},
		{"1.1.0-rc2", "1.1.0-rc1", true},
		{"1.1.0-rc1", "1.1.0-rc2", false},
		{"1.1.0-rc10", "1.1.0-rc9", true},
		{"1.1.0-rc1", "1.1.0-rc1", false},
		{"1.1.0-rc1", "1.0.9", true},
		{"1.0.9", "1.1.0-rc1", false},
		// Метаданные сборки на порядок не влияют.
		{"1.1.0+abc", "1.1.0", false},
	}
	for _, c := range cases {
		if got := newer(c.a, c.b); got != c.want {
			t.Errorf("newer(%q, %q) = %v, ожидалось %v", c.a, c.b, got, c.want)
		}
	}
}

func TestInstallUpdateRejectsOtherProcessesOnOldBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sekvyr")
	if err := os.WriteFile(path, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	running, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	const processes = 16
	start := make(chan struct{})
	installed := make(chan string, processes)
	for n := range processes {
		go func() {
			candidate := fmt.Sprintf("verified candidate %d", n)
			<-start
			if installUpdate(path, running, []byte(candidate)) != nil {
				candidate = ""
			}
			installed <- candidate
		}()
	}
	close(start)
	var winner string
	for range processes {
		if candidate := <-installed; candidate != "" {
			if winner != "" {
				t.Fatalf("another process on the old binary also replaced it: %s", candidate)
			}
			winner = candidate
		}
	}
	if data, err := os.ReadFile(path); err != nil || winner == "" || string(data) != winner {
		t.Fatalf("installed file did not match the winning candidate: %q, %v", data, err)
	}
	current, err := os.Stat(path)
	if err != nil || current.Mode().Perm() != 0o755 {
		t.Fatalf("installed binary is not executable: %v, %v", current, err)
	}
	if err := installUpdate(path, current, []byte("next verified candidate")); err != nil {
		t.Fatal(err)
	}
}
