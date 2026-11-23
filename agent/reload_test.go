package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestAgentReloadFailureDoesNotReuseStartupConfig(t *testing.T) {
	const childConfig = "SEKVYR_TEST_AGENT_RELOAD_CONFIG"
	if path := os.Getenv(childConfig); path != "" {
		if err := cmdAgent([]string{"--config", path, "--interval", "30ms", "--no-cache", "--no-update"}); err != nil {
			t.Fatal(err)
		}
		return
	}

	var startupRequests atomic.Int32
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/machine/token":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if body["client_secret"] == "startup" {
				startupRequests.Add(1)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": body["client_secret"]})
		case "/api/v1/machine/secrets":
			_ = json.NewEncoder(w).Encode(secretsResponse{Project: "sample", Environment: "test",
				Values: []value{{Name: "PROBE", Value: strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")}}})
		case "/api/v1/machine/report":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer panel.Close()
	dir := t.TempDir()
	path, output, log := filepath.Join(dir, "agent.json"), filepath.Join(dir, "app.env"), filepath.Join(dir, "agent.log")
	cfg := &Config{URL: panel.URL, ClientID: "fixture", ClientSecret: "startup",
		Apps: []App{{Project: "sample", Env: "test", Out: output, OnChange: noHook, Mode: "0400"}}}
	if err := saveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	stderr, err := os.Create(log)
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestAgentReloadFailureDoesNotReuseStartupConfig$")
	child.Env = append(os.Environ(), childConfig+"="+path, "STATE_DIRECTORY="+dir, "SEKVYR_LANG=en")
	child.Stderr = stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Signal(syscall.SIGTERM)
		_ = child.Wait()
	}()
	wait := func(file, want string, count int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if data, _ := os.ReadFile(file); strings.Count(string(data), want) >= count {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("agent did not produce %q", want)
	}
	wait(output, "PROBE=startup", 1)
	cfg.ClientSecret = "current"
	if err := saveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	wait(output, "PROBE=current", 1)
	before := startupRequests.Load()
	if err := writeFile(path, "{", 0o600); err != nil {
		t.Fatal(err)
	}
	wait(log, "could not re-read the config", 3)
	if got := startupRequests.Load(); got != before {
		t.Fatal("agent reused startup credentials after reload failure")
	}
	if data, err := os.ReadFile(output); err != nil || !strings.Contains(string(data), "PROBE=current") {
		t.Fatal("agent changed the last applied file while configuration was invalid")
	}
	cfg.ClientSecret = "recovered"
	if err := saveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	wait(output, "PROBE=recovered", 1)
}
