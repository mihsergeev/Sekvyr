package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakePanel отвечает на вход машины, отказывает в значениях (e2e-проекту
// ключ еще не выдан) и запоминает, присылал ли агент ключ ноды.
func fakePanel(t *testing.T) (*httptest.Server, func() bool) {
	t.Helper()
	var mu sync.Mutex
	gotKey := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/machine/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case "/api/v1/machine/report":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			gotKey = gotKey || body["public_key"] != ""
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Ключ проекта этой машине не выдан"})
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotKey
	}
}

func renderConfig(t *testing.T, url string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.json")
	cfg := Config{URL: url, ClientID: "id", ClientSecret: "secret", Apps: []App{{Project: "shop", Env: "prod"}}}
	if err := saveConfig(path, &cfg); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRenderKeepsItsOwnCopyDuringPanelOutage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SEKVYR_NODE_KEY", filepath.Join(dir, "node.key"))
	t.Setenv("STATE_DIRECTORY", dir)
	var status atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failure := status.Load(); failure != 0 {
			w.WriteHeader(int(failure))
			return
		}
		switch r.URL.Path {
		case "/api/v1/machine/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "fixture"})
		case "/api/v1/machine/secrets":
			_ = json.NewEncoder(w).Encode(secretsResponse{Project: "shop", Environment: "prod",
				Values: []value{{Name: "PROBE", Value: "synthetic", Path: "/"}}})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer second.Close()

	config := renderConfig(t, first.URL)
	file := filepath.Join(dir, "app.env")
	args := []string{"--config", config, "-o", file}
	if err := cmdRender(args); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	status.Store(http.StatusServiceUnavailable)
	if err := cmdRender(args); err != nil {
		t.Fatal(err)
	}
	if rendered, err := os.ReadFile(file); err != nil || string(rendered) != "PROBE=synthetic\n" {
		t.Fatal("render did not restore its cached file", err)
	}
	otherFile := filepath.Join(dir, "other.env")
	if err := cmdRender([]string{"--config", renderConfig(t, second.URL), "-o", otherFile}); err == nil || exists(otherFile) {
		t.Fatal("render used another panel's copy")
	}
	status.Store(http.StatusForbidden)
	if err := cmdRender(append(args, "--no-cache")); err == nil {
		t.Fatal("render succeeded after an explicit access denial")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	status.Store(http.StatusServiceUnavailable)
	if err := cmdRender(args); err == nil || exists(file) {
		t.Fatal("outage resurrected a cache after access was denied")
	}
}

func TestRenderHonorsStatusWithUnreadableResponseBody(t *testing.T) {
	for _, tt := range []struct {
		name, path string
		code       int
		oversized  bool
	}{
		{"truncated token refusal", "/api/v1/machine/token", http.StatusForbidden, false},
		{"truncated environment ambiguity", "/api/v1/machine/secrets", http.StatusBadRequest, false},
		{"oversized secrets refusal", "/api/v1/machine/secrets", http.StatusForbidden, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("STATE_DIRECTORY", dir)
			t.Setenv("SEKVYR_NODE_KEY", filepath.Join(dir, "node.key"))
			var stage atomic.Int32
			panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if stage.Load() == 2 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				if stage.Load() == 1 && r.URL.Path == tt.path {
					w.Header().Set("Content-Length", "50000000")
					w.WriteHeader(tt.code)
					if tt.oversized {
						chunk := strings.Repeat("!", 1<<20)
						for i := 0; i <= maxBody/len(chunk); i++ {
							if _, err := io.WriteString(w, chunk); err != nil {
								break
							}
						}
					} else {
						_, _ = io.WriteString(w, "interrupted")
					}
					return
				}
				switch r.URL.Path {
				case "/api/v1/machine/token":
					_, _ = io.WriteString(w, `{"access_token":"fixture"}`)
				case "/api/v1/machine/secrets":
					_, _ = io.WriteString(w, `{"project":"shop","environment":"prod","values":[{"name":"PROBE","path":"/","value":"fixture"}]}`)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer panel.Close()
			file := filepath.Join(dir, "app.env")
			args := []string{"--config", renderConfig(t, panel.URL), "-o", file}
			if err := cmdRender(args); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}
			stage.Store(1)
			var refused *panelError
			if err := cmdRender(args); !errors.As(err, &refused) || refused.code != tt.code || exists(file) {
				t.Fatalf("refusal lost its status or restored a file: %v", err)
			}
			stage.Store(2)
			if err := cmdRender(args); err == nil || exists(file) {
				t.Fatal("outage restored a cache after access was refused")
			}
		})
	}
}

func TestRenderRejectsIncompleteOrMisdirectedSuccess(t *testing.T) {
	for _, tt := range []struct {
		name, token, response string
	}{
		{"empty token", `{}`, `{"project":"shop","environment":"prod","values":[]}`},
		{"invalid token header", `{"access_token":"a\nb"}`, `{"project":"shop","environment":"prod","values":[]}`},
		{"missing values", "", `{"project":"shop","environment":"prod"}`},
		{"missing secret value", "", `{"project":"shop","environment":"prod","values":[{"name":"PROBE","path":"/"}]}`},
		{"null secret entry", "", `{"project":"shop","environment":"prod","values":[null]}`},
		{"null response", "", `null`},
		{"wrong environment", "", `{"project":"shop","environment":"stage","values":[]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("STATE_DIRECTORY", dir)
			t.Setenv("SEKVYR_NODE_KEY", filepath.Join(dir, "node.key"))
			var mode atomic.Int32
			var secretsCalls atomic.Int32
			panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/machine/token":
					if mode.Load() == 1 && tt.token != "" {
						_, _ = io.WriteString(w, tt.token)
						return
					}
					_, _ = io.WriteString(w, `{"access_token":"fixture"}`)
				case "/api/v1/machine/secrets":
					secretsCalls.Add(1)
					responses := []string{`{"project":"shop","environment":"prod","values":[{"name":"PROBE","path":"/","value":"fixture"}]}`, tt.response, `{"project":"shop","environment":"prod","values":[]}`}
					_, _ = io.WriteString(w, responses[mode.Load()])
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer panel.Close()
			file := filepath.Join(dir, "app.env")
			args := []string{"--config", renderConfig(t, panel.URL), "-o", file}
			if err := cmdRender(args); err != nil {
				t.Fatal(err)
			}
			mode.Store(1)
			if err := cmdRender(args); err == nil {
				t.Fatal("malformed response succeeded")
			}
			if tt.token != "" && secretsCalls.Load() != 1 {
				t.Fatal("requested values without a valid token")
			}
			if current, err := os.ReadFile(file); err != nil || string(current) != "PROBE=fixture\n" {
				t.Fatalf("malformed response changed the applied file: %v", err)
			}
			mode.Store(2)
			if err := cmdRender(args); err != nil {
				t.Fatalf("valid empty environment was rejected: %v", err)
			}
			if info, err := os.Stat(file); err != nil || info.Size() != 0 {
				t.Fatalf("valid empty environment did not clear the file: %v", err)
			}
		})
	}
}

// init-контейнер render в Kubernetes с общим ключом (SEKVYR_NODE_KEY) шлет
// ключ ноды и при отказе: иначе ключ e2e-проекта нельзя выдать никогда.
func TestRenderReportsSharedKey(t *testing.T) {
	srv, gotKey := fakePanel(t)
	t.Setenv("SEKVYR_NODE_KEY", filepath.Join(t.TempDir(), "node.key"))
	t.Setenv("STATE_DIRECTORY", t.TempDir())
	config := renderConfig(t, srv.URL)
	// Общий ключ лежит заранее (в Kubernetes - Secret).
	if _, err := nodePublicKey(config); err != nil {
		t.Fatal(err)
	}
	if err := cmdRender([]string{"--config", config, "--no-cache"}); err == nil {
		t.Fatal("render без значений прошел")
	}
	if !gotKey() {
		t.Fatal("ключ ноды не отправлен")
	}
}

// Переменная задана, а файла по ней нет: render не заводит новый ключ и не
// шлет его - панель сменила бы ключ машины.
func TestRenderDoesNotMintSharedKey(t *testing.T) {
	srv, gotKey := fakePanel(t)
	t.Setenv("SEKVYR_NODE_KEY", filepath.Join(t.TempDir(), "node.key"))
	t.Setenv("STATE_DIRECTORY", t.TempDir())
	if err := cmdRender([]string{"--config", renderConfig(t, srv.URL), "--no-cache"}); err == nil {
		t.Fatal("render без значений прошел")
	}
	if gotKey() {
		t.Fatal("отправлен только что созданный ключ")
	}
}

// Без явного общего ключа render ключ не шлет: случайный каталог состояния
// дал бы другой ключ, и панель сняла бы обертки машины.
func TestRenderKeepsLocalKeyToItself(t *testing.T) {
	srv, gotKey := fakePanel(t)
	t.Setenv("SEKVYR_NODE_KEY", "")
	t.Setenv("STATE_DIRECTORY", t.TempDir())
	if err := cmdRender([]string{"--config", renderConfig(t, srv.URL), "--no-cache"}); err == nil {
		t.Fatal("render без значений прошел")
	}
	if gotKey() {
		t.Fatal("отправлен ключ из случайного каталога")
	}
}

// Ключа по общему пути нет, а панель прислала e2e-обертку: раскрытие само
// заводит ключ ноды по этому пути. Отправлять его нельзя - решение о том,
// лежал ли ключ, принимается до получения значений.
func TestRenderDoesNotSendKeyMintedByUnwrap(t *testing.T) {
	var mu sync.Mutex
	gotKey := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/machine/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case "/api/v1/machine/report":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			gotKey = gotKey || body["public_key"] != ""
			mu.Unlock()
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project": "shop", "environment": "prod", "e2e": true,
				"values":      []map[string]string{{"name": "A", "path": "/", "value": "e2e:v1:AAAA"}},
				"project_key": map[string]string{"nonce": "AAAA", "wrapped_key": "AAAA", "ephemeral_public": "AAAA"},
			})
		}
	}))
	defer srv.Close()
	t.Setenv("SEKVYR_NODE_KEY", filepath.Join(t.TempDir(), "node.key"))
	t.Setenv("STATE_DIRECTORY", t.TempDir())
	if err := cmdRender([]string{"--config", renderConfig(t, srv.URL), "--no-cache"}); err == nil {
		t.Fatal("render с непригодной оберткой прошел")
	}
	mu.Lock()
	defer mu.Unlock()
	if gotKey {
		t.Fatal("отправлен ключ, заведенный раскрытием обертки")
	}
}
