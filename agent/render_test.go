package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
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
