package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPanelCredentialsStayOnConfiguredOrigin(t *testing.T) {
	var forwarded atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Store(true)
		w.Write([]byte(`{"access_token":"fixture"}`))
	}))
	defer destination.Close()
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer panel.Close()

	_, tokenErr := token(&Config{URL: panel.URL, ClientID: "fixture-id", ClientSecret: "fixture-only"})
	bearerErr := get(panel.URL, "fixture-bearer", nil)
	if forwarded.Load() {
		t.Error("cross-origin redirect forwarded a credential-bearing request")
	}
	if tokenErr == nil || bearerErr == nil || unreachable(tokenErr) || unreachable(bearerErr) {
		t.Error("cross-origin redirect must be rejected without cached secrets")
	}
}

func TestPanelSameOriginRedirectPreservesRequest(t *testing.T) {
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/machine/token" {
			http.Redirect(w, r, "/canonical/token", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path != "/canonical/token" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Write([]byte(`{"access_token":"fixture"}`))
	}))
	defer panel.Close()

	access, err := token(&Config{URL: panel.URL, ClientID: "fixture-id", ClientSecret: "fixture-only"})
	if err != nil || access != "fixture" {
		t.Fatalf("same-origin request failed: %v", err)
	}
}
