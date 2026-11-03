package panelauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func projectedToken(t *testing.T, override func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss": "https://kubernetes.example.com", "sub": "system:serviceaccount:apps:sekvyr-operator",
		"aud": []string{"sekvyr"}, "exp": time.Now().Add(time.Hour).Unix(),
		"kubernetes.io": map[string]any{"namespace": "apps", "serviceaccount": map[string]any{"name": "sekvyr-operator", "uid": "test-serviceaccount"}, "pod": map[string]any{"uid": "test-pod"}},
	}
	if override != nil {
		override(claims)
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately not a valid signature. Only the real panel authenticates JWTs.
	return "test-header." + base64.RawURLEncoding.EncodeToString(raw) + ".synthetic-not-a-signature"
}

func clientFor(t *testing.T, handler http.HandlerFunc) (*Client, string, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(projectedToken(t, nil)), 0600); err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	c, err := New(Config{Origin: server.URL, AllowedOrigins: []string{server.URL}, TokenFile: path, Namespace: "apps", ServiceAccount: "sekvyr-operator", Audience: "sekvyr", CustomCAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, path, server
}

func requireReason(t *testing.T, err error, reason string) {
	t.Helper()
	var safe *Error
	if !errors.As(err, &safe) || safe.Reason != reason {
		t.Fatalf("expected %s, got %v", reason, err)
	}
}

func TestProjectedRotationAndReadOnlyIdentity(t *testing.T) {
	var received []string
	c, path, _ := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/machine/token":
			if r.Method != "POST" || r.Header.Get("Authorization") != "" {
				t.Error("unexpected token request")
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if len(body) != 1 || body["kubernetes_token"] == "" {
				t.Error("wrong credential shape")
			}
			received = append(received, body["kubernetes_token"])
			fmt.Fprint(w, `{"access_token":"synthetic-test-session","token_type":"Bearer","expires_in":300,"name":"test identity"}`)
		case "/api/v1/machine/whoami":
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer synthetic-test-session" {
				t.Error("wrong session")
			}
			fmt.Fprint(w, `{"name":"test identity","client_id":"test-only","environments":[],"expires_at":""}`)
		default:
			t.Error("unexpected endpoint")
			w.WriteHeader(404)
		}
	})
	session, err := c.Login(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = c.CheckIdentity(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	rotated := projectedToken(t, func(c map[string]any) { c["exp"] = time.Now().Add(2 * time.Hour).Unix() })
	if err = os.WriteFile(path, []byte(rotated), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(received) != 2 || received[0] == received[1] || received[1] != rotated {
		t.Fatal("projected token rotation was not observed")
	}
	for _, rendered := range []string{fmt.Sprintf("%v", session), fmt.Sprintf("%+v", session), fmt.Sprintf("%#v", session)} {
		if strings.Contains(rendered, "synthetic-test-session") {
			t.Fatal("session leaked")
		}
	}
	serialized, _ := json.Marshal(session)
	if strings.Contains(string(serialized), "synthetic-test-session") {
		t.Fatal("JSON leaked session")
	}
}

func TestDeniedIdentityNeverSent(t *testing.T) {
	var hits atomic.Int32
	c, path, _ := clientFor(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(500) })
	for name, override := range map[string]func(map[string]any){
		"namespace":          func(c map[string]any) { c["sub"] = "system:serviceaccount:other:sekvyr-operator" },
		"audience":           func(c map[string]any) { c["aud"] = []string{"kubernetes"} },
		"multiple audiences": func(c map[string]any) { c["aud"] = []string{"sekvyr", "kubernetes"} },
		"missing pod":        func(c map[string]any) { delete(c["kubernetes.io"].(map[string]any), "pod") },
		"not before":         func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			os.WriteFile(path, []byte(projectedToken(t, override)), 0600)
			if _, err := c.Login(context.Background()); err == nil {
				t.Fatal("wrong identity accepted")
			}
		})
	}
	os.WriteFile(path, []byte(projectedToken(t, func(c map[string]any) { c["exp"] = 1 })), 0600)
	_, err := c.Login(context.Background())
	requireReason(t, err, "ProjectedTokenExpired")
	os.WriteFile(path, []byte(strings.Repeat("x", maxTokenBytes+1)), 0600)
	_, err = c.Login(context.Background())
	requireReason(t, err, "ProjectedTokenInvalid")
	if hits.Load() != 0 {
		t.Fatal("wrong credentials reached network")
	}
}

func TestRedirectsNeverForwardCredentials(t *testing.T) {
	var hits atomic.Int32
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer sink.Close()
	c, _, _ := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+"/stolen", http.StatusTemporaryRedirect)
	})
	_, err := c.Login(context.Background())
	requireReason(t, err, "RedirectDenied")
	if hits.Load() != 0 {
		t.Fatal("redirect leaked projected token")
	}
}

func TestResponsesAreBoundedStrictAndSanitized(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate":        `{"access_token":"a","access_token":"b","token_type":"Bearer","expires_in":300}`,
		"unknown":          `{"access_token":"a","token_type":"Bearer","expires_in":300,"other":true}`,
		"trailing":         `{"access_token":"a","token_type":"Bearer","expires_in":300} {}`,
		"oversized":        strings.Repeat("x", maxResponseBytes+1),
		"too long expiry":  `{"access_token":"a","token_type":"Bearer","expires_in":86400}`,
		"header injection": `{"access_token":"a\r\nb","token_type":"Bearer","expires_in":300}`,
	} {
		t.Run(name, func(t *testing.T) {
			c, _, _ := clientFor(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, raw) })
			_, err := c.Login(context.Background())
			requireReason(t, err, "ResponseInvalid")
		})
	}
	for code, reason := range map[int]string{401: "AuthenticationDenied", 403: "AccessDenied", 429: "RateLimited", 503: "PanelUnavailable"} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			c, _, _ := clientFor(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code); fmt.Fprint(w, "PRIVATE-SENTINEL") })
			_, err := c.Login(context.Background())
			requireReason(t, err, reason)
			if strings.Contains(err.Error(), "PRIVATE-SENTINEL") {
				t.Fatal("upstream body leaked")
			}
		})
	}
}

func TestTLSVerificationCancellationAndOrigins(t *testing.T) {
	c, _, server := clientFor(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{}`) })
	wrong, err := New(Config{Origin: server.URL, AllowedOrigins: []string{server.URL}, TokenFile: c.tokenFile, Namespace: "apps", ServiceAccount: "sekvyr-operator", Audience: "sekvyr"})
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	_, err = wrong.Login(context.Background())
	requireReason(t, err, "PanelUnavailable")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.Login(ctx)
	requireReason(t, err, "PanelUnavailable")
	for _, raw := range []string{"http://panel.example.com", "https://user:password@panel.example.com", "https://panel.example.com/path", "https://panel.example.com?secret=a", "https://panel.example.com#fragment", "https://panel.example.com.", "https://panel.example.com:", "https://panel.example.com:0", "https://panel.example.com/%2f", "https://panel.example.com\\evil"} {
		if _, err := CanonicalOrigin(raw); err == nil {
			t.Errorf("unsafe origin accepted: %s", raw)
		}
	}
	for raw, want := range map[string]string{"https://PANEL.example.com:443/": "https://panel.example.com", "https://panel.example.com:8443": "https://panel.example.com:8443"} {
		got, err := CanonicalOrigin(raw)
		if err != nil || got != want {
			t.Errorf("origin normalization failed %s", raw)
		}
	}
	_, err = New(Config{Origin: server.URL, AllowedOrigins: []string{"https://panel.example.com"}})
	requireReason(t, err, "OriginDenied")
}

func TestDuplicateKeysRejectedAtEveryDepth(t *testing.T) {
	for _, raw := range []string{`{"x":{"y":1,"y":2}}`, `[{"x":1,"x":2}]`, `{} {}`, `{"x":1,}`, `[]x`} {
		if decodeNoDuplicates([]byte(raw)) == nil {
			t.Errorf("invalid JSON accepted")
		}
	}
	if err := decodeNoDuplicates([]byte(`{"x":[1,true,null,{"y":"text"}]}`)); err != nil {
		t.Fatal(err)
	}
}
