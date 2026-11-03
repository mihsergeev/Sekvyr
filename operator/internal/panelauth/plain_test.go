package panelauth

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func plainResponse(value string) []byte {
	raw, _ := json.Marshal(map[string]any{"project": "app", "environment": "test", "e2e": false, "project_key": nil,
		"values": []map[string]string{{"name": "TOKEN", "path": "/runtime", "value": value}}})
	return raw
}

func TestPlainCompleteResponseAndValuesAlwaysRedacted(t *testing.T) {
	secret := "public-test-canary-value\x00e\u0301\n"
	snapshot, err := DecodePlainSnapshot(plainResponse(secret), "app", "test")
	if err != nil || !snapshot.Valid() || len(snapshot.Values()) != 1 || string(snapshot.Values()[0].Data()) != secret {
		t.Fatal("complete authenticated Plain response was not preserved")
	}
	for _, object := range []any{snapshot, *snapshot, snapshot.Values(), snapshot.Values()[0], &snapshot.Values()[0]} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, object), "public-test-canary-value") {
				t.Fatal("Plain value escaped through formatting")
			}
		}
	}
	copy := snapshot.Values()[0].Data()
	copy[0] = 'X'
	if string(snapshot.Values()[0].Data()) != secret || (&PlainSnapshot{}).Valid() || (*PlainSnapshot)(nil).Valid() {
		t.Fatal("Plain snapshot can be modified or fabricated with a zero value")
	}
}

func TestPlainStrictWireNeverAcceptsEncryptedOrAmbiguousResponse(t *testing.T) {
	good := string(plainResponse("public-test-value"))
	bad := []string{
		strings.Replace(good, `"e2e":false`, `"e2e":true`, 1),
		strings.Replace(good, `"project_key":null`, `"project_key":{}`, 1),
		strings.Replace(good, `"e2e":false,`, ``, 1),
		strings.Replace(good, `"e2e":false`, `"e2e":null`, 1),
		strings.Replace(good, `"project":"app"`, `"Project":"app"`, 1),
		strings.Replace(good, `"project":"app"`, `"project":"app","project":"app"`, 1),
		strings.Replace(good, `"project":"app"`, `"project":"other"`, 1),
		strings.Replace(good, `"name":"TOKEN"`, `"name":"TOKEN","unexpected":true`, 1),
		strings.Replace(good, `"path":"/runtime"`, `"path":"/runtime/../other"`, 1),
		strings.Replace(good, `"path":"/runtime"`, `"path":"/runtime/"`, 1),
		strings.Replace(good, `"name":"TOKEN"`, `"name":"e\u0301"`, 1),
		strings.Replace(good, `"value":"public-test-value"`, `"value":null`, 1),
		strings.Replace(good, `"value":"public-test-value"`, `"value":"\ud800"`, 1),
		strings.TrimSuffix(good, "}") + `,"unknown":true}`,
		good + `{}`,
	}
	for i, raw := range bad {
		if _, err := DecodePlainSnapshot([]byte(raw), "app", "test"); err == nil {
			t.Fatalf("invalid Plain response accepted: case %d", i)
		}
	}
	if _, err := DecodePlainSnapshot([]byte(`{"project":"app","environment":"test","values":null,"e2e":false,"project_key":null}`), "app", "test"); err == nil {
		t.Fatal("null list can clear a target")
	}
	if _, err := DecodePlainSnapshot([]byte(`{"project":"app","environment":"test","values":[],"e2e":false,"project_key":null}`), "app", "test"); err != nil {
		t.Fatal("an explicit complete empty list should reach the binding allowEmpty gate")
	}
}

func TestPlainDuplicateTuplesAndSourceBounds(t *testing.T) {
	var response map[string]any
	_ = json.Unmarshal(plainResponse("canary"), &response)
	row := map[string]string{"name": "TOKEN", "path": "/runtime", "value": "public"}
	response["values"] = []any{row, row}
	raw, _ := json.Marshal(response)
	if _, err := DecodePlainSnapshot(raw, "app", "test"); err == nil {
		t.Fatal("duplicate source tuple accepted")
	}
	response["values"] = make([]any, 1025)
	raw, _ = json.Marshal(response)
	if _, err := DecodePlainSnapshot(raw, "app", "test"); err == nil {
		t.Fatal("source entry bound not enforced")
	}
	if _, err := DecodePlainSnapshot(plainResponse(strings.Repeat("x", (8<<20)+1)), "app", "test"); err == nil {
		t.Fatal("decoded source bound not enforced")
	}
}

func TestPlainEndpointPinnedSessionAndScopeErrorsDoNotLeakBody(t *testing.T) {
	requests, code := 0, 200
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests++
		if req.URL.Path != "/api/v1/machine/secrets" || req.URL.Query().Get("project") != "app" || req.URL.Query().Get("env") != "test" || req.URL.Query().Get("group") != "team" || req.Header.Get("Authorization") != "Bearer synthetic-session" {
			t.Error("Plain request escaped its exact route, query or session")
		}
		w.WriteHeader(code)
		if code != 200 {
			_, _ = w.Write([]byte("public-test-sensitive-upstream-body"))
			return
		}
		_, _ = w.Write(plainResponse("canary"))
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := New(Config{Origin: server.URL, AllowedOrigins: []string{server.URL}, TokenFile: "unused", Namespace: "apps", ServiceAccount: "operator", Audience: "sekvyr", CustomCAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session := Session{token: "synthetic-session", origin: server.URL, ExpiresAt: time.Now().Add(time.Hour)}
	if _, err = client.PlainSecrets(context.Background(), session, "team", "app", "test"); err != nil {
		t.Fatal(err)
	}
	before := requests
	if _, err = client.PlainSecrets(context.Background(), session, "team&scope=other", "app", "test"); err == nil || requests != before {
		t.Fatal("query injection reached transport")
	}
	for _, status := range []int{401, 403, 404, 409, 429, 503} {
		code = status
		if _, err = client.PlainSecrets(context.Background(), session, "team", "app", "test"); err == nil || strings.Contains(err.Error(), "sensitive-upstream") {
			t.Fatal("upstream denial was hidden or exposed")
		}
	}
}
