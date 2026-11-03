package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
)

func testScope() e2e2.Scope {
	return e2e2.Scope{RealmID: "10000000-0000-4000-8000-000000000001", ProjectID: "10000000-0000-4000-8000-000000000002", EnvironmentID: "10000000-0000-4000-8000-000000000003", ViewID: "10000000-0000-4000-8000-000000000004", LogID: "10000000-0000-4000-8000-000000000005"}
}
func ca(server *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
}
func safeError(t *testing.T, err error) {
	t.Helper()
	var safe *Error
	if !errors.As(err, &safe) {
		t.Fatal("missing sanitized transport refusal")
	}
	if strings.Contains(err.Error(), "private-upstream") || strings.Contains(err.Error(), "Bearer") {
		t.Fatal("upstream body or credential leaked")
	}
}
func credential(t *testing.T) (string, string) {
	t.Helper()
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		t.Fatal("random failed")
	}
	token := base64.RawURLEncoding.EncodeToString(key)
	file := filepath.Join(t.TempDir(), "credential")
	if os.WriteFile(file, []byte(token+"\n"), 0600) != nil {
		t.Fatal("fixture file failed")
	}
	return file, token
}

func TestStagedFetcherFixedScopeReadOnlyCredentialAndRotation(t *testing.T) {
	scope := testScope()
	file, token := credential(t)
	hash := strings.Repeat("1", 64)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/api/e2e2/witness/views/"+scope.ViewID+"/envelopes/"+hash || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("unexpected staged request authority")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ciphertext":"fake-ciphertext-only"}`))
	}))
	defer server.Close()
	f, err := NewStagedFetcher(server.URL, ca(server), file, []string{scope.ViewID})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if raw, e := f.Fetch(context.Background(), scope, hash); e != nil || !bytes.Contains(raw, []byte("fake-ciphertext")) {
		t.Fatal("staged TLS fetch failed")
	}
	_, newToken := credential(t)
	token = newToken
	if os.WriteFile(file, []byte(token), 0600) != nil {
		t.Fatal("rotation failed")
	}
	if _, e := f.Fetch(context.Background(), scope, hash); e != nil {
		t.Fatal("rotated token was not reopened")
	}
	bad := scope
	bad.ViewID = bad.RealmID
	if _, e := f.Fetch(context.Background(), bad, hash); e == nil {
		t.Fatal("unregistered view fetched")
	}
	if _, e := f.Fetch(context.Background(), scope, "../escape"); e == nil {
		t.Fatal("hash injection fetched")
	}
	if calls.Load() != 2 {
		t.Fatal("invalid scope reached network")
	}
}

func TestTLSVerificationRedirectProxyAndBodyBounds(t *testing.T) {
	file, _ := credential(t)
	scope := testScope()
	var redirected, proxied atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	for _, mode := range []string{"redirect", "body-overflow", "compressed", "upstream-error"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, destination.URL, 302)
				case "body-overflow":
					w.Header().Set("Content-Length", "16777217")
					w.Write([]byte("fake-overflow"))
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
					w.Write([]byte("fake-compressed"))
				case "upstream-error":
					w.WriteHeader(500)
					w.Write([]byte("private-upstream-body-with-bearer"))
				}
			}))
			defer server.Close()
			f, e := NewStagedFetcher(server.URL, ca(server), file, []string{scope.ViewID})
			if e != nil {
				t.Fatal(e)
			}
			// Localhost is exempted by ProxyFromEnvironment, so an observed local
			// request alone would not prove this security configuration invariant.
			if f.http.Transport.(*http.Transport).Proxy != nil {
				t.Fatal("transport can consult an environment proxy")
			}
			defer f.Close()
			_, e = f.Fetch(context.Background(), scope, strings.Repeat("1", 64))
			safeError(t, e)
			untrusted, e := NewStagedFetcher(server.URL, nil, file, []string{scope.ViewID})
			if e != nil {
				t.Fatal(e)
			}
			defer untrusted.Close()
			_, e = untrusted.Fetch(context.Background(), scope, strings.Repeat("1", 64))
			safeError(t, e)
		})
	}
	if redirected.Load() != 0 || proxied.Load() != 0 {
		t.Fatal("credentials escaped through redirect or environment proxy")
	}
	if _, e := NewStagedFetcher("http://panel.example.invalid", nil, file, []string{scope.ViewID}); e == nil {
		t.Fatal("plaintext origin accepted")
	}
}

func TestWitnessTLSRawProofStillNeedsPinnedVerifier(t *testing.T) {
	scope := testScope()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("key generation failed")
	}
	hash := strings.Repeat("1", 64)
	nonce := make([]byte, 32)
	rand.Read(nonce)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/logs/"+scope.LogID+"/head-challenge" || r.Header.Get("Authorization") != "" {
			t.Error("wrong witness transport authority")
		}
		var fields map[string]string
		if json.NewDecoder(r.Body).Decode(&fields) != nil || len(fields) != 3 || fields["request_nonce"] != base64.RawURLEncoding.EncodeToString(nonce) || fields["floor_sequence"] != "1" || fields["floor_hash"] != hash {
			t.Error("head challenge changed")
		}
		body := e2e2.HeadBody{Format: "sekvyr-e2e2-head-v1", Scope: scope, WitnessEpoch: "1", Sequence: "1", EnvelopeHash: hash, ReadKeyEpoch: "1", PublisherPolicyEpoch: "1", RequestNonce: fields["request_nonce"], WitnessKeyID: e2e2.KeyID(public), FloorSequence: "1", FloorHash: hash}
		raw, _ := json.Marshal(body)
		canonical, _ := e2e2.Canonical(raw, e2e2.MaxHeadProofBytes)
		proof := e2e2.HeadProof{Body: body, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append(e2e2.Domain("sekvyr-e2e2/head/v1"), canonical...)))}
		json.NewEncoder(w).Encode(proof)
	}))
	defer server.Close()
	client, e := NewWitnessClient(server.URL, []string{server.URL}, ca(server))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	ws := witness.Scope{RealmID: scope.RealmID, ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID, ViewID: scope.ViewID, LogID: scope.LogID}
	challenge := witness.Challenge{Scope: ws, Nonce: nonce, Floor: witness.Floor{Sequence: "1", EnvelopeHash: hash}}
	raw, e := client.Head(context.Background(), challenge)
	if e != nil {
		t.Fatal(e)
	}
	v, e := witness.NewPinnedVerifier(witness.Trust{Scope: ws, WitnessEpoch: "1", KeyID: e2e2.KeyID(public), PublicKey: public, PublisherPolicyEpoch: "1", Checkpoint: challenge.Floor})
	if e != nil {
		t.Fatal(e)
	}
	if head, e := v.VerifyHead(context.Background(), challenge, raw); e != nil || head.EnvelopeHash != hash {
		t.Fatal("TLS wire did not verify against independent pinned key")
	}
	if _, e := NewWitnessClient(server.URL, []string{"https://witness.example.invalid"}, ca(server)); e == nil {
		t.Fatal("unapproved witness origin accepted")
	}
}

func TestWitnessRefusesRedirectOversizeAndCanceledRequests(t *testing.T) {
	for _, mode := range []string{"redirect", "oversize", "error"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, "https://witness.example.invalid", 302)
				case "oversize":
					w.Write(bytes.Repeat([]byte{'x'}, e2e2.MaxHeadProofBytes+1))
				case "error":
					w.WriteHeader(503)
					w.Write([]byte("private-upstream-error"))
				}
			}))
			defer server.Close()
			c, e := NewWitnessClient(server.URL, []string{server.URL}, ca(server))
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			s := testScope()
			challenge := witness.Challenge{Scope: witness.Scope{RealmID: s.RealmID, ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID, ViewID: s.ViewID, LogID: s.LogID}, Nonce: make([]byte, 32), Floor: witness.Floor{Sequence: "0", EnvelopeHash: e2e2.ZeroHash}}
			_, e = c.Head(context.Background(), challenge)
			safeError(t, e)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, e = c.Head(ctx, challenge)
			safeError(t, e)
		})
	}
}
