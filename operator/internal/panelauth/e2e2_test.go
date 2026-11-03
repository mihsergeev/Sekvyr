package panelauth

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func reportPublicKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ephemeral node key generation failed")
	}
	return key.PublicKey().Bytes()
}

func TestNodeReportContainsOnlyPinnedPublicMetadata(t *testing.T) {
	public := reportPublicKey(t)
	var calls atomic.Int32
	c, _, _ := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/machine/report" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer synthetic-test-session" {
			t.Error("unexpected report route or session")
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["public_key"] != base64.StdEncoding.EncodeToString(public) || body["agent_version"] != "sekvyr-operator-stage4" {
			t.Error("report includes incorrect key or extra fields")
		}
		w.Write([]byte(`{"ok":true}`))
	})
	session := Session{token: "synthetic-test-session", origin: c.origin, ExpiresAt: time.Now().Add(time.Minute)}
	if err := c.ReportNodeKey(context.Background(), session, public); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("node report was not performed exactly once")
	}
}

func TestE2E2MethodsUseOnlyFixedSameOriginReadPaths(t *testing.T) {
	view := "10000000-0000-4000-8000-000000000004"
	digest := strings.Repeat("1", 64)
	var paths []string
	c, _, _ := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer synthetic-test-session" {
			t.Error("unexpected E2E2 authority")
		}
		paths = append(paths, r.URL.RequestURI())
		w.Write([]byte(`{"fake":"bounded-wire-only"}`))
	})
	session := Session{token: "synthetic-test-session", origin: c.origin, ExpiresAt: time.Now().Add(time.Minute)}
	if _, err := c.E2E2Envelope(context.Background(), session, view, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := c.E2E2ReaderWrap(context.Background(), session, view, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := c.E2E2Capabilities(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	expected := []string{"/api/v1/machine/e2e2/views/" + view + "/envelopes/" + digest, "/api/v1/machine/e2e2/views/" + view + "/reader-wrap?envelope_hash=" + digest, "/api/v1/machine/capabilities"}
	if len(paths) != len(expected) {
		t.Fatal("unexpected read count")
	}
	for i := range expected {
		if paths[i] != expected[i] {
			t.Fatal("fixed read path or canonical hash query changed")
		}
	}
}

func TestReportAndE2E2InputGuardsRunBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	c, _, _ := clientFor(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) })
	session := Session{token: "synthetic-test-session", origin: c.origin, ExpiresAt: time.Now().Add(time.Minute)}
	view, digest := "10000000-0000-4000-8000-000000000004", strings.Repeat("1", 64)
	if _, err := c.E2E2Envelope(context.Background(), session, "../escape", digest); err == nil {
		t.Fatal("view path injection accepted")
	}
	if _, err := c.E2E2ReaderWrap(context.Background(), session, view, digest+"&other=view"); err == nil {
		t.Fatal("query injection accepted")
	}
	if err := c.ReportNodeKey(context.Background(), session, make([]byte, 65)); err == nil {
		t.Fatal("invalid curve point reported")
	}
	session.origin = "https://other.example.invalid"
	if err := c.ReportNodeKey(context.Background(), session, reportPublicKey(t)); err == nil {
		t.Fatal("foreign session reported")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input reached network")
	}
}

func TestNodeReportRedirectBoundsAndErrorsAreSanitized(t *testing.T) {
	for _, mode := range []string{"redirect", "denied", "forbidden", "unavailable", "invalid", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _ := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, "https://other.example.invalid/private-upstream-route", 302)
				case "denied":
					w.WriteHeader(401)
					w.Write([]byte("private-upstream-response"))
				case "forbidden":
					w.WriteHeader(403)
					w.Write([]byte("private-upstream-response"))
				case "unavailable":
					w.WriteHeader(503)
					w.Write([]byte("private-upstream-response"))
				case "invalid":
					w.WriteHeader(400)
					w.Write([]byte("private-upstream-response"))
				case "oversize":
					w.Write(bytes.Repeat([]byte{'x'}, 32769))
				}
			})
			session := Session{token: "synthetic-test-session", origin: c.origin, ExpiresAt: time.Now().Add(time.Minute)}
			err := c.ReportNodeKey(context.Background(), session, reportPublicKey(t))
			want := "NodeReportDenied"
			if mode == "denied" {
				want = "AuthenticationDenied"
			}
			if mode == "forbidden" {
				want = "AccessDenied"
			}
			if mode == "unavailable" {
				want = "PanelUnavailable"
			}
			if mode == "redirect" {
				want = "RedirectDenied"
			}
			if mode == "oversize" {
				want = "ResponseBounds"
			}
			requireReason(t, err, want)
			if strings.Contains(err.Error(), "private-upstream") || strings.Contains(err.Error(), session.token) {
				t.Fatal("upstream data leaked")
			}
		})
	}
}
