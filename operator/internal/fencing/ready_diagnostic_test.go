package fencing

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
)

func diagnosticClient(t *testing.T, f *fixture, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	file := filepath.Join(t.TempDir(), "projected-token")
	if err := os.WriteFile(file, []byte("public-unit-token"), 0600); err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	c, err := NewClient(ClientConfig{Origin: server.URL, AllowedOrigins: []string{server.URL}, CustomCAPEM: ca,
		TokenFile: file, PodUID: f.identity.PodUID, InstallationID: uid(20), LogID: uid(25),
		ExpectedLeaseHolderIdentity: f.holder, MinimumCursor: f.ledger.state.Cursor, Journal: f.ledger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestReadyDiagnosticClosedServiceReasonsRealTLS(t *testing.T) {
	for _, reason := range []string{"JournalUnavailable", "LeaseExpired", "LeaseMismatch", "LeaseUnavailable",
		"AuthenticationDenied", "BoundPodRequired", "GrantChanged", "BarriersIncomplete", "FencerBusy"} {
		t.Run(reason, func(t *testing.T) {
			f := newFixture(t)
			session := f.active(t)
			c := diagnosticClient(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httpError(w, http.StatusConflict, reason)
			}))
			if err := c.Ready(context.Background(), session); Reason(err) != reason {
				t.Fatal("fixed service reason was not preserved")
			}
			// The acquisition/barrier behavior is deliberately unchanged.
			if _, err := c.Acquire(context.Background(), uid(20), 1); Reason(err) != "FencerDenied" {
				t.Fatal("diagnostic change broadened acquisition behavior")
			}
			if _, err := c.Barriers(context.Background(), session); Reason(err) != "FencerDenied" {
				t.Fatal("diagnostic change broadened barrier behavior")
			}
		})
	}
}

func TestReadyDiagnosticRejectsUnknownMalformedAndOversizeBodies(t *testing.T) {
	const private = "PRIVATE_RESPONSE_SENTINEL"
	for _, payload := range []string{
		private, `{"reason":"` + private + `"}`, `{"reason":"LeaseExpired","detail":"` + private + `"}`,
		`{"reason":"LeaseExpired","reason":"LeaseMismatch"}`, `{"Reason":"LeaseExpired"}`,
		`{"reason":null}`, `{}`, `{"reason":"LeaseExpired"} {}`, strings.Repeat("x", 4097),
		`{"reason":"LeaseExpired"}` + strings.Repeat(" ", 4097),
	} {
		f := newFixture(t)
		session := f.active(t)
		c := diagnosticClient(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, payload)
		}))
		err := c.Ready(context.Background(), session)
		if err == nil || Reason(err) != "FencerDenied" || strings.Contains(err.Error(), private) {
			t.Fatal("untrusted response was accepted or exposed")
		}
	}
}

func TestReadyDiagnosticPreservesLocalJournalFailure(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	c := diagnosticClient(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, response{Grant: session.Grant(), GrantHash: session.Hash(), Active: true})
	}))
	f.ledger.failure = errors.New("PRIVATE_JOURNAL_SENTINEL")
	err := c.Ready(context.Background(), session)
	if Reason(err) != "JournalUnavailable" || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("local verification failure lost its phase or leaked detail")
	}
	f.ledger.failure = nil
	delete(f.ledger.state.Activations, uid(20))
	if err = c.Ready(context.Background(), session); Reason(err) != "BarriersIncomplete" {
		t.Fatal("local missing activation was not preserved")
	}
}

func TestReadyDiagnosticTokenCancellationRedirectAndTransportFailClosed(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	calls := 0
	c := diagnosticClient(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", "https://redirect.example.test/private")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	if err := c.Ready(context.Background(), session); Reason(err) != "RedirectDenied" || calls != 1 {
		t.Fatal("redirect was followed or misclassified")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Ready(ctx, session); Reason(err) != "Cancelled" || calls != 1 {
		t.Fatal("cancelled request reached network")
	}
	if err := os.WriteFile(c.config.TokenFile, []byte("PRIVATE_TOKEN with whitespace"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Ready(context.Background(), session); Reason(err) != "ProjectedTokenInvalid" || calls != 1 || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("malformed projected token reached network or leaked")
	}
	if err := os.Remove(c.config.TokenFile); err != nil {
		t.Fatal(err)
	}
	if err := c.Ready(context.Background(), session); Reason(err) != "ProjectedTokenUnavailable" || calls != 1 {
		t.Fatal("missing projected token reached network")
	}
	if err := os.WriteFile(c.config.TokenFile, []byte("public-unit-token"), 0600); err != nil {
		t.Fatal(err)
	}
	c.http.Transport = diagnosticFailureTransport{}
	if err := c.Ready(context.Background(), session); Reason(err) != "FencerUnavailable" || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("transport failure was not redacted")
	}
}

type diagnosticFailureTransport struct{}

func (diagnosticFailureTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("PRIVATE_TRANSPORT_SENTINEL")
}

func TestReadyDiagnosticInflightParentCancellationRealTLS(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	started := make(chan struct{})
	c := diagnosticClient(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-time.After(1500 * time.Millisecond):
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Ready(ctx, session) }()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-started:
	case <-timer.C:
		t.Fatal("request did not reach the TLS endpoint within its bound")
	}
	cancel()
	select {
	case err := <-done:
		if Reason(err) != "Cancelled" {
			t.Fatal("inflight parent cancellation was misclassified")
		}
	case <-timer.C:
		t.Fatal("cancelled TLS request did not stop within its bound")
	}
}

type readyCancelLedger struct {
	Ledger
	cancel context.CancelFunc
	called *bool
}

func (l readyCancelLedger) ReadCurrent(ctx context.Context, log string, floor journal.Cursor) (journal.CurrentState, error) {
	*l.called = true
	l.cancel()
	return journal.CurrentState{}, errors.New("PRIVATE_CANCELLED_JOURNAL_SENTINEL")
}

func TestReadyDiagnosticLocalJournalParentCancellation(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	c := diagnosticClient(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, response{Grant: session.Grant(), GrantHash: session.Hash(), Active: true})
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	called := false
	c.config.Journal = readyCancelLedger{Ledger: f.ledger, cancel: cancel, called: &called}
	err := c.Ready(ctx, session)
	if !called || Reason(err) != "Cancelled" || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("cancelled local journal verification was misclassified or exposed")
	}
}
