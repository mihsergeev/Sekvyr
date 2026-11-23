package journal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func gatewayTLS(t *testing.T) ([]byte, tls.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "public-test-root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootKey := private("tls-root")
	rootDER, err := x509.CreateCertificate(nilRandom{}, rootTemplate, rootTemplate, rootKey.Public().(ed25519.PublicKey), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	create := func(label string, serial int64, usage x509.ExtKeyUsage, ip bool) tls.Certificate {
		key := private(label)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: label}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if ip {
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(nilRandom{}, template, rootCert, key.Public().(ed25519.PublicKey), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), create("public-test-server", 2, x509.ExtKeyUsageServerAuth, true), create("public-test-client", 3, x509.ExtKeyUsageClientAuth, false)
}

// X509's Ed25519 signatures are deterministic; this source is test-only and
// never substitutes for production randomness in TLS or protocol nonces.
type nilRandom struct{}

func (nilRandom) Read(p []byte) (int, error) {
	for n := range p {
		p[n] = byte(n)
	}
	return len(p), nil
}

type changingStorage struct {
	Storage
	first []StoredSlot
	later []StoredSlot
	reads int
}

func (s *changingStorage) ReadAll(context.Context, string) ([]StoredSlot, error) {
	s.reads++
	if s.reads == 1 {
		return s.first, nil
	}
	return s.later, nil
}

func TestGatewayStreamValidatesTheReturnedSnapshot(t *testing.T) {
	f := setupJournal(t)
	f.initial(t)
	registration := f.registration
	registration.MinimumCursor = f.state.Cursor
	current := f.store.slots
	expired := append([]StoredSlot(nil), current...)
	expired[1].Receipt.RetainUntil = "2000-01-01T00:00:00Z"
	for _, tc := range []struct {
		name   string
		first  []StoredSlot
		status int
		reason string
	}{
		{name: "below floor", first: current[:1], status: 503, reason: "JournalBelowCheckpoint"},
		{name: "empty", status: 503, reason: "JournalMissingOrCapacity"},
		{name: "expired retention", first: expired, status: 503, reason: "RetentionInvalid"},
		{name: "valid", first: current, status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage := &changingStorage{Storage: f.store, first: tc.first, later: current}
			gateway, err := NewGateway(storage, []Registration{registration}, nil)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/v1/storage/logs/"+registration.LogID+"/journal", nil)
			request.Header.Set("X-Sekvyr-Journal-Nonce", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			response := httptest.NewRecorder()
			gateway.stream(request.Context(), response, request, registration.LogID)
			if response.Code != tc.status || storage.reads != 1 {
				t.Fatalf("status=%d, reads=%d, want status=%d and one validated snapshot", response.Code, storage.reads, tc.status)
			}
			if tc.reason != "" {
				var body map[string]string
				if json.Unmarshal(response.Body.Bytes(), &body) != nil || body["reason"] != tc.reason {
					t.Fatalf("unexpected response %s", response.Body.String())
				}
			} else if !bytes.Contains(response.Body.Bytes(), []byte(registration.MinimumCursor.RecordHash)) {
				t.Fatal("stream omitted the validated cursor")
			}
		})
	}
}

func TestReadRecordUsesTheValidatedSnapshot(t *testing.T) {
	f := setupJournal(t)
	f.initial(t)
	registration := f.registration
	registration.MinimumCursor = f.state.Cursor
	storage := &changingStorage{Storage: f.store, first: f.store.slots, later: f.store.slots[:1]}
	ledger, err := New(storage, []Registration{registration}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ledger.ReadRecord(context.Background(), registration.LogID, "1")
	if err != nil || !bytes.Equal(raw, f.store.slots[1].Raw) || storage.reads != 1 {
		t.Fatalf("ReadRecord did not use one validated snapshot, reads=%d, error=%v", storage.reads, err)
	}
}

func TestGatewayAppendReturnsReceiptOnlyFromVerifiedSlot(t *testing.T) {
	f := setupJournal(t)
	f.initial(t)
	log := f.state.Scope.LogID
	valid := f.store.slots
	corrupt := append([]StoredSlot(nil), valid...)
	fork, err := DecodeRecord(valid[1].Raw)
	if err != nil {
		t.Fatal(err)
	}
	fork.PreviousRecordHash = ZeroHash
	corrupt[1].Raw, err = EncodeRecord(fork)
	if err != nil {
		t.Fatal(err)
	}
	corrupt[1].Receipt.VersionID = "unverified-slot-version"
	for _, tc := range []struct {
		name   string
		first  []StoredSlot
		status int
	}{
		{"exact retry uses verified receipt", valid, http.StatusOK},
		{"new write rejects invalid readback", valid[:1], http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage := &changingStorage{Storage: &memoryStorage{slots: tc.first}, first: tc.first, later: corrupt}
			gateway, err := NewGateway(storage, []Registration{f.registration}, []GatewayClient{{CommonName: "publisher", Logs: []string{log}, WriteKinds: []string{"snapshot"}}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPut, "/v1/storage/logs/"+log+"/slots/1", bytes.NewReader(valid[1].Raw))
			request.Header.Set("If-None-Match", "*")
			request.Header.Set("Content-Type", "application/json")
			cert := &x509.Certificate{Subject: pkix.Name{CommonName: "publisher"}}
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
			response := httptest.NewRecorder()
			gateway.ServeHTTP(response, request)
			if response.Code != tc.status || bytes.Contains(response.Body.Bytes(), []byte(corrupt[1].Receipt.VersionID)) {
				t.Fatalf("status=%d, body=%s", response.Code, response.Body.String())
			}
			if tc.status == http.StatusOK {
				var receipt RetentionReceipt
				if json.Unmarshal(response.Body.Bytes(), &receipt) != nil || receipt != valid[1].Receipt || storage.reads != 1 {
					t.Fatal("retry receipt did not come from the already verified slot")
				}
			}
		})
	}
}

func TestGatewayMTLSConditionalAppendAndStreamFailures(t *testing.T) {
	f := setupJournal(t)
	gateway, err := NewGateway(f.store, []Registration{f.registration}, []GatewayClient{{CommonName: "public-test-client", Logs: []string{f.state.Scope.LogID}, WriteKinds: []string{"snapshot"}}})
	if err != nil {
		t.Fatal(err)
	}
	ca, serverCert, clientCert := gatewayTLS(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	var fault atomic.Value
	fault.Store("")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := httptest.NewRecorder()
		gateway.ServeHTTP(recorder, r)
		for key, values := range recorder.Header() {
			w.Header()[key] = values
		}
		code := recorder.Code
		body := recorder.Body.Bytes()
		if r.Method == "PUT" && fault.Load().(string) == "put-lost-ack" && code == 200 {
			code = 503
			body = []byte(`{"reason":"StorageUnavailable"}`)
		}
		w.WriteHeader(code)
		if r.Method == "GET" && recorder.Code == 200 {
			lines := bytes.Split(bytes.TrimSuffix(body, []byte("\n")), []byte("\n"))
			switch fault.Load().(string) {
			case "drop-end":
				lines = lines[:len(lines)-1]
			case "drop-slot":
				lines = append(lines[:1], lines[2:]...)
			case "duplicate":
				lines = append(append(append([][]byte{}, lines[:2]...), lines[1]), lines[2:]...)
			case "reorder":
				lines[1], lines[2] = lines[2], lines[1]
			case "bad-nonce":
				var end streamMeta
				_ = json.Unmarshal(lines[len(lines)-1], &end)
				end.Nonce = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
				lines[len(lines)-1], _ = json.Marshal(end)
			case "extra":
				lines = append(lines, []byte("{}"))
			}
			body = append(bytes.Join(lines, []byte("\n")), '\n')
		}
		_, _ = w.Write(body)
	})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	defer server.Close()
	storage, err := NewAPIStorageClient(server.URL, ca, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ledger, err := New(storage, []Registration{f.registration}, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := ledger.ReadCurrent(context.Background(), f.state.Scope.LogID, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	fault.Store("put-lost-ack")
	state, err = ledger.AppendSnapshotCAS(context.Background(), f.state.Scope.LogID, state.Cursor, f.vectorRaw)
	fault.Store("")
	if err != nil {
		t.Fatal("gateway lost acknowledgement did not resolve exact slot", err)
	}
	if state.Snapshot.Sequence != "1" || len(f.store.slots) != 2 {
		t.Fatal("append not replayed")
	}
	if _, err = storage.PutIfAbsent(context.Background(), state.Scope.LogID, 1, f.store.slots[1].Raw); err != nil || len(f.store.slots) != 2 {
		t.Fatal("gateway exact-slot retry duplicated", err)
	}
	for _, name := range []string{"drop-end", "drop-slot", "duplicate", "reorder", "bad-nonce", "extra"} {
		t.Run(name, func(t *testing.T) {
			fault.Store(name)
			if _, err := ledger.ReadCurrent(context.Background(), state.Scope.LogID, state.Cursor); err == nil {
				t.Fatal("partial/ambiguous stream accepted")
			}
		})
	}
	fault.Store("")
	before := len(f.store.slots)
	request, _ := http.NewRequest("DELETE", server.URL+"/v1/storage/logs/"+state.Scope.LogID+"/slots/0", nil)
	response, err := storage.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode < 400 || len(f.store.slots) != before {
		t.Fatal("unsafe gateway operation")
	}
	// A trusted certificate with an unregistered identity still has no API rights.
	rootBlock, _ := pem.Decode(ca)
	rootCert, _ := x509.ParseCertificate(rootBlock.Bytes)
	unknownKey := private("tls-unregistered")
	unknownTemplate := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "public-unregistered"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	unknownDER, certErr := x509.CreateCertificate(nilRandom{}, unknownTemplate, rootCert, unknownKey.Public().(ed25519.PublicKey), private("tls-root"))
	if certErr != nil {
		t.Fatal(certErr)
	}
	clientCert = tls.Certificate{Certificate: [][]byte{unknownDER}, PrivateKey: unknownKey}
	badClient, err := NewAPIStorageClient(server.URL, ca, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	defer badClient.Close()
	if _, err = badClient.ReadAll(context.Background(), state.Scope.LogID); Reason(err) != "StorageDenied" {
		t.Fatal("CA-valid unregistered identity accepted", err)
	}
}
func TestStrictJournalDecoderRejectsCaseMissingNullAndUnknown(t *testing.T) {
	for _, raw := range []string{`{"journal_sequence":"1"}`, `{"Journal_sequence":"1","record_hash":"abc"}`, `{"journal_sequence":null,"record_hash":"abc"}`, `{"journal_sequence":"1","record_hash":"abc","extra":1}`, `{"journal_sequence":"1","journal_sequence":"2","record_hash":"abc"}`} {
		var c Cursor
		if DecodeStrict([]byte(raw), &c, 2048) == nil {
			t.Fatal("ambiguous shape accepted")
		}
	}
	f := setupJournal(t)
	raw, _ := EncodeRecord(f.genesis)
	if _, err := DecodeRecord(raw); err != nil {
		t.Fatal("explicit null union rejected", err)
	}
}
