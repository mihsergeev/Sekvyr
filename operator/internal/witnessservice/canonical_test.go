package witnessservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
)

type canonicalMemory struct {
	mu    sync.Mutex
	slots []journal.StoredSlot
}

func (m *canonicalMemory) ReadAll(context.Context, string) ([]journal.StoredSlot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]journal.StoredSlot(nil), m.slots...), nil
}
func (m *canonicalMemory) PutIfAbsent(_ context.Context, _ string, n uint64, raw []byte) (journal.RetentionReceipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n != uint64(len(m.slots)) {
		return journal.RetentionReceipt{}, journal.Failure("CASConflict")
	}
	receipt := journal.RetentionReceipt{VersionID: "public-version", Mode: "COMPLIANCE", RetainUntil: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	m.slots = append(m.slots, journal.StoredSlot{Raw: append([]byte(nil), raw...), Receipt: receipt})
	return receipt, nil
}
func canonicalPrivate(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("sekvyr-e2e2-public-test-vector/" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}
func canonicalKey(t *testing.T, label string) journal.Key {
	t.Helper()
	key, err := journal.KeyFromPublic(canonicalPrivate(label).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func TestCanonicalHTTPFreshAuthorityProofAndExactCommit(t *testing.T) {
	raw, err := os.ReadFile("../../design/e2e2.public-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Envelope  e2e2.Envelope  `json:"envelope"`
		Plaintext e2e2.Plaintext `json:"plaintext"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("public fixture")
	}
	scope := fixture.Envelope.Body.Header.Scope
	authority := journal.Authority{Revision: "1", AdminKey: canonicalKey(t, "canonical-admin"), PublisherPolicyEpoch: "1", PublisherKeys: []journal.Key{canonicalKey(t, "publisher")}, ReadKeyEpoch: "1", WitnessEpoch: "1", WitnessKey: canonicalKey(t, "witness"), FencerEpoch: "1", FencerKeys: []journal.Key{canonicalKey(t, "canonical-fencer")}}
	genesis, err := journal.SignGenesis(journal.GenesisBody{Format: "sekvyr-journal-genesis-v1", Scope: scope, PanelOrigin: "https://panel.example.test", Authority: authority}, canonicalPrivate("canonical-admin"))
	if err != nil {
		t.Fatal(err)
	}
	record := journal.NewGenesisRecord(genesis)
	hash, _ := journal.RecordHash(record)
	reg := journal.Registration{LogID: scope.LogID, GenesisHash: hash, AdminPublicKey: authority.AdminKey.PublicKey, MinimumCursor: journal.Cursor{JournalSequence: "0", RecordHash: hash}}
	ledger, err := journal.New(&canonicalMemory{}, []journal.Registration{reg}, nil)
	if err != nil {
		t.Fatal(err)
	}
	recordRaw, _ := journal.EncodeRecord(record)
	state, err := ledger.InitializeCAS(context.Background(), scope.LogID, recordRaw)
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, _ := json.Marshal(fixture.Envelope)
	state, err = ledger.AppendSnapshotCAS(context.Background(), scope.LogID, state.Cursor, envelopeRaw)
	if err != nil {
		t.Fatal(err)
	}
	fetch := &staged{blobs: map[string][]byte{state.Snapshot.EnvelopeHash: envelopeRaw}}
	cfg := CanonicalConfig{Format: "sekvyr-witness-canonical-config-v1", Registrations: []CanonicalRegistration{{Journal: reg, StagingTokenFile: "private-test-file-unused"}}, SigningKeyFiles: []string{"private-test-file-unused"}, Clients: []journal.GatewayClient{{CommonName: "public-admin", Logs: []string{scope.LogID}, WriteKinds: []string{"snapshot", "transition"}}}}
	service, err := NewCanonical(context.Background(), ledger, cfg, []ed25519.PrivateKey{canonicalPrivate("witness")}, func(journal.CurrentState, CanonicalRegistration) (StagedFetcher, error) { return fetch, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	request := func(path string, body any, authenticated bool) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		if authenticated {
			certificate := &x509.Certificate{Subject: pkix.Name{CommonName: "public-admin"}}
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
		}
		w := httptest.NewRecorder()
		service.ServeHTTP(w, r)
		return w
	}
	nonce := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	challenge := AuthorityChallengeRequest{RequestNonce: nonce, Floor: reg.MinimumCursor}
	route := "/v2/logs/" + scope.LogID + "/authority-challenge"
	if response := request(route, challenge, false); response.Code != 403 {
		t.Fatal("authority API public", response.Code)
	}
	response := request(route, challenge, true)
	if response.Code != 200 {
		t.Fatal("authority challenge", response.Code)
	}
	view, err := journal.VerifyAuthorityProof(response.Body.Bytes(), scope, hash, authority.WitnessKey, nonce, reg.MinimumCursor)
	if err != nil || view.Snapshot.Sequence != "1" {
		t.Fatal("authority proof not bound to current journal", err)
	}
	if _, err = journal.VerifyAuthorityProof(response.Body.Bytes(), scope, hash, authority.WitnessKey, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB", reg.MinimumCursor); err == nil {
		t.Fatal("nonce replay accepted")
	}
	header := fixture.Envelope.Body.Header
	header.Sequence = "2"
	header.Action = "update"
	header.PreviousHash = state.Snapshot.EnvelopeHash
	seed := sha256.Sum256([]byte("sekvyr-e2e2-public-test-vector/view-read"))
	nextRaw, err := e2e2.SealSnapshot(header, fixture.Plaintext, seed[:], canonicalPrivate("publisher"))
	if err != nil {
		t.Fatal(err)
	}
	nextHash, _ := e2e2.EnvelopeHash(nextRaw)
	fetch.blobs[nextHash] = nextRaw
	response = request("/v2/logs/"+scope.LogID+"/commits", CanonicalCommitRequest{Expected: state.Cursor, EnvelopeHash: nextHash}, true)
	if response.Code != 200 {
		t.Fatal("canonical HTTP commit", response.Code)
	}
	var committed journal.CurrentState
	if journal.DecodeStrict(response.Body.Bytes(), &committed, journal.MaxReplayBytes) != nil || committed.Snapshot.Sequence != "2" {
		t.Fatal("bad commit state")
	}
	headResponse := request("/v1/logs/"+scope.LogID+"/head-challenge", HeadRequest{RequestNonce: nonce, FloorSequence: "1", FloorHash: state.Snapshot.EnvelopeHash}, false)
	if headResponse.Code != 200 {
		t.Fatal("reader v1 compatibility", headResponse.Code)
	}
	var proof e2e2.HeadProof
	if e2e2.DecodeStrict(headResponse.Body.Bytes(), &proof, e2e2.MaxHeadProofBytes) != nil || proof.Body.Sequence != "2" || proof.Body.EnvelopeHash != nextHash {
		t.Fatal("head did not reflect canonical commit")
	}
}
