package witnessservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
)

type staged struct {
	mu     sync.Mutex
	blobs  map[string][]byte
	scopes []e2e2.Scope
	hashes []string
	broken bool
}

func (f *staged) Fetch(_ context.Context, scope e2e2.Scope, hash string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scopes = append(f.scopes, scope)
	f.hashes = append(f.hashes, hash)
	if f.broken {
		return nil, errors.New("private-upstream-credential-body")
	}
	return bytes.Clone(f.blobs[hash]), nil
}

type fixture struct {
	root      string
	cfg       Config
	genesis   Genesis
	private   ed25519.PrivateKey
	publisher ed25519.PrivateKey
	admin     ed25519.PublicKey
	fetch     *staged
	s         *Service
	readKey   []byte
}

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	p, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("key generation failed")
	}
	return p, k
}
func setup(t *testing.T) *fixture {
	t.Helper()
	admin, adminPrivate := key(t)
	wp, wk := key(t)
	pp, pk := key(t)
	scope := e2e2.Scope{RealmID: "10000000-0000-4000-8000-000000000001", ProjectID: "10000000-0000-4000-8000-000000000002", EnvironmentID: "10000000-0000-4000-8000-000000000003", ViewID: "10000000-0000-4000-8000-000000000004", LogID: "10000000-0000-4000-8000-000000000005"}
	g := Genesis{Body: GenesisBody{Format: "sekvyr-witness-genesis-v1", Scope: scope, PanelOrigin: "https://panel.example.invalid", WitnessEpoch: "1", WitnessPublicKey: base64.RawURLEncoding.EncodeToString(wp), WitnessKeyID: e2e2.KeyID(wp), PublisherPolicyEpoch: "1", PublisherKeys: []PublicKey{{KeyID: e2e2.KeyID(pp), PublicKey: base64.RawURLEncoding.EncodeToString(pp)}}, ReadKeyEpoch: "1", AdminKeyID: e2e2.KeyID(admin)}}
	body, e := canonical(g.Body, 64<<10)
	if e != nil {
		t.Fatal(e)
	}
	g.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(adminPrivate, append(e2e2.Domain(genesisDomain), body...)))
	raw, e := canonical(g, 64<<10)
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	hash, e := Initialize(root, raw, admin)
	if e != nil {
		t.Fatal(e)
	}
	cfg := Config{Format: "sekvyr-witness-config-v1", Registrations: []Registration{{LogID: scope.LogID, GenesisHash: hash, AdminPublicKey: base64.RawURLEncoding.EncodeToString(admin), MinimumCheckpoint: Checkpoint{"0", e2e2.ZeroHash}, StagingTokenFile: "/test-only/credential"}}}
	f := &fixture{root: root, cfg: cfg, genesis: g, private: wk, publisher: pk, admin: admin, fetch: &staged{blobs: map[string][]byte{}}, readKey: make([]byte, 32)}
	if _, e = rand.Read(f.readKey); e != nil {
		t.Fatal("key generation failed")
	}
	f.s = f.open(t)
	return f
}
func (f *fixture) open(t *testing.T) *Service {
	t.Helper()
	s, e := New(f.root, f.cfg, f.private, true, func(g GenesisBody, r Registration) (StagedFetcher, error) {
		if g.Scope != f.genesis.Body.Scope || r.GenesisHash != f.cfg.Registrations[0].GenesisHash {
			t.Fatal("factory received unauthorized authority")
		}
		return f.fetch, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func (f *fixture) publish(t *testing.T, seq, prev, value string, modify func(*e2e2.Header)) CommitRequest {
	t.Helper()
	action := "update"
	if seq == "1" {
		action = "initial"
	}
	h := e2e2.Header{Protocol: "e2e2", Suite: "HKDF-SHA256+A256GCM+Ed25519", Intent: "publish", Scope: f.genesis.Body.Scope, Sequence: seq, PreviousHash: prev, ReadKeyEpoch: "1", PublisherPolicyEpoch: "1", PublisherKeyID: e2e2.KeyID(f.publisher.Public().(ed25519.PublicKey)), EntryCount: 1, Action: action, Parents: []e2e2.Parent{}}
	if modify != nil {
		modify(&h)
	}
	raw, e := e2e2.SealSnapshot(h, e2e2.Plaintext{Format: "sekvyr-e2e2-values-v1", Context: h.Scope, Entries: []e2e2.Entry{{Path: "/runtime", Name: "PASSWORD", Value: value}}}, f.readKey, f.publisher)
	if e != nil {
		t.Fatal(e)
	}
	hash, e := e2e2.EnvelopeHash(raw)
	if e != nil {
		t.Fatal(e)
	}
	f.fetch.blobs[hash] = raw
	policy := "1"
	expected := "1"
	if seq == "1" {
		expected = "0"
		policy = "0"
	} else {
		n, _ := e2e2.Counter(seq, false)
		expected = fmtCounter(n - 1)
	}
	return CommitRequest{EnvelopeHash: hash, Expected: Expected{WitnessEpoch: "1", Sequence: expected, EnvelopeHash: prev, PublisherPolicyEpoch: policy}}
}
func fmtCounter(v uint64) string { return strconv.FormatUint(v, 10) }
func request(t *testing.T, seq, hash string) HeadRequest {
	t.Helper()
	n := make([]byte, 32)
	if _, e := rand.Read(n); e != nil {
		t.Fatal("nonce failed")
	}
	return HeadRequest{RequestNonce: base64.RawURLEncoding.EncodeToString(n), FloorSequence: seq, FloorHash: hash}
}
func reason(t *testing.T, err error) string {
	t.Helper()
	var safe *Error
	if !errors.As(err, &safe) {
		t.Fatal("expected fixed safe error")
	}
	return safe.Reason
}

func TestDurableRestartFreshProofAndNoPlaintextJournal(t *testing.T) {
	f := setup(t)
	one := f.publish(t, "1", e2e2.ZeroHash, "fake-plaintext-unique-1", nil)
	if _, e := f.s.Commit(context.Background(), f.genesis.Body.LogID, one); e != nil {
		t.Fatal(e)
	}
	two := f.publish(t, "2", one.EnvelopeHash, "fake-plaintext-unique-2", nil)
	if _, e := f.s.Commit(context.Background(), f.genesis.Body.LogID, two); e != nil {
		t.Fatal(e)
	}
	restarted := f.open(t)
	challenge := request(t, "1", one.EnvelopeHash)
	proof, e := restarted.Head(context.Background(), f.genesis.Body.LogID, challenge)
	if e != nil {
		t.Fatal(e)
	}
	verifier, e := witness.NewPinnedVerifier(witness.Trust{Scope: toWitness(f.genesis.Body.Scope), WitnessEpoch: "1", KeyID: f.genesis.Body.WitnessKeyID, PublicKey: f.private.Public().(ed25519.PublicKey), PublisherPolicyEpoch: "1", Checkpoint: witness.Floor{Sequence: "1", EnvelopeHash: one.EnvelopeHash}})
	if e != nil {
		t.Fatal(e)
	}
	nonce, _ := e2e2.DecodeBase64(challenge.RequestNonce, 32)
	head, e := verifier.VerifyHead(context.Background(), witness.Challenge{Scope: toWitness(f.genesis.Body.Scope), Nonce: nonce, Floor: witness.Floor{Sequence: "1", EnvelopeHash: one.EnvelopeHash}}, proof)
	if e != nil || head.Sequence != "2" || head.EnvelopeHash != two.EnvelopeHash {
		t.Fatal("restart did not prove durable canonical head")
	}
	files, _ := os.ReadDir(filepath.Join(f.root, f.genesis.Body.LogID))
	for _, file := range files {
		raw, _ := os.ReadFile(filepath.Join(f.root, f.genesis.Body.LogID, file.Name()))
		if bytes.Contains(raw, []byte("fake-plaintext")) {
			t.Fatal("plaintext persisted in journal")
		}
	}
	if len(f.fetch.scopes) != 2 || f.fetch.scopes[0] != f.genesis.Body.Scope || f.fetch.hashes[1] != two.EnvelopeHash {
		t.Fatal("unregistered fetch scope or hash")
	}
}

func TestConcurrentCASAcrossIndependentServiceInstances(t *testing.T) {
	f := setup(t)
	other := f.open(t)
	a := f.publish(t, "1", e2e2.ZeroHash, "fake-a", nil)
	b := f.publish(t, "1", e2e2.ZeroHash, "fake-b", nil)
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, s := range []*Service{f.s, other} {
		req := a
		if i == 1 {
			req = b
		}
		go func(s *Service, r CommitRequest) {
			<-start
			_, e := s.Commit(context.Background(), f.genesis.Body.LogID, r)
			results <- e
		}(s, req)
	}
	close(start)
	success, conflict := 0, 0
	for i := 0; i < 2; i++ {
		e := <-results
		if e == nil {
			success++
		} else if reason(t, e) == "CASConflict" {
			conflict++
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("two competing canonical successors or no CAS winner")
	}
	if _, e := f.open(t).Head(context.Background(), f.genesis.Body.LogID, request(t, "0", e2e2.ZeroHash)); e != nil {
		t.Fatal(e)
	}
}

func TestDamageAndIndependentCheckpointFailClosed(t *testing.T) {
	for _, damage := range []string{"torn-tail", "gap", "symlink", "genesis-rewrite", "missing-journal", "minimum-ahead", "minimum-fork"} {
		t.Run(damage, func(t *testing.T) {
			f := setup(t)
			one := f.publish(t, "1", e2e2.ZeroHash, "fake-one", nil)
			if _, e := f.s.Commit(context.Background(), f.genesis.Body.LogID, one); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(f.root, f.genesis.Body.LogID)
			switch damage {
			case "torn-tail":
				os.WriteFile(filepath.Join(path, recordName(2)), []byte(`{"format":`), 0600)
			case "gap":
				os.Rename(filepath.Join(path, recordName(1)), filepath.Join(path, recordName(2)))
			case "symlink":
				os.Symlink(filepath.Join(path, recordName(1)), filepath.Join(path, recordName(2)))
			case "genesis-rewrite":
				raw, _ := os.ReadFile(filepath.Join(path, recordName(0)))
				os.WriteFile(filepath.Join(path, recordName(0)), bytes.Replace(raw, []byte("panel.example.invalid"), []byte("other.example.invalid"), 1), 0600)
			case "missing-journal":
				os.Rename(path, path+"-missing")
			case "minimum-ahead":
				f.s.registrations[f.genesis.Body.LogID] = Registration{LogID: f.cfg.Registrations[0].LogID, GenesisHash: f.cfg.Registrations[0].GenesisHash, AdminPublicKey: f.cfg.Registrations[0].AdminPublicKey, MinimumCheckpoint: Checkpoint{"2", strings.Repeat("a", 64)}}
			case "minimum-fork":
				r := f.s.registrations[f.genesis.Body.LogID]
				r.MinimumCheckpoint = Checkpoint{"1", strings.Repeat("a", 64)}
				f.s.registrations[r.LogID] = r
			}
			if proof, e := f.s.Head(context.Background(), f.genesis.Body.LogID, request(t, "0", e2e2.ZeroHash)); e == nil || len(proof) != 0 {
				t.Fatal("damaged or rolled-back ledger signed a proof")
			}
		})
	}
}

func TestAuthorityCannotComeFromPanelOrRuntimeReset(t *testing.T) {
	f := setup(t)
	if _, e := New(f.root, f.cfg, f.private, false, func(GenesisBody, Registration) (StagedFetcher, error) { return f.fetch, nil }); reason(t, e) != "DevelopmentProfileNotAuthorized" {
		t.Fatal("filesystem profile implicitly authorized")
	}
	raw, _ := canonical(f.genesis, 64<<10)
	if _, e := Initialize(f.root, raw, f.admin); e == nil {
		t.Fatal("reinitialization overwrote canonical authority")
	}
	_, wrong := key(t)
	if _, e := New(f.root, f.cfg, wrong, true, func(GenesisBody, Registration) (StagedFetcher, error) { return f.fetch, nil }); reason(t, e) != "SigningKeyMismatch" {
		t.Fatal("unregistered signing authority accepted")
	}
	for _, bad := range []string{"scope", "read-rotation", "publisher-policy", "read-action"} {
		t.Run(bad, func(t *testing.T) {
			g := setup(t)
			modify := func(h *e2e2.Header) {
				switch bad {
				case "scope":
					h.ViewID = h.RealmID
				case "read-rotation":
					h.ReadKeyEpoch = "2"
				case "publisher-policy":
					h.PublisherPolicyEpoch = "2"
				case "read-action":
					h.Action = "migrate"
				}
			}
			if bad == "read-action" {
				one := g.publish(t, "1", e2e2.ZeroHash, "fake-1", nil)
				g.s.Commit(context.Background(), g.genesis.Body.LogID, one)
				req := g.publish(t, "2", one.EnvelopeHash, "fake-2", func(h *e2e2.Header) { h.Action = "rotate-read-key" })
				if _, e := g.s.Commit(context.Background(), g.genesis.Body.LogID, req); reason(t, e) != "AuthorityTransitionNotSupported" {
					t.Fatal("rotation accepted")
				}
				return
			}
			req := g.publish(t, "1", e2e2.ZeroHash, "fake-signed-invalid-authority", modify)
			if _, e := g.s.Commit(context.Background(), g.genesis.Body.LogID, req); e == nil {
				t.Fatal("panel-supplied authority accepted")
			}
		})
	}
}

func TestHistoricalFloorAndHTTPBoundary(t *testing.T) {
	f := setup(t)
	one := f.publish(t, "1", e2e2.ZeroHash, "fake-http", nil)
	f.s.Commit(context.Background(), f.genesis.Body.LogID, one)
	if proof, e := f.s.Head(context.Background(), f.genesis.Body.LogID, request(t, "1", strings.Repeat("f", 64))); e == nil || proof != nil {
		t.Fatal("unrecognized floor accepted")
	}
	url := "/v1/logs/" + f.genesis.Body.LogID + "/head-challenge"
	valid, _ := json.Marshal(request(t, "0", e2e2.ZeroHash))
	for _, body := range [][]byte{bytes.Replace(valid, []byte(`"request_nonce":`), []byte(`"request_nonce":"duplicate","request_nonce":`), 1), bytes.Replace(valid, []byte(`"request_nonce":`), []byte(`"Request_nonce":`), 1), append(valid, []byte(`{}`)...), []byte(strings.Repeat("x", 2049))} {
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.s.ServeHTTP(w, req)
		if w.Code == 200 {
			t.Fatal("invalid authority wire accepted")
		}
	}
	for _, endpoint := range []string{"/v1/register", "/v1/reset", "/v1/logs/" + f.genesis.Body.LogID + "/delete"} {
		w := httptest.NewRecorder()
		f.s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, endpoint, nil))
		if w.Code == 200 {
			t.Fatal("runtime administrative endpoint exposed")
		}
	}
	f.fetch.broken = true
	two := f.publish(t, "2", one.EnvelopeHash, "fake-2", nil)
	body, _ := json.Marshal(two)
	r := httptest.NewRequest(http.MethodPost, "/v1/logs/"+f.genesis.Body.LogID+"/commits", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, r)
	if w.Code == 200 || bytes.Contains(w.Body.Bytes(), []byte("private-upstream")) {
		t.Fatal("fetch failure accepted or leaked upstream body")
	}
}
