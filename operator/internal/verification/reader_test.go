package verification

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
)

type testSource struct {
	envelopes                  map[string][]byte
	wrap                       []byte
	envelopeCalls, wrapCalls   int
	brokenEnvelope, brokenWrap bool
}

func (s *testSource) EnvelopeByHash(_ context.Context, _ witness.Scope, hash string) ([]byte, error) {
	s.envelopeCalls++
	if s.brokenEnvelope {
		return nil, errors.New("fake-private-upstream-body")
	}
	raw, ok := s.envelopes[hash]
	if !ok {
		return nil, errors.New("no canonical blob")
	}
	return bytes.Clone(raw), nil
}
func (s *testSource) ReaderWrap(_ context.Context, _ witness.Scope, _, _, _, _ string) ([]byte, error) {
	s.wrapCalls++
	if s.brokenWrap {
		return nil, errors.New("fake-private-wrap-body")
	}
	return bytes.Clone(s.wrap), nil
}

type testWitness struct {
	key             ed25519.PrivateKey
	head            witness.Head
	calls           int
	nonces          [][]byte
	floors          []witness.Floor
	mutate          func(*e2e2.HeadProof, int)
	choose          func(int) witness.Head
	unavailable     bool
	replay          bool
	previous        []byte
	mutateTransport bool
}

func (w *testWitness) Head(_ context.Context, c witness.Challenge) ([]byte, error) {
	w.calls++
	w.nonces = append(w.nonces, bytes.Clone(c.Nonce))
	w.floors = append(w.floors, c.Floor)
	if w.unavailable {
		return nil, errors.New("fake-private-witness-body")
	}
	if w.replay && w.previous != nil {
		return bytes.Clone(w.previous), nil
	}
	head := w.head
	if w.choose != nil {
		head = w.choose(w.calls)
	}
	proof := e2e2.HeadProof{Body: e2e2.HeadBody{Format: "sekvyr-e2e2-head-v1", Scope: codecScope(head.Scope), WitnessEpoch: head.WitnessEpoch,
		Sequence: head.Sequence, EnvelopeHash: head.EnvelopeHash, ReadKeyEpoch: head.ReadKeyEpoch, PublisherPolicyEpoch: head.PublisherPolicyEpoch,
		RequestNonce: base64.RawURLEncoding.EncodeToString(c.Nonce), WitnessKeyID: e2e2.KeyID(w.key.Public().(ed25519.PublicKey)), FloorSequence: c.Floor.Sequence, FloorHash: c.Floor.EnvelopeHash}}
	if w.mutate != nil {
		w.mutate(&proof, w.calls)
	}
	body, _ := json.Marshal(proof.Body)
	canonical, err := e2e2.Canonical(body, e2e2.MaxHeadProofBytes)
	if err != nil {
		return nil, err
	}
	proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(w.key, append(e2e2.Domain("sekvyr-e2e2/head/v1"), canonical...)))
	raw, err := json.Marshal(proof)
	if w.previous == nil {
		w.previous = bytes.Clone(raw)
	}
	if w.mutateTransport {
		clear(c.Nonce)
		if c.HighWatermark != nil {
			c.HighWatermark.Sequence = "0"
		}
	}
	return raw, err
}

type readerFixture struct {
	reader    *Reader
	trust     Trust
	node      *ecdh.PrivateKey
	publisher ed25519.PrivateKey
	key       []byte
	source    *testSource
	witness   *testWitness
	heads     []witness.Head
}

func newFixture(t *testing.T, snapshots int) *readerFixture {
	t.Helper()
	_, publisher, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, witnessKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	scope := witness.Scope{RealmID: "77777777-7777-4777-8777-777777777777", ProjectID: "88888888-8888-4888-8888-888888888888", EnvironmentID: "99999999-9999-4999-8999-999999999999", ViewID: "66666666-6666-4666-8666-666666666666", LogID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
	keys := map[string]ed25519.PublicKey{e2e2.KeyID(publisher.Public().(ed25519.PublicKey)): publisher.Public().(ed25519.PublicKey)}
	fingerprint, _ := e2e2.NodeKeyFingerprint(node.PublicKey())
	source := &testSource{envelopes: map[string][]byte{}}
	var heads []witness.Head
	previous := e2e2.ZeroHash
	for i := 1; i <= snapshots; i++ {
		action := "initial"
		if i > 1 {
			action = "update"
		}
		plain := e2e2.Plaintext{Format: "sekvyr-e2e2-values-v1", Context: codecScope(scope), Entries: []e2e2.Entry{{Path: "/runtime", Name: "TOKEN", Value: "fake-stage3-application-value-" + strconv.Itoa(i)}}}
		header := e2e2.Header{Protocol: "e2e2", Suite: "HKDF-SHA256+A256GCM+Ed25519", Intent: "publish", Scope: codecScope(scope), Sequence: strconv.Itoa(i), PreviousHash: previous, ReadKeyEpoch: "1", PublisherPolicyEpoch: "1", PublisherKeyID: e2e2.KeyID(publisher.Public().(ed25519.PublicKey)), EntryCount: 1, Action: action, Parents: []e2e2.Parent{}}
		raw, err := e2e2.SealSnapshot(header, plain, key, publisher)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := e2e2.EnvelopeHash(raw)
		if err != nil {
			t.Fatal(err)
		}
		source.envelopes[hash] = raw
		heads = append(heads, witness.Head{Scope: scope, WitnessEpoch: "1", Sequence: strconv.Itoa(i), EnvelopeHash: hash, ReadKeyEpoch: "1", PublisherPolicyEpoch: "1"})
		previous = hash
	}
	wrap, err := e2e2.WrapReader(e2e2.WrapContext{Protocol: "e2e2-reader-key-v1", Scope: codecScope(scope), ReadKeyEpoch: "1", PublisherPolicyEpoch: "1", PublisherKeyID: e2e2.KeyID(publisher.Public().(ed25519.PublicKey)), RecipientFingerprint: fingerprint}, key, node.PublicKey(), publisher)
	if err != nil {
		t.Fatal(err)
	}
	source.wrap = wrap
	w := &testWitness{key: witnessKey, head: heads[0]}
	trust := Trust{Scope: scope, PublisherPolicyEpoch: "1", PublisherKeys: keys, WitnessEpoch: "1", WitnessKeyID: e2e2.KeyID(witnessKey.Public().(ed25519.PublicKey)), WitnessPublicKey: witnessKey.Public().(ed25519.PublicKey), MinimumCheckpoint: witness.Floor{Sequence: "1", EnvelopeHash: heads[0].EnvelopeHash}, NodeFingerprint: fingerprint}
	reader, err := NewReader(trust, node, w, source)
	if err != nil {
		t.Fatal(err)
	}
	return &readerFixture{reader: reader, trust: trust, node: node, publisher: publisher, key: key, source: source, witness: w, heads: heads}
}
func expectReaderFailure(t *testing.T, f *readerFixture, local *witness.Head, reason string) {
	t.Helper()
	accepted, err := f.reader.ReadCurrent(context.Background(), local)
	var safe *Error
	if accepted != nil || !errors.As(err, &safe) || safe.Reason != reason {
		t.Fatalf("expected safe refusal %s; got %v", reason, err)
	}
	if strings.Contains(err.Error(), "fake-private-") {
		t.Fatal("upstream body leaked")
	}
}

func TestCurrentViewUsesTwoFreshProofsAndSignedWrap(t *testing.T) {
	f := newFixture(t, 1)
	f.witness.mutateTransport = true
	accepted, err := f.reader.ReadCurrent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.witness.calls != 2 || f.source.envelopeCalls != 1 || f.source.wrapCalls != 1 || bytes.Equal(f.witness.nonces[0], f.witness.nonces[1]) {
		t.Fatal("not two distinct freshness checks")
	}
	if accepted.Head() != f.heads[0] || len(accepted.Values()) != 1 || string(accepted.Values()[0].Data()) != "fake-stage3-application-value-1" {
		t.Fatal("verified view differs")
	}
	for _, text := range []string{fmt.Sprintf("%+v", accepted), fmt.Sprintf("%#v", accepted), fmt.Sprintf("%+v", accepted.Values())} {
		if strings.Contains(text, "fake-stage3-") {
			t.Fatal("formatting leaked value")
		}
	}
	raw, _ := json.Marshal(accepted)
	if bytes.Contains(raw, []byte("fake-stage3-")) {
		t.Fatal("JSON leaked value")
	}
	copy := accepted.Values()
	copy[0].data[0] ^= 1
	if string(accepted.Values()[0].Data()) != "fake-stage3-application-value-1" {
		t.Fatal("mutable accepted alias")
	}
}

func TestSignedReplayAndMisboundProofsFail(t *testing.T) {
	t.Run("replay", func(t *testing.T) {
		f := newFixture(t, 1)
		f.witness.replay = true
		expectReaderFailure(t, f, nil, "NonceMismatch")
	})
	t.Run("wrong nonce with valid signature", func(t *testing.T) {
		f := newFixture(t, 1)
		f.witness.mutate = func(p *e2e2.HeadProof, _ int) {
			p.Body.RequestNonce = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		}
		expectReaderFailure(t, f, nil, "NonceMismatch")
	})
	t.Run("wrong scope with valid signature", func(t *testing.T) {
		f := newFixture(t, 1)
		f.witness.mutate = func(p *e2e2.HeadProof, _ int) { p.Body.ViewID = "11111111-1111-4111-8111-111111111111" }
		expectReaderFailure(t, f, nil, "TrustMismatch")
	})
	t.Run("rollback", func(t *testing.T) {
		f := newFixture(t, 2)
		expectReaderFailure(t, f, &f.heads[1], "ProofInvalid")
		if f.source.envelopeCalls != 0 {
			t.Fatal("rollback reached source")
		}
	})
	t.Run("fork", func(t *testing.T) {
		f := newFixture(t, 1)
		local := f.heads[0]
		local.EnvelopeHash = strings.Repeat("b", 64)
		expectReaderFailure(t, f, &local, "ForkDetected")
		if f.witness.calls != 0 {
			t.Fatal("forged local floor reached network")
		}
	})
	t.Run("invalid local context", func(t *testing.T) {
		f := newFixture(t, 1)
		local := f.heads[0]
		local.Scope.ViewID = "11111111-1111-4111-8111-111111111111"
		expectReaderFailure(t, f, &local, "CheckpointInvalid")
		if f.witness.calls != 0 {
			t.Fatal("invalid local state reached network")
		}
	})
}

func TestHeadAdvanceRetriesFromHighestVerifiedFloor(t *testing.T) {
	f := newFixture(t, 2)
	f.witness.choose = func(call int) witness.Head {
		if call == 1 {
			return f.heads[0]
		}
		return f.heads[1]
	}
	accepted, err := f.reader.ReadCurrent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Head() != f.heads[1] || string(accepted.Values()[0].Data()) != "fake-stage3-application-value-2" || f.witness.calls != 4 || f.witness.floors[2].EnvelopeHash != f.heads[1].EnvelopeHash {
		t.Fatal("advanced head not retried from its verified floor")
	}
	f = newFixture(t, 4)
	f.witness.choose = func(call int) witness.Head { return f.heads[call/2] }
	expectReaderFailure(t, f, nil, "HeadChanged")
	if f.witness.calls != 6 || f.source.envelopeCalls != 3 {
		t.Fatal("head retry bounds ignored")
	}
	for i, nonce := range f.witness.nonces {
		for j := 0; j < i; j++ {
			if bytes.Equal(nonce, f.witness.nonces[j]) {
				t.Fatal("nonce reused across retries")
			}
		}
	}
}

func TestUnavailablePanelOrWitnessNeverReturnsPartialValues(t *testing.T) {
	t.Run("first witness", func(t *testing.T) {
		f := newFixture(t, 1)
		f.witness.unavailable = true
		expectReaderFailure(t, f, nil, "WitnessUnavailable")
		if f.source.envelopeCalls != 0 {
			t.Fatal("source fetched before witness")
		}
	})
	t.Run("panel", func(t *testing.T) {
		f := newFixture(t, 1)
		f.source.brokenEnvelope = true
		expectReaderFailure(t, f, nil, "CanonicalSnapshotUnavailable")
	})
	t.Run("wrapper", func(t *testing.T) {
		f := newFixture(t, 1)
		f.source.brokenWrap = true
		expectReaderFailure(t, f, nil, "ReadKeyUnavailable")
	})
	t.Run("second witness", func(t *testing.T) {
		f := newFixture(t, 1)
		f.witness.choose = func(_ int) witness.Head { f.witness.unavailable = true; return f.heads[0] }
		expectReaderFailure(t, f, nil, "WitnessUnavailable")
	})
	t.Run("tampered wrapper", func(t *testing.T) {
		f := newFixture(t, 1)
		var wrap e2e2.ReaderWrap
		json.Unmarshal(f.source.wrap, &wrap)
		wrap.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		f.source.wrap, _ = json.Marshal(wrap)
		expectReaderFailure(t, f, nil, "SignatureInvalid")
	})
}

func TestNoImplicitTrustAndNoCallerSuppliedCurrentHead(t *testing.T) {
	var reader *Reader
	if accepted, err := reader.ReadCurrent(context.Background(), nil); accepted != nil || err == nil {
		t.Fatal("zero reader accepted data")
	}
	f := newFixture(t, 1)
	trust := f.trust
	trust.MinimumCheckpoint = witness.Floor{Sequence: "0", EnvelopeHash: e2e2.ZeroHash}
	if _, err := NewReader(trust, f.node, f.witness, f.source); err == nil {
		t.Fatal("TOFU/genesis allowed")
	}
	if _, err := NewReader(f.trust, new(ecdh.PrivateKey), f.witness, f.source); err == nil {
		t.Fatal("uninitialized node accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	accepted, err := f.reader.ReadCurrent(ctx, nil)
	if accepted != nil || err == nil || f.witness.calls != 0 {
		t.Fatal("cancelled reader did external work")
	}
	for _, key := range f.trust.PublisherKeys {
		clear(key)
	}
	clear(f.trust.WitnessPublicKey)
	if _, err := f.reader.ReadCurrent(context.Background(), nil); err != nil {
		t.Fatal("constructor retained caller-owned mutable keys")
	}
}

type synchronizedHeads struct {
	mu    sync.Mutex
	inner *testWitness
}

func (h *synchronizedHeads) Head(ctx context.Context, c witness.Challenge) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.inner.Head(ctx, c)
}

type synchronizedSource struct {
	mu    sync.Mutex
	inner *testSource
}

func (s *synchronizedSource) EnvelopeByHash(ctx context.Context, scope witness.Scope, hash string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.EnvelopeByHash(ctx, scope, hash)
}
func (s *synchronizedSource) ReaderWrap(ctx context.Context, scope witness.Scope, hash, read, policy, fingerprint string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.ReaderWrap(ctx, scope, hash, read, policy, fingerprint)
}

func TestConcurrentReadersDoNotShareChallengeOrMutableAcceptedState(t *testing.T) {
	f := newFixture(t, 1)
	reader, err := NewReader(f.trust, f.node, &synchronizedHeads{inner: f.witness}, &synchronizedSource{inner: f.source})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			a, err := reader.ReadCurrent(context.Background(), nil)
			if err == nil && (a.Head() != f.heads[0] || len(a.Values()) != 1) {
				err = errors.New("concurrent verification changed result")
			}
			failures <- err
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.witness.calls != 16 {
		t.Fatal("concurrent readers skipped proof pair")
	}
	for i, nonce := range f.witness.nonces {
		for j := 0; j < i; j++ {
			if bytes.Equal(nonce, f.witness.nonces[j]) {
				t.Fatal("concurrent nonce reuse")
			}
		}
	}
}
