package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

// Every deterministic scalar in this file is public synthetic test material.
func material(label string) []byte {
	h := sha256.Sum256([]byte("sekvyr-e2e2-public-test-vector/" + label))
	return append([]byte(nil), h[:]...)
}
func private(label string) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(material(label)) }
func testKey(t *testing.T, label string) Key {
	t.Helper()
	key, err := KeyFromPublic(private(label).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type memoryStorage struct {
	mu       sync.Mutex
	slots    []StoredSlot
	loseNext bool
	reads    int
}

func (m *memoryStorage) ReadAll(context.Context, string) ([]StoredSlot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	out := make([]StoredSlot, len(m.slots))
	for n, s := range m.slots {
		out[n] = StoredSlot{Raw: append([]byte(nil), s.Raw...), Receipt: s.Receipt}
	}
	return out, nil
}
func (m *memoryStorage) PutIfAbsent(_ context.Context, _ string, n uint64, raw []byte) (RetentionReceipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n != uint64(len(m.slots)) {
		return RetentionReceipt{}, Failure("CASConflict")
	}
	receipt := RetentionReceipt{VersionID: "public-version-" + fmtCounter(n), Mode: "COMPLIANCE", RetainUntil: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)}
	m.slots = append(m.slots, StoredSlot{Raw: append([]byte(nil), raw...), Receipt: receipt})
	if m.loseNext {
		m.loseNext = false
		return RetentionReceipt{}, Failure("StorageUnavailable")
	}
	return receipt, nil
}

type journalFixture struct {
	ledger       *Ledger
	store        *memoryStorage
	registration Registration
	state        CurrentState
	genesis      Record
	envelope     e2e2.Envelope
	plain        e2e2.Plaintext
	vectorRaw    []byte
}

func setupJournal(t *testing.T) *journalFixture {
	t.Helper()
	raw, err := os.ReadFile("../../design/e2e2.public-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Envelope  e2e2.Envelope  `json:"envelope"`
		Plaintext e2e2.Plaintext `json:"plaintext"`
	}
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("public vector")
	}
	scope := vector.Envelope.Body.Header.Scope
	authority := Authority{Revision: "1", AdminKey: testKey(t, "journal-admin"), PublisherPolicyEpoch: "1", PublisherKeys: []Key{testKey(t, "publisher")}, ReadKeyEpoch: "1", WitnessEpoch: "1", WitnessKey: testKey(t, "witness"), FencerEpoch: "1", FencerKeys: []Key{testKey(t, "journal-fencer")}}
	signed, err := SignGenesis(GenesisBody{Format: "sekvyr-journal-genesis-v1", Scope: scope, PanelOrigin: "https://panel.example.test", Authority: authority}, private("journal-admin"))
	if err != nil {
		t.Fatal(err)
	}
	record := NewGenesisRecord(signed)
	hash, err := RecordHash(record)
	if err != nil {
		t.Fatal(err)
	}
	registration := Registration{LogID: scope.LogID, GenesisHash: hash, AdminPublicKey: authority.AdminKey.PublicKey, MinimumCursor: Cursor{JournalSequence: "0", RecordHash: hash}}
	store := &memoryStorage{}
	ledger, err := New(store, []Registration{registration}, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := EncodeRecord(record)
	state, err := ledger.InitializeCAS(context.Background(), scope.LogID, encoded)
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, _ := json.Marshal(vector.Envelope)
	return &journalFixture{ledger: ledger, store: store, registration: registration, state: state, genesis: record, envelope: vector.Envelope, plain: vector.Plaintext, vectorRaw: envelopeRaw}
}
func (f *journalFixture) initial(t *testing.T) {
	t.Helper()
	state, err := f.ledger.AppendSnapshotCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, f.vectorRaw)
	if err != nil {
		t.Fatal(err)
	}
	f.state = state
}
func (f *journalFixture) snapshot(t *testing.T, authority Authority, label, action string) e2e2.Envelope {
	t.Helper()
	header := f.envelope.Body.Header
	header.Sequence, _ = nextCounter(f.state.Snapshot.Sequence)
	header.PreviousHash = f.state.Snapshot.EnvelopeHash
	header.PublisherPolicyEpoch = authority.PublisherPolicyEpoch
	header.ReadKeyEpoch = authority.ReadKeyEpoch
	header.PublisherKeyID = testKey(t, label).KeyID
	header.Action = action
	if action == "restore" {
		h := f.state.History["1"]
		header.RestoredFrom = &h
	} else {
		header.RestoredFrom = nil
	}
	plain := f.plain
	plain.Entries = append([]e2e2.Entry(nil), f.plain.Entries...)
	plain.Entries[0].Value = "public-canary-" + authority.Revision
	raw, err := e2e2.SealSnapshot(header, plain, material("view-read"), private(label))
	if err != nil {
		t.Fatal(err)
	}
	var envelope e2e2.Envelope
	if e2e2.DecodeStrict(raw, &envelope, e2e2.MaxEnvelopeBytes) != nil {
		t.Fatal("sealed fixture")
	}
	return envelope
}
func (f *journalFixture) transition(t *testing.T, kind string, next Authority, enrollment *Enrollment, envelope *e2e2.Envelope) (CurrentState, error) {
	t.Helper()
	body := TransitionBody{Format: "sekvyr-authority-transition-v1", Scope: f.state.Scope, GenesisHash: f.state.GenesisHash, Expected: f.state.Cursor, PreviousAuthorityDigest: f.state.AuthorityDigest, Kind: kind, Authority: next, Enrollment: enrollment, ActivatingEnvelope: envelope}
	label := "journal-admin"
	if f.state.Authority.AdminKey == testKey(t, "journal-admin-2") {
		label = "journal-admin-2"
	}
	signed, err := SignTransition(body, private(label))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)
	state, err := f.ledger.AppendTransitionCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, raw)
	if err == nil {
		f.state = state
	}
	return state, err
}
func nextAuthority(t *testing.T, a Authority) Authority {
	t.Helper()
	a.Revision, _ = nextCounter(a.Revision)
	return a
}

func TestJournalConcurrentCanonicalSlotAndLostAcknowledgement(t *testing.T) {
	f := setupJournal(t)
	f.initial(t)
	a := f.snapshot(t, f.state.Authority, "publisher", "update")
	b := f.snapshot(t, f.state.Authority, "publisher", "update")
	rawA, _ := json.Marshal(a)
	rawB, _ := json.Marshal(b)
	expected := f.state.Cursor
	results := make(chan error, 2)
	for _, raw := range [][]byte{rawA, rawB} {
		go func(raw []byte) {
			_, err := f.ledger.AppendSnapshotCAS(context.Background(), f.state.Scope.LogID, expected, raw)
			results <- err
		}(raw)
	}
	success, conflict := 0, 0
	for n := 0; n < 2; n++ {
		err := <-results
		if err == nil {
			success++
		} else if Reason(err) == "CASConflict" {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 || len(f.store.slots) != 3 {
		t.Fatal("split brain accepted multiple slots")
	}
	current, err := f.ledger.ReadCurrent(context.Background(), f.state.Scope.LogID, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	f.state = current
	next := f.snapshot(t, f.state.Authority, "publisher", "update")
	raw, _ := json.Marshal(next)
	f.store.loseNext = true
	resolved, err := f.ledger.AppendSnapshotCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, raw)
	if err != nil || resolved.Snapshot.Sequence != "3" {
		t.Fatal("exact committed candidate was not resolved", err)
	}
	after, err := f.ledger.ReadCurrent(context.Background(), f.state.Scope.LogID, f.state.Cursor)
	if err != nil || after.Snapshot.Sequence != "3" {
		t.Fatal("committed tail lost", err)
	}
	if _, err = f.ledger.AppendSnapshotCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, raw); err != nil || len(f.store.slots) != 4 {
		t.Fatal("exact retry created another slot", err)
	}
	different := f.snapshot(t, f.state.Authority, "publisher", "update")
	differentRaw, _ := json.Marshal(different)
	if _, err = f.ledger.AppendSnapshotCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, differentRaw); Reason(err) != "CASConflict" {
		t.Fatal("different candidate resolved as committed", err)
	}
	f.store.slots = f.store.slots[:2]
	if _, err = f.ledger.ReadCurrent(context.Background(), f.state.Scope.LogID, after.Cursor); Reason(err) != "JournalBelowCheckpoint" {
		t.Fatal("restore below independent floor accepted", err)
	}
}
func TestJournalAuthorityRotationReplaysHistoricalKeysAndActivatesAtomically(t *testing.T) {
	f := setupJournal(t)
	f.initial(t)
	next := nextAuthority(t, f.state.Authority)
	next.PublisherPolicyEpoch = "2"
	next.PublisherKeys = []Key{testKey(t, "publisher-2")}
	if _, err := f.transition(t, "rotate-publisher", next, nil, nil); Reason(err) != "ActivationSnapshotRequired" {
		t.Fatal("unactivated policy accepted", err)
	}
	if len(f.store.slots) != 2 {
		t.Fatal("failed transition wrote slot")
	}
	envelope := f.snapshot(t, next, "publisher-2", "update")
	if _, err := f.transition(t, "rotate-publisher", next, nil, &envelope); err != nil {
		t.Fatal(err)
	}
	if f.state.Snapshot.Sequence != "2" || len(f.state.History) != 3 {
		t.Fatal("activation not atomic")
	}
	historical, err := f.ledger.ReadCurrent(context.Background(), f.state.Scope.LogID, Cursor{})
	if err != nil || historical.Authority.PublisherKeys[0] != next.PublisherKeys[0] {
		t.Fatal("historical old-key prefix not valid", err)
	}
	stale := f.snapshot(t, f.state.Authority, "publisher", "update")
	raw, _ := json.Marshal(stale)
	if _, err = f.ledger.AppendSnapshotCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, raw); Reason(err) != "EnvelopeInvalid" {
		t.Fatal("revoked publisher committed", err)
	}
	next = nextAuthority(t, f.state.Authority)
	next.ReadKeyEpoch = "2"
	envelope = f.snapshot(t, next, "publisher-2", "rotate-read-key")
	if _, err = f.transition(t, "rotate-read-key", next, nil, &envelope); err != nil {
		t.Fatal(err)
	}
	next = nextAuthority(t, f.state.Authority)
	next.WitnessEpoch = "2"
	next.WitnessKey = testKey(t, "witness-2")
	snapshotBefore := f.state.Snapshot
	if _, err = f.transition(t, "rotate-witness", next, nil, nil); err != nil {
		t.Fatal(err)
	}
	if f.state.Snapshot != snapshotBefore || f.state.Cursor.JournalSequence == f.state.Snapshot.Sequence {
		t.Fatal("journal/snapshot sequences conflated")
	}
	proofNonce := base64Nonce()
	body := AuthorityProofBody{Format: "sekvyr-authority-proof-v2", State: f.state.AuthorityView(), RequestNonce: proofNonce, Floor: f.registration.MinimumCursor}
	proof, err := SignAuthorityProof(body, private("witness-2"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyAuthorityProof(proof, f.state.Scope, f.state.GenesisHash, next.WitnessKey, proofNonce, f.registration.MinimumCursor); err != nil {
		t.Fatal(err)
	}
	if _, err = SignAuthorityProof(body, private("witness")); Reason(err) != "SigningKeyMismatch" {
		t.Fatal("old witness signed current proof", err)
	}
	if _, err = VerifyAuthorityProof(proof, f.state.Scope, f.state.GenesisHash, testKey(t, "witness"), proofNonce, f.registration.MinimumCursor); err == nil {
		t.Fatal("historical witness key accepted")
	}
}
func base64Nonce() string { return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
func enrollment(t *testing.T) Enrollment {
	t.Helper()
	refs, err := CanonicalObjectRefs([]ObjectRef{{APIVersion: "v1", Kind: "Secret", Namespace: "trial", Name: "state", UID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, {APIVersion: "v1", Kind: "Secret", Namespace: "trial", Name: "target", UID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}, {APIVersion: "apps/v1", Kind: "Deployment", Namespace: "trial", Name: "app", UID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc"}})
	if err != nil {
		t.Fatal(err)
	}
	return Enrollment{InstallationID: "11111111-1111-4111-8111-111111111111", BootstrapGeneration: 1, Namespace: "trial", NamespaceUID: "22222222-2222-4222-8222-222222222222", OperatorServiceAccount: "operator", OperatorServiceAccountUID: "33333333-3333-4333-8333-333333333333", FencerServiceAccount: "fencer", FencerServiceAccountUID: "44444444-4444-4444-8444-444444444444", Lease: ObjectRef{APIVersion: "coordination.k8s.io/v1", Kind: "Lease", Namespace: "trial", Name: "operator", UID: "55555555-5555-4555-8555-555555555555"}, NodeFingerprint: "p256-sha256:" + stringHash("public-node"), IdentityKeySecretUID: "66666666-6666-4666-8666-666666666666", TrustBundleSecretUID: "77777777-7777-4777-8777-777777777777", AllowedObjects: refs}
}
func stringHash(s string) string {
	hash := sha256.Sum256([]byte(s))
	const chars = "0123456789abcdef"
	out := make([]byte, 64)
	for n, b := range hash {
		out[n*2] = chars[b>>4]
		out[n*2+1] = chars[b&15]
	}
	return string(out)
}
func (f *journalFixture) grant(t *testing.T, e Enrollment, term, previous, signer, holder string) (SignedFenceGrant, error) {
	t.Helper()
	body := FenceGrant{Format: "sekvyr-fence-grant-v1", Scope: f.state.Scope, GenesisHash: f.state.GenesisHash, InstallationID: e.InstallationID, BootstrapGeneration: e.BootstrapGeneration, OwnerPodUID: "88888888-8888-4888-8888-888888888888", LeaseHolderIdentity: holder, Term: term, PreviousGrantHash: previous, AuthorityDigest: f.state.AuthorityDigest, Snapshot: f.state.Snapshot, Objects: e.AllowedObjects}
	g, err := SignFenceGrant(body, private(signer))
	if err != nil {
		return g, err
	}
	raw, _ := json.Marshal(g)
	state, err := f.ledger.AppendFenceGrantCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, raw)
	if err == nil {
		f.state = state
	}
	return g, err
}
func TestJournalFencePendingActivationMonotonicTermsAndRotations(t *testing.T) {
	f := setupJournal(t)
	f.initial(t)
	e := enrollment(t)
	next := nextAuthority(t, f.state.Authority)
	if _, err := f.transition(t, "enroll-installation", next, &e, nil); err != nil {
		t.Fatal(err)
	}
	g, err := f.grant(t, e, "1", ZeroHash, "journal-fencer", "operator_uid_process-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.state.CurrentGrant(e.InstallationID); !ok {
		t.Fatal("pending grant missing")
	}
	if _, ok := f.state.ActiveGrant(e.InstallationID); ok {
		t.Fatal("unactivated grant active")
	}
	hash, _ := FenceGrantHash(g.Body)
	body := FenceActivation{Format: "sekvyr-fence-activation-v1", Scope: f.state.Scope, GenesisHash: f.state.GenesisHash, InstallationID: e.InstallationID, BootstrapGeneration: 1, OwnerPodUID: g.Body.OwnerPodUID, LeaseHolderIdentity: g.Body.LeaseHolderIdentity, Term: "1", GrantHash: hash, AuthorityDigest: f.state.AuthorityDigest, Snapshot: f.state.Snapshot, Objects: e.AllowedObjects}
	activation, _ := SignFenceActivation(body, private("journal-fencer"))
	raw, _ := json.Marshal(activation)
	f.state, err = f.ledger.AppendFenceActivationCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.state.ActiveGrant(e.InstallationID); !ok {
		t.Fatal("activation not durable")
	}
	second, err := f.grant(t, e, "2", hash, "journal-fencer", "operator_uid_process-2")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.state.ActiveGrant(e.InstallationID); ok {
		t.Fatal("old activation reused for new session")
	}
	if _, err = f.ledger.AppendFenceActivationCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, raw); Reason(err) != "GrantCASConflict" && Reason(err) != "ActivationInvalid" {
		t.Fatal("old activation accepted", err)
	}
	next = nextAuthority(t, f.state.Authority)
	next.FencerEpoch = "2"
	next.FencerKeys = []Key{testKey(t, "journal-fencer-2")}
	if _, err = f.transition(t, "rotate-fencer", next, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.state.CurrentGrant(e.InstallationID); ok {
		t.Fatal("old authority grant valid")
	}
	secondHash, _ := FenceGrantHash(second.Body)
	if _, err = f.grant(t, e, "3", secondHash, "journal-fencer", "operator_uid_process-3"); err == nil {
		t.Fatal("old fencer minted grant")
	}
	if _, err = f.grant(t, e, "1", ZeroHash, "journal-fencer-2", "operator_uid_process-3"); Reason(err) != "GrantCASConflict" {
		t.Fatal("term reset after rotation", err)
	}
	if _, err = f.grant(t, e, "3", secondHash, "journal-fencer-2", "operator_uid_process-3"); err != nil {
		t.Fatal(err)
	}
	next = nextAuthority(t, f.state.Authority)
	next.AdminKey = testKey(t, "journal-admin-2")
	if _, err = f.transition(t, "rotate-admin", next, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = f.ledger.ReadCurrent(context.Background(), f.state.Scope.LogID, Cursor{}); err != nil {
		t.Fatal("root handover broke historical genesis pin", err)
	}
}
func TestJournalCorruptAndBelowRetentionNeverReturnState(t *testing.T) {
	for _, kind := range []string{"retention", "version", "gap", "signature", "unknown", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			f := setupJournal(t)
			f.initial(t)
			switch kind {
			case "retention":
				f.store.slots[1].Receipt.Mode = "GOVERNANCE"
			case "version":
				f.store.slots[1].Receipt.VersionID = ""
			case "gap":
				r, _ := DecodeRecord(f.store.slots[1].Raw)
				r.JournalSequence = "9"
				f.store.slots[1].Raw, _ = EncodeRecord(r)
			case "signature":
				r, _ := DecodeRecord(f.store.slots[1].Raw)
				r.Envelope.Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				f.store.slots[1].Raw, _ = EncodeRecord(r)
			case "unknown":
				f.store.slots[1].Raw = append(f.store.slots[1].Raw[:len(f.store.slots[1].Raw)-1], []byte(",\"unexpected\":1}")...)
			case "duplicate":
				f.store.slots[1].Raw = append([]byte("{\"format\":\"forged\","), f.store.slots[1].Raw[1:]...)
			}
			if _, err := f.ledger.ReadCurrent(context.Background(), f.state.Scope.LogID, Cursor{}); err == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
}

func TestJournalAuthorityRolesStayIndependentAcrossHistory(t *testing.T) {
	f := setupJournal(t)
	f.initial(t)
	next := nextAuthority(t, f.state.Authority)
	next.AdminKey = next.WitnessKey
	if _, err := f.transition(t, "rotate-admin", next, nil, nil); err == nil {
		t.Fatal("witness key became administrative root")
	}
	next = nextAuthority(t, f.state.Authority)
	oldWitness := next.WitnessKey
	next.WitnessEpoch = "2"
	next.WitnessKey = testKey(t, "witness-2")
	if _, err := f.transition(t, "rotate-witness", next, nil, nil); err != nil {
		t.Fatal(err)
	}
	next = nextAuthority(t, f.state.Authority)
	next.AdminKey = oldWitness
	if _, err := f.transition(t, "rotate-admin", next, nil, nil); Reason(err) != "AuthorityRoleConflict" {
		t.Fatal("historical witness was promoted to admin", err)
	}
	next = nextAuthority(t, f.state.Authority)
	next.FencerEpoch = "2"
	next.FencerKeys = []Key{next.PublisherKeys[0]}
	if _, err := f.transition(t, "rotate-fencer", next, nil, nil); err == nil {
		t.Fatal("publisher key became fencer")
	}
}

func TestJournalSignedRecoveryAppendsWithoutResettingHistory(t *testing.T) {
	f := setupJournal(t)
	f.initial(t)
	next := nextAuthority(t, f.state.Authority)
	next.WitnessEpoch = "2"
	next.WitnessKey = testKey(t, "witness-2")
	envelope := f.snapshot(t, next, "publisher", "restore")
	body := TransitionBody{Format: "sekvyr-authority-transition-v1", Scope: f.state.Scope, GenesisHash: f.state.GenesisHash, Expected: f.state.Cursor, PreviousAuthorityDigest: f.state.AuthorityDigest, Kind: "recover", Authority: next, ActivatingEnvelope: &envelope, RecoveryFrom: &RecoveryLink{LogID: f.state.Scope.LogID, GenesisHash: f.state.GenesisHash, MinimumCursor: f.state.Cursor, SnapshotSequence: "1", EnvelopeHash: f.state.Snapshot.EnvelopeHash}}
	signed, err := SignTransition(body, private("journal-admin"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)
	state, err := f.ledger.AppendTransitionCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, raw)
	if err != nil || state.Snapshot.Sequence != "2" || state.History["1"] != f.state.Snapshot.EnvelopeHash || state.Cursor.JournalSequence != "2" {
		t.Fatal("recovery reset authority history", err)
	}
	body.Expected = state.Cursor
	body.PreviousAuthorityDigest = state.AuthorityDigest
	body.Authority.Revision = "3"
	body.Authority.WitnessEpoch = "1"
	signed, _ = SignTransition(body, private("journal-admin"))
	raw, _ = json.Marshal(signed)
	if _, err = f.ledger.AppendTransitionCAS(context.Background(), state.Scope.LogID, state.Cursor, raw); err == nil {
		t.Fatal("recovery decreased epoch")
	}
}

func TestFenceGrantInvalidatedByEqualPlaintextCanonicalAdvance(t *testing.T) {
	f := setupJournal(t)
	f.initial(t)
	e := enrollment(t)
	next := nextAuthority(t, f.state.Authority)
	if _, err := f.transition(t, "enroll-installation", next, &e, nil); err != nil {
		t.Fatal(err)
	}
	g, err := f.grant(t, e, "1", ZeroHash, "journal-fencer", "operator_process-1")
	if err != nil {
		t.Fatal(err)
	}
	grantHash, _ := FenceGrantHash(g.Body)
	a := FenceActivation{Format: "sekvyr-fence-activation-v1", Scope: f.state.Scope, GenesisHash: f.state.GenesisHash, InstallationID: e.InstallationID, BootstrapGeneration: e.BootstrapGeneration, OwnerPodUID: g.Body.OwnerPodUID, LeaseHolderIdentity: g.Body.LeaseHolderIdentity, Term: g.Body.Term, GrantHash: grantHash, AuthorityDigest: f.state.AuthorityDigest, Snapshot: f.state.Snapshot, Objects: e.AllowedObjects}
	signed, err := SignFenceActivation(a, private("journal-fencer"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)
	f.state, err = f.ledger.AppendFenceActivationCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, raw)
	if err != nil {
		t.Fatal(err)
	}
	beforeDigest := f.state.AuthorityDigest
	h := f.envelope.Body.Header
	h.Sequence = "2"
	h.Action = "update"
	h.PreviousHash = f.state.Snapshot.EnvelopeHash
	raw, err = e2e2.SealSnapshot(h, f.plain, material("view-read"), private("publisher"))
	if err != nil {
		t.Fatal(err)
	}
	f.state, err = f.ledger.AppendSnapshotCAS(context.Background(), f.state.Scope.LogID, f.state.Cursor, raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.state.AuthorityDigest != beforeDigest {
		t.Fatal("snapshot spuriously changed authority policy")
	}
	if _, ok := f.state.CurrentGrant(e.InstallationID); ok {
		t.Fatal("old grant authorized a newer snapshot")
	}
	if _, ok := f.state.ActiveGrant(e.InstallationID); ok {
		t.Fatal("old activation survived new canonical data")
	}
	if f.state.Grants[e.InstallationID].Body.Term != "1" {
		t.Fatal("term high-watermark lost")
	}
	if _, err = f.grant(t, e, "2", grantHash, "journal-fencer", "operator_process-1"); err != nil {
		t.Fatal("current snapshot could not prepare next term", err)
	}
}
