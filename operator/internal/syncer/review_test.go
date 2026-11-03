package syncer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/verification"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// These transports deliver real signed/encrypted public fixtures to the real
// Reader. No Accepted or Value can be fabricated by the synchronization tests.
type reviewSource struct{ envelope, wrapper []byte }

func (s reviewSource) EnvelopeByHash(context.Context, witness.Scope, string) ([]byte, error) {
	return bytes.Clone(s.envelope), nil
}
func (s reviewSource) ReaderWrap(context.Context, witness.Scope, string, string, string, string) ([]byte, error) {
	return bytes.Clone(s.wrapper), nil
}

type reviewHeads struct {
	head   witness.Head
	signer ed25519.PrivateKey
}

func (p reviewHeads) Head(_ context.Context, c witness.Challenge) ([]byte, error) {
	body := e2e2.HeadBody{Format: "sekvyr-e2e2-head-v1", Scope: e2e2.Scope{RealmID: p.head.Scope.RealmID, ProjectID: p.head.Scope.ProjectID, EnvironmentID: p.head.Scope.EnvironmentID, ViewID: p.head.Scope.ViewID, LogID: p.head.Scope.LogID}, WitnessEpoch: p.head.WitnessEpoch, Sequence: p.head.Sequence, EnvelopeHash: p.head.EnvelopeHash, ReadKeyEpoch: p.head.ReadKeyEpoch, PublisherPolicyEpoch: p.head.PublisherPolicyEpoch, RequestNonce: base64.RawURLEncoding.EncodeToString(c.Nonce), WitnessKeyID: e2e2.KeyID(p.signer.Public().(ed25519.PublicKey)), FloorSequence: c.Floor.Sequence, FloorHash: c.Floor.EnvelopeHash}
	raw, _ := json.Marshal(body)
	canonical, err := e2e2.Canonical(raw, e2e2.MaxHeadProofBytes)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(p.signer, append(e2e2.Domain("sekvyr-e2e2/head/v1"), canonical...))
	return json.Marshal(e2e2.HeadProof{Body: body, Signature: base64.RawURLEncoding.EncodeToString(signature)})
}
func reviewMaterial(label string) []byte {
	sum := sha256.Sum256([]byte("sekvyr-e2e2-public-test-vector/" + label))
	return bytes.Clone(sum[:])
}
func reviewReader(t *testing.T, second bool, sameValues bool) (*verification.Reader, witness.Head, string) {
	t.Helper()
	raw, err := os.ReadFile("../../design/e2e2.public-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Envelope  json.RawMessage `json:"envelope"`
		Plaintext e2e2.Plaintext  `json:"plaintext"`
		Hash      string          `json:"envelope_hash"`
		Publisher string          `json:"publisher_public_key"`
		Witness   string          `json:"witness_public_key"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid public fixture")
	}
	var envelope e2e2.Envelope
	if err := e2e2.DecodeStrict(fixture.Envelope, &envelope, e2e2.MaxEnvelopeBytes); err != nil {
		t.Fatal(err)
	}
	if second {
		header := envelope.Body.Header
		header.Sequence = "2"
		header.PreviousHash = fixture.Hash
		header.Action = "update"
		if !sameValues {
			fixture.Plaintext.Entries[0].Value = "canary-value-2"
		}
		fixture.Envelope, err = e2e2.SealSnapshot(header, fixture.Plaintext, reviewMaterial("view-read"), ed25519.NewKeyFromSeed(reviewMaterial("publisher")))
		if err != nil {
			t.Fatal(err)
		}
	}
	hash, err := e2e2.EnvelopeHash(fixture.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := e2e2.DecodeStrict(fixture.Envelope, &envelope, e2e2.MaxEnvelopeBytes); err != nil {
		t.Fatal(err)
	}
	wrapperRaw, err := os.ReadFile("../../tests/e2e2/public-reader-wrap-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var wrap struct {
		Scalar  string          `json:"public_test_node_scalar"`
		Wrapper json.RawMessage `json:"wrapper"`
	}
	if json.Unmarshal(wrapperRaw, &wrap) != nil {
		t.Fatal("invalid wrapper fixture")
	}
	scalar, _ := e2e2.DecodeBase64(wrap.Scalar, 32)
	node, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := e2e2.NodeKeyFingerprint(node.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	h := envelope.Body.Header
	scope := witness.Scope{RealmID: h.RealmID, ProjectID: h.ProjectID, EnvironmentID: h.EnvironmentID, ViewID: h.ViewID, LogID: h.LogID}
	head := witness.Head{Scope: scope, WitnessEpoch: "1", Sequence: h.Sequence, EnvelopeHash: hash, ReadKeyEpoch: "1", PublisherPolicyEpoch: "1"}
	pub, _ := e2e2.DecodeBase64(fixture.Publisher, 32)
	wpub, _ := e2e2.DecodeBase64(fixture.Witness, 32)
	trust := verification.Trust{Scope: scope, PublisherPolicyEpoch: "1", PublisherKeys: map[string]ed25519.PublicKey{e2e2.KeyID(ed25519.PublicKey(pub)): ed25519.PublicKey(pub)}, WitnessEpoch: "1", WitnessKeyID: e2e2.KeyID(ed25519.PublicKey(wpub)), WitnessPublicKey: ed25519.PublicKey(wpub), MinimumCheckpoint: witness.Floor{Sequence: "1", EnvelopeHash: fixture.Hash}, NodeFingerprint: fingerprint}
	reader, err := verification.NewReader(trust, node, reviewHeads{head: head, signer: ed25519.NewKeyFromSeed(reviewMaterial("witness"))}, reviewSource{envelope: fixture.Envelope, wrapper: wrap.Wrapper})
	if err != nil {
		t.Fatal(err)
	}
	return reader, head, fingerprint
}

type reviewWriter struct {
	client.Client
	t                     *testing.T
	config                installation.Config
	events                []string
	failState, failTarget bool
}

func (w *reviewWriter) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	secret, ok := obj.(*corev1.Secret)
	if !ok || secret.Name != "target" {
		w.t.Fatal("unexpected object write")
	}
	var state corev1.Secret
	if err := w.Client.Get(ctx, client.ObjectKey{Namespace: w.config.Namespace, Name: w.config.StateSecret.Name}, &state); err != nil {
		w.t.Fatal(err)
	}
	var decoded State
	if json.Unmarshal(state.Data[StateKey], &decoded) != nil || len(decoded.Bindings) != 1 {
		w.t.Fatal("target create before durable checkpoint")
	}
	for _, record := range decoded.Bindings {
		if record.Mode == "Plain" && record.Head != nil || record.Mode != "Plain" && record.Head == nil {
			w.t.Fatal("target create without durable head")
		}
	}
	w.events = append(w.events, "target-create")
	secret.SetUID(types.UID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"))
	return w.Client.Create(ctx, obj, opts...)
}
func (w *reviewWriter) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		w.t.Fatal("unexpected non-Secret mutation")
	}
	if secret.Name == w.config.StateSecret.Name {
		w.events = append(w.events, "state")
		if w.failState {
			return errors.New("synthetic-state-unavailable")
		}
	} else {
		w.events = append(w.events, "target-update")
		if w.failTarget {
			return apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, secret.Name, errors.New("synthetic-CAS-conflict"))
		}
	}
	return w.Client.Update(ctx, obj, opts...)
}
func reviewEngine(t *testing.T, fingerprint string) (Engine, *api.SekvyrSecret, *api.SekvyrStore, api.Binding, *reviewWriter) {
	t.Helper()
	cfg := installation.Config{InstallationID: "11111111-1111-4111-8111-111111111111", Namespace: "review-system", ServiceAccount: "operator", BootstrapGeneration: 1, AllowedTargetSecrets: []string{"target"}, StateSecret: installation.SecretPin{Name: "state", UID: "22222222-2222-4222-8222-222222222222", Key: "installation.json"}, TrustBundleSecret: installation.SecretPin{Name: "trust", UID: "33333333-3333-4333-8333-333333333333", Key: "trust.json"}, IdentityKeySecret: installation.SecretPin{Name: "identity", UID: "44444444-4444-4444-8444-444444444444", Key: "node.pem"}}
	state := State{Version: 1, InstallationID: cfg.InstallationID, BootstrapGeneration: 1, TrustBundleUID: cfg.TrustBundleSecret.UID, NodeFingerprint: fingerprint, Bindings: map[string]Record{}}
	raw, _ := json.Marshal(state)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "state", Namespace: cfg.Namespace, UID: types.UID(cfg.StateSecret.UID)}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{StateKey: raw}}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	writer := &reviewWriter{Client: fakeClient, t: t, config: cfg}
	cr := &api.SekvyrSecret{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: cfg.Namespace, UID: "55555555-5555-4555-8555-555555555555"}}
	store := &api.SekvyrStore{ObjectMeta: metav1.ObjectMeta{Name: "store", Namespace: cfg.Namespace, UID: "77777777-7777-4777-8777-777777777777"}}
	b := api.Binding{ID: "88888888-8888-4888-8888-888888888888", Name: "binding", ResourceName: cr.Name, Source: api.Source{Group: "", Project: "app", Environment: "prod", PathPrefix: "/", ViewID: "66666666-6666-4666-8666-666666666666"}, Selection: api.Selection{Mode: "All"}, Encryption: api.Encryption{Mode: "E2E", Protocol: "e2e2", TrustKey: "review", Freshness: &api.Freshness{Mode: "WitnessCurrent"}}, Target: api.Target{Name: "target", DeletionPolicy: "Retain"}}
	return Engine{Config: cfg, Reader: fakeClient, Writer: writer, NodeFingerprint: fingerprint}, cr, store, b, writer
}
func reviewRecord(t *testing.T, e Engine) Record {
	t.Helper()
	_, state, err := e.state().load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Bindings) != 1 {
		t.Fatal("unexpected registry count")
	}
	for _, record := range state.Bindings {
		return record
	}
	t.Fatal("record missing")
	return Record{}
}

func TestReviewCheckpointDurableBeforeTargetAndNoAdoption(t *testing.T) {
	reader, head, fingerprint := reviewReader(t, false, true)
	e, cr, store, b, writer := reviewEngine(t, fingerprint)
	ctx := context.Background()
	authorize := func(context.Context) error { return nil }
	result, err := e.Sync(ctx, cr, store, b, reader, authorize)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || len(result.Revision) != 32 {
		t.Fatal("initial sync failed")
	}
	record := reviewRecord(t, e)
	if record.Head == nil || *record.Head != head || record.TargetUID == "" {
		t.Fatal("checkpoint/target ownership not durable")
	}
	if len(writer.events) < 4 || writer.events[0] != "state" || writer.events[1] != "state" || writer.events[2] != "target-create" {
		t.Fatal("write ordering wrong")
	}
	var target corev1.Secret
	if e.Reader.Get(ctx, client.ObjectKey{Namespace: e.Config.Namespace, Name: b.Target.Name}, &target) != nil {
		t.Fatal("target missing")
	}
	if len(target.OwnerReferences) != 0 {
		t.Fatal("Retain target unexpectedly garbage collected")
	}
	var intent struct {
		Eligible bool `json:"eligible"`
	}
	if json.Unmarshal([]byte(target.Annotations[intentAnnotation]), &intent) != nil || intent.Eligible {
		t.Fatal("stage 4 created rollout eligibility")
	}
	cr.UID = "99999999-9999-4999-8999-999999999999"
	if _, err := e.Preflight(ctx, cr, store, b); Reason(err) != "OwnershipConflict" {
		t.Fatal("recreated CR adopted previous target")
	}
}
func TestReviewStateFailureNeverCreatesTarget(t *testing.T) {
	reader, _, fingerprint := reviewReader(t, false, true)
	e, cr, store, b, writer := reviewEngine(t, fingerprint)
	writer.failState = true
	if _, err := e.Sync(context.Background(), cr, store, b, reader, func(context.Context) error { return nil }); Reason(err) != "StateWriteFailed" {
		t.Fatal("state failure not preserved")
	}
	for _, event := range writer.events {
		if event != "state" {
			t.Fatal("target mutation after state failure")
		}
	}
}
func TestReviewCASFailurePreservesAdvancedCheckpoint(t *testing.T) {
	first, _, fingerprint := reviewReader(t, false, true)
	e, cr, store, b, writer := reviewEngine(t, fingerprint)
	ctx := context.Background()
	authorize := func(context.Context) error { return nil }
	if _, err := e.Sync(ctx, cr, store, b, first, authorize); err != nil {
		t.Fatal(err)
	}
	second, head, _ := reviewReader(t, true, false)
	writer.failTarget = true
	if _, err := e.Sync(ctx, cr, store, b, second, authorize); Reason(err) != "TargetConflict" {
		t.Fatal("target CAS conflict not rejected")
	}
	record := reviewRecord(t, e)
	if record.Head == nil || *record.Head != head {
		t.Fatal("accepted checkpoint lost after failed target CAS")
	}
	var target corev1.Secret
	_ = e.Reader.Get(ctx, client.ObjectKey{Namespace: e.Config.Namespace, Name: b.Target.Name}, &target)
	if string(target.Data["DEMO_VALUE"]) != "canary-value-1" {
		t.Fatal("failed target CAS changed values")
	}
}
func TestReviewNoOpAdvancesCheckpointWithoutDataRevisionOrRollout(t *testing.T) {
	first, _, fingerprint := reviewReader(t, false, true)
	e, cr, store, b, writer := reviewEngine(t, fingerprint)
	ctx := context.Background()
	authorize := func(context.Context) error { return nil }
	initial, err := e.Sync(ctx, cr, store, b, first, authorize)
	if err != nil {
		t.Fatal(err)
	}
	second, head, _ := reviewReader(t, true, true)
	before := len(writer.events)
	result, err := e.Sync(ctx, cr, store, b, second, authorize)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Revision != initial.Revision {
		t.Fatal("same plaintext triggered a data revision")
	}
	record := reviewRecord(t, e)
	if record.Head == nil || *record.Head != head {
		t.Fatal("new canonical checkpoint not persisted")
	}
	for _, event := range writer.events[before:] {
		if event == "target-create" {
			t.Fatal("no-op created a target")
		}
	}
}
func TestReviewPreexistingTargetAndStateReplacementFailClosed(t *testing.T) {
	_, _, fingerprint := reviewReader(t, false, true)
	e, cr, store, b, writer := reviewEngine(t, fingerprint)
	ctx := context.Background()
	preexisting := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: b.Target.Name, Namespace: e.Config.Namespace, UID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"DEMO_VALUE": []byte("unowned")}}
	if err := writer.Client.Create(ctx, preexisting); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Preflight(ctx, cr, store, b); Reason(err) != "OwnershipConflict" {
		t.Fatal("unowned target adopted")
	}
	var state corev1.Secret
	_ = writer.Client.Get(ctx, client.ObjectKey{Namespace: e.Config.Namespace, Name: e.Config.StateSecret.Name}, &state)
	_ = writer.Client.Delete(ctx, &state)
	state.ResourceVersion = ""
	state.UID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	if writer.Client.Create(ctx, &state) != nil {
		t.Fatal("replacement setup failed")
	}
	if _, _, err := e.state().load(ctx); Reason(err) != "StateReplaced" {
		t.Fatal("replacement state trusted")
	}
}

func TestReviewRegistryAdvanceBeforeTargetStopsOldAcceptedHead(t *testing.T) {
	first, _, fingerprint := reviewReader(t, false, true)
	second, _, _ := reviewReader(t, true, false)
	ctx := context.Background()
	newer, err := second.ReadCurrent(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	e, cr, store, b, writer := reviewEngine(t, fingerprint)
	calls := 0
	authorize := func(ctx context.Context) error {
		calls++
		if calls != 3 {
			return nil
		}
		// Simulate a second authorized worker durably accepting a newer real
		// verified head after this worker's state CAS, before its target write.
		var stateSecret corev1.Secret
		if err := writer.Client.Get(ctx, client.ObjectKey{Namespace: e.Config.Namespace, Name: e.Config.StateSecret.Name}, &stateSecret); err != nil {
			return err
		}
		var state State
		if err := json.Unmarshal(stateSecret.Data[StateKey], &state); err != nil {
			return err
		}
		for key, record := range state.Bindings {
			head := newer.Head()
			record.Head = &head
			state.Bindings[key] = record
		}
		raw, err := json.Marshal(state)
		if err != nil {
			return err
		}
		stateSecret.Data[StateKey] = raw
		return writer.Client.Update(ctx, &stateSecret)
	}
	if _, err := e.Sync(ctx, cr, store, b, first, authorize); Reason(err) != "HeadChanged" {
		t.Fatal("older accepted head survived a newer durable registry checkpoint", err)
	}
	for _, event := range writer.events {
		if event == "target-create" || event == "target-update" {
			t.Fatal("target changed after a higher checkpoint became known")
		}
	}
	if record := reviewRecord(t, e); record.Head == nil || *record.Head != newer.Head() {
		t.Fatal("concurrent newer checkpoint was overwritten")
	}
}
