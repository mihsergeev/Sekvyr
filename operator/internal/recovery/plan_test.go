package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
)

func testID(n string) string { return n + "0000000-0000-4000-8000-000000000000" }
func fixture(t *testing.T) (installation.Config, journal.CurrentState, Body, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	admin := journal.Key{KeyID: e2e2.KeyID(pub), PublicKey: base64.RawURLEncoding.EncodeToString(pub)}
	ca := installation.CARef{Name: "trust-ca", Key: "ca.crt"}
	cfg := installation.Config{InstallationID: testID("1"), Namespace: "trial-system", ServiceAccount: "operator", BootstrapGeneration: 2, AllowedPanelOrigins: []string{"https://panel.example.invalid"}, AllowedWitnessOrigins: []string{"https://witness.example.invalid"}, IdentityKeySecret: installation.SecretPin{Name: "node", UID: testID("2"), Key: "node.pem"}, TrustBundleSecret: installation.SecretPin{Name: "trust", UID: testID("3"), Key: "trust.json"}, StateSecret: installation.SecretPin{Name: "state", UID: testID("4"), Key: "installation.json"}, AllowedTargetSecrets: []string{"target"}, CAConfigMaps: []installation.CAPin{{Name: ca.Name, UID: testID("5"), Key: ca.Key, DERSetSHA256: strings.Repeat("a", 64)}}}
	cfg.HA = &installation.HAConfig{Trial: true, FencerOrigin: "https://fencer.example.invalid", AllowedFencerOrigins: []string{"https://fencer.example.invalid"}, FencerCAConfigMapRef: &ca, GatewayOrigin: "https://journal.example.invalid", GatewayCAConfigMapRef: &ca, GatewayClientSecret: installation.SecretPin{Name: "journal-client", UID: testID("6"), Key: "tls.crt"}, GatewayClientKeyKey: "tls.key", Journal: journal.Registration{LogID: testID("7"), GenesisHash: strings.Repeat("b", 64), AdminPublicKey: admin.PublicKey, MinimumCursor: journal.Cursor{JournalSequence: "0", RecordHash: strings.Repeat("b", 64)}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal("invalid test config", err)
	}
	scope := e2e2.Scope{RealmID: testID("8"), ProjectID: testID("9"), EnvironmentID: testID("a"), ViewID: testID("b"), LogID: testID("7")}
	state := journal.CurrentState{Scope: scope, GenesisHash: cfg.HA.Journal.GenesisHash, Cursor: journal.Cursor{JournalSequence: "7", RecordHash: strings.Repeat("c", 64)}, Snapshot: journal.Snapshot{Sequence: "4", EnvelopeHash: strings.Repeat("d", 64), ReadKeyEpoch: "2", PublisherPolicyEpoch: "2"}, Authority: journal.Authority{AdminKey: admin, WitnessEpoch: "2"}, Enrollments: map[string]journal.Enrollment{}}
	fp := "p256-sha256:" + strings.Repeat("e", 64)
	state.Enrollments[cfg.InstallationID] = journal.Enrollment{BootstrapGeneration: 2, Namespace: cfg.Namespace, OperatorServiceAccount: cfg.ServiceAccount, NodeFingerprint: fp, IdentityKeySecretUID: cfg.IdentityKeySecret.UID, TrustBundleSecretUID: cfg.TrustBundleSecret.UID, AllowedObjects: []journal.ObjectRef{{APIVersion: "v1", Kind: "Secret", Namespace: cfg.Namespace, Name: "state", UID: cfg.StateSecret.UID}, {APIVersion: "v1", Kind: "Secret", Namespace: cfg.Namespace, Name: "target", UID: testID("c")}}}
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	body := Body{Format: "sekvyr-checkpoint-recovery-v1", Operation: "recover", RecoveryID: testID("d"), InstallationID: cfg.InstallationID, PreviousBootstrapGeneration: 1, PreviousStateSecretUID: testID("e"), BootstrapGeneration: 2, StateSecretName: "state", StateSecretUID: cfg.StateSecret.UID, IdentityKeySecretUID: cfg.IdentityKeySecret.UID, TrustBundleSecretUID: cfg.TrustBundleSecret.UID, NodeFingerprint: fp, Scope: scope, GenesisHash: state.GenesisHash, Cursor: state.Cursor, Snapshot: state.Snapshot, Binding: Binding{StoreName: "store", StoreUID: testID("f"), CRName: "binding", CRUID: testID("8"), BindingID: testID("9"), ViewID: scope.ViewID, TargetName: "target", TargetUID: testID("c"), CRGeneration: 1, StoreGeneration: 1, Identity: strings.Repeat("f", 64)}, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), ExpectedStateSHA256: strings.Repeat("a", 64)}
	return cfg, state, body, key, now
}

func TestExplicitInitializationDoesNotAuthorizeRecoveryReset(t *testing.T) {
	cfg, state, b, key, now := fixture(t)
	cfg.BootstrapGeneration = 1
	enrolled := state.Enrollments[cfg.InstallationID]
	enrolled.BootstrapGeneration = 1
	state.Enrollments[cfg.InstallationID] = enrolled
	b.Operation = "initialize"
	b.PreviousBootstrapGeneration = 0
	b.PreviousStateSecretUID = ""
	b.BootstrapGeneration = 1
	empty := sha256.Sum256(nil)
	b.ExpectedStateSHA256 = hex.EncodeToString(empty[:])
	if _, err := Verify(context.Background(), encoded(t, b, key), cfg, state, now); err != nil {
		t.Fatal("explicit initial plan rejected", err)
	}
	b.Operation = "recover"
	if _, err := Verify(context.Background(), encoded(t, b, key), cfg, state, now); err == nil {
		t.Fatal("initialization accepted as recovery")
	}
	b.Operation = "initialize"
	b.ExpectedStateSHA256 = strings.Repeat("a", 64)
	if _, err := Verify(context.Background(), encoded(t, b, key), cfg, state, now); err == nil {
		t.Fatal("initialization could overwrite existing state")
	}
}
func encoded(t *testing.T, b Body, k ed25519.PrivateKey) []byte {
	t.Helper()
	p, err := Sign(b, k)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestRecoveryExactCurrentAuthorityAndBindings(t *testing.T) {
	cfg, state, b, key, now := fixture(t)
	accepted, err := Verify(context.Background(), encoded(t, b, key), cfg, state, now)
	if err != nil || accepted.Head() != state.Head() || accepted.Body() != b || len(accepted.Hash()) != 64 {
		t.Fatal("valid independent plan rejected", err)
	}
	// A valid signature does not authorize another current cursor, enrollment,
	// bootstrap, target UID, expiration, or already rotated administrative key.
	tests := map[string]func(*Body, *journal.CurrentState){
		"cursor rollback":          func(b *Body, _ *journal.CurrentState) { b.Cursor.JournalSequence = "6" },
		"fork":                     func(b *Body, _ *journal.CurrentState) { b.Cursor.RecordHash = strings.Repeat("f", 64) },
		"snapshot rollback":        func(b *Body, _ *journal.CurrentState) { b.Snapshot.Sequence = "3" },
		"wrong target":             func(b *Body, _ *journal.CurrentState) { b.Binding.TargetUID = testID("e") },
		"same state UID":           func(b *Body, _ *journal.CurrentState) { b.PreviousStateSecretUID = b.StateSecretUID },
		"old bootstrap":            func(b *Body, _ *journal.CurrentState) { b.BootstrapGeneration = 1 },
		"expired":                  func(b *Body, _ *journal.CurrentState) { b.ExpiresAt = now.Format(time.RFC3339) },
		"long lived":               func(b *Body, _ *journal.CurrentState) { b.ExpiresAt = now.Add(25 * time.Hour).Format(time.RFC3339) },
		"malformed expected state": func(b *Body, _ *journal.CurrentState) { b.ExpectedStateSHA256 = "" },
		"different node":           func(b *Body, _ *journal.CurrentState) { b.NodeFingerprint = "p256-sha256:" + strings.Repeat("f", 64) },
		"rotated admin": func(_ *Body, s *journal.CurrentState) {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			s.Authority.AdminKey, _ = journal.KeyFromPublic(pub)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := b
			s := state
			mutate(&changed, &s)
			if _, err := Verify(context.Background(), encoded(t, changed, key), cfg, s, now); err == nil {
				t.Fatal("unsafe recovery accepted")
			}
		})
	}
}
func TestRecoveryRejectsUnsignedEditsAndAmbiguousWire(t *testing.T) {
	cfg, state, b, key, now := fixture(t)
	raw := encoded(t, b, key)
	var p Plan
	_ = json.Unmarshal(raw, &p)
	p.Body.AllowRollout = true
	edited, _ := json.Marshal(p)
	unknown := append(append([]byte{}, raw[:len(raw)-1]...), []byte(",\"extra\":true}")...)
	duplicate := append(append([]byte{}, raw[:len(raw)-1]...), []byte(",\"key_id\":\"duplicate\"}")...)
	for _, bad := range [][]byte{edited, unknown, duplicate, []byte("null"), append(raw, raw...)} {
		if _, err := Verify(context.Background(), bad, cfg, state, now); err == nil {
			t.Fatal("malformed or edited plan accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Verify(ctx, raw, cfg, state, now); err == nil {
		t.Fatal("cancelled recovery accepted")
	}
	if _, err := Sign(b, make([]byte, 64)); err == nil {
		t.Fatal("invalid private signing key accepted")
	}
}
