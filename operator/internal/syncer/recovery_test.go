package syncer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	"github.com/mihsergeev/Sekvyr/operator/internal/recovery"
	"github.com/mihsergeev/Sekvyr/operator/internal/verification"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func recoverySetup(t *testing.T, changed bool) (Engine, *api.SekvyrSecret, *api.SekvyrStore, api.Binding, *reviewWriter, *recovery.Accepted, *verification.Accepted) {
	t.Helper()
	return recoverySetupRollout(t, changed, false)
}
func recoverySetupRollout(t *testing.T, changed, allowRollout bool) (Engine, *api.SekvyrSecret, *api.SekvyrStore, api.Binding, *reviewWriter, *recovery.Accepted, *verification.Accepted) {
	t.Helper()
	ctx := context.Background()
	e, cr, store, b, w := rolloutSetup(t)
	first, _, _ := reviewReader(t, false, true)
	if _, err := e.Sync(ctx, cr, store, b, first, authorize); err != nil {
		t.Fatal(err)
	}
	oldStateUID := e.Config.StateSecret.UID
	var previous corev1.Secret
	_ = e.Reader.Get(ctx, client.ObjectKey{Namespace: e.Config.Namespace, Name: e.Config.StateSecret.Name}, &previous)
	if err := w.Client.Delete(ctx, &previous); err != nil {
		t.Fatal(err)
	}
	e.Config.StateSecret.UID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	e.Config.BootstrapGeneration = 2
	e.Config.AllowedPanelOrigins = []string{"https://panel.example.invalid"}
	e.Config.AllowedWitnessOrigins = []string{"https://witness.example.invalid"}
	ref := &installation.CARef{Name: "trial-ca", Key: "ca.crt"}
	e.Config.CAConfigMaps = []installation.CAPin{{Name: ref.Name, Key: ref.Key, UID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", DERSetSHA256: strings.Repeat("a", 64)}}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub64 := base64.RawURLEncoding.EncodeToString(pub)
	next, head, _ := reviewReader(t, changed, !changed)
	accepted, err := next.ReadCurrent(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := journal.CurrentState{Scope: e2e2.Scope{RealmID: head.Scope.RealmID, ProjectID: head.Scope.ProjectID, EnvironmentID: head.Scope.EnvironmentID, ViewID: head.Scope.ViewID, LogID: head.Scope.LogID}, GenesisHash: strings.Repeat("b", 64), Cursor: journal.Cursor{JournalSequence: "8", RecordHash: strings.Repeat("c", 64)}, Snapshot: journal.Snapshot{Sequence: head.Sequence, EnvelopeHash: head.EnvelopeHash, ReadKeyEpoch: head.ReadKeyEpoch, PublisherPolicyEpoch: head.PublisherPolicyEpoch}, Authority: journal.Authority{AdminKey: journal.Key{KeyID: e2e2.KeyID(pub), PublicKey: pub64}, WitnessEpoch: head.WitnessEpoch}, Enrollments: map[string]journal.Enrollment{}}
	e.Config.HA = &installation.HAConfig{Trial: true, FencerOrigin: "https://fencer.example.invalid", AllowedFencerOrigins: []string{"https://fencer.example.invalid"}, FencerCAConfigMapRef: ref, GatewayOrigin: "https://journal.example.invalid", GatewayCAConfigMapRef: ref, GatewayClientSecret: installation.SecretPin{Name: "journal-client", UID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Key: "tls.crt"}, GatewayClientKeyKey: "tls.key", Journal: journal.Registration{LogID: head.Scope.LogID, GenesisHash: state.GenesisHash, AdminPublicKey: pub64, MinimumCursor: journal.Cursor{JournalSequence: "0", RecordHash: state.GenesisHash}}}
	target := targetFor(t, e)
	state.Enrollments[e.Config.InstallationID] = journal.Enrollment{BootstrapGeneration: 2, Namespace: e.Config.Namespace, OperatorServiceAccount: e.Config.ServiceAccount, NodeFingerprint: e.NodeFingerprint, IdentityKeySecretUID: e.Config.IdentityKeySecret.UID, TrustBundleSecretUID: e.Config.TrustBundleSecret.UID, AllowedObjects: []journal.ObjectRef{{APIVersion: "v1", Kind: "Secret", Namespace: e.Config.Namespace, Name: e.Config.StateSecret.Name, UID: e.Config.StateSecret.UID}, {APIVersion: "v1", Kind: "Secret", Namespace: e.Config.Namespace, Name: target.Name, UID: string(target.UID)}}}
	newState := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: e.Config.StateSecret.Name, Namespace: e.Config.Namespace, UID: types.UID(e.Config.StateSecret.UID)}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{}}
	if err := w.Client.Create(ctx, newState); err != nil {
		t.Fatal(err)
	}
	w.config = e.Config
	now := time.Now()
	body := recovery.Body{Format: "sekvyr-checkpoint-recovery-v1", Operation: "recover", RecoveryID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", InstallationID: e.Config.InstallationID, PreviousBootstrapGeneration: 1, PreviousStateSecretUID: oldStateUID, BootstrapGeneration: 2, StateSecretName: e.Config.StateSecret.Name, StateSecretUID: e.Config.StateSecret.UID, IdentityKeySecretUID: e.Config.IdentityKeySecret.UID, TrustBundleSecretUID: e.Config.TrustBundleSecret.UID, NodeFingerprint: e.NodeFingerprint, Scope: state.Scope, GenesisHash: state.GenesisHash, Cursor: state.Cursor, Snapshot: state.Snapshot, Binding: recovery.Binding{StoreName: store.Name, StoreUID: string(store.UID), CRName: cr.Name, CRUID: string(cr.UID), BindingID: b.ID, ViewID: b.Source.ViewID, TargetName: target.Name, TargetUID: string(target.UID), CRGeneration: cr.Generation, StoreGeneration: store.Generation, Identity: bindingIdentity(b)}, ExpiresAt: now.Add(time.Hour).UTC().Format(time.RFC3339), ExpectedStateSHA256: StateDigest(nil)}
	body.AllowRollout = allowRollout
	signed, err := recovery.Sign(body, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)
	plan, err := recovery.Verify(ctx, raw, e.Config, state, now)
	if err != nil {
		t.Fatal(err)
	}
	w.events = nil
	return e, cr, store, b, w, plan, accepted
}

func TestRecoveryRolloutRequiresSignedOptInAndActualChangedBytes(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "equal", true: "changed"}[changed], func(t *testing.T) {
			e, cr, store, b, w, plan, accepted := recoverySetupRollout(t, changed, true)
			if err := w.Client.Create(context.Background(), testDeployment(e)); err != nil {
				t.Fatal(err)
			}
			if err := e.RestoreCheckpoint(context.Background(), plan, accepted, cr, store, b, authorize); err != nil {
				t.Fatal(err)
			}
			auth := reviewRecord(t, e).Rollout
			if auth.Intent.Eligible != changed {
				t.Fatal("rollout eligibility ignored actual data change")
			}
			if changed && (len(auth.Intent.Deployments) != 1 || auth.Intent.Deployments[0].UID == "") {
				t.Fatal("new explicit recovery rollout lacks independent Deployment pin")
			}
		})
	}
}

func TestRecoverySameBytesPreservesRevisionAndInvalidatesRollout(t *testing.T) {
	e, cr, store, b, w, plan, accepted := recoverySetup(t, false)
	before := targetFor(t, e).Annotations[revisionAnnotation]
	if err := e.RestoreCheckpoint(context.Background(), plan, accepted, cr, store, b, authorize); err != nil {
		t.Fatal(err)
	}
	target := targetFor(t, e)
	record := reviewRecord(t, e)
	if target.Annotations[revisionAnnotation] != before || record.Rollout.Intent.Eligible || record.Rollout.Cancelled {
		t.Fatal("same-byte recovery changed revision or restored pending rollout")
	}
	if len(w.events) != 3 || w.events[0] != "state" || w.events[1] != "target-update" || w.events[2] != "state" {
		t.Fatal("recovery ordering", w.events)
	}
	beforeEvents := len(w.events)
	if err := e.RestoreCheckpoint(context.Background(), plan, accepted, cr, store, b, authorize); err != nil || len(w.events) != beforeEvents {
		t.Fatal("completed plan replay caused mutation", err)
	}
}

func TestRecoveryTargetFailureBlocksRuntimeAndExactRetryCompletes(t *testing.T) {
	e, cr, store, b, w, plan, accepted := recoverySetup(t, true)
	before := targetFor(t, e).Data
	w.failTarget = true
	if err := e.RestoreCheckpoint(context.Background(), plan, accepted, cr, store, b, authorize); Reason(err) != "RecoveryTargetWriteFailed" {
		t.Fatal("injected target failure", err)
	}
	if _, err := e.Preflight(context.Background(), cr, store, b); Reason(err) != "RecoveryPending" {
		t.Fatal("runtime admitted partial recovery", err)
	}
	if !equalData(before, targetFor(t, e).Data) {
		t.Fatal("target changed despite failed CAS")
	}
	var state corev1.Secret
	_ = e.Reader.Get(context.Background(), client.ObjectKey{Namespace: e.Config.Namespace, Name: e.Config.StateSecret.Name}, &state)
	var prepared State
	_ = json.Unmarshal(state.Data[StateKey], &prepared)
	var revision string
	for _, r := range prepared.Bindings {
		revision = r.Rollout.Intent.Revision
	}
	w.failTarget = false
	if err := e.RestoreCheckpoint(context.Background(), plan, accepted, cr, store, b, authorize); err != nil {
		t.Fatal(err)
	}
	if targetFor(t, e).Annotations[revisionAnnotation] != revision || equalData(before, targetFor(t, e).Data) {
		t.Fatal("retry rebased revision or failed value update")
	}
	if _, err := e.Preflight(context.Background(), cr, store, b); err != nil {
		t.Fatal("completed recovery remains blocked", err)
	}
}

func TestRecoveryDeniesChangedStateBindingOrOfflineJournal(t *testing.T) {
	for _, mode := range []string{"state", "binding", "journal"} {
		t.Run(mode, func(t *testing.T) {
			e, cr, store, b, w, plan, accepted := recoverySetup(t, true)
			if mode == "state" {
				var s corev1.Secret
				_ = e.Reader.Get(context.Background(), client.ObjectKey{Namespace: e.Config.Namespace, Name: e.Config.StateSecret.Name}, &s)
				if s.Data == nil {
					s.Data = map[string][]byte{}
				}
				s.Data[StateKey] = []byte("unreviewed")
				_ = w.Client.Update(context.Background(), &s)
			}
			if mode == "binding" {
				store.Generation++
			}
			check := authorize
			if mode == "journal" {
				check = func(context.Context) error { return errors.New("synthetic journal unavailable") }
			}
			before := targetFor(t, e).Data
			if err := e.RestoreCheckpoint(context.Background(), plan, accepted, cr, store, b, check); err == nil {
				t.Fatal("unsafe recovery admitted")
			}
			if len(w.events) != 0 || !equalData(before, targetFor(t, e).Data) {
				t.Fatal("denied recovery wrote objects")
			}
		})
	}
}

type recoveryLostAck struct {
	client.Client
	phase string
	fired bool
}

func (w *recoveryLostAck) Update(ctx context.Context, obj client.Object, options ...client.UpdateOption) error {
	phase := "target"
	if secret, ok := obj.(*corev1.Secret); ok && secret.Name == "state" {
		var state State
		_ = json.Unmarshal(secret.Data[StateKey], &state)
		if state.Recovery != nil {
			phase = state.Recovery.Phase
		}
	}
	if err := w.Client.Update(ctx, obj, options...); err != nil {
		return err
	}
	if phase == w.phase && !w.fired {
		w.fired = true
		return errors.New("synthetic lost response after durable write")
	}
	return nil
}
func TestRecoveryResolvesEveryLostResponseWithoutDuplicateTargetUpdate(t *testing.T) {
	for _, phase := range []string{"prepared", "target", "complete"} {
		t.Run(phase, func(t *testing.T) {
			e, cr, store, b, w, plan, accepted := recoverySetup(t, true)
			lost := &recoveryLostAck{Client: e.Writer, phase: phase}
			e.Writer = lost
			if err := e.RestoreCheckpoint(context.Background(), plan, accepted, cr, store, b, authorize); err == nil || !lost.fired {
				t.Fatal("lost acknowledgement not injected")
			}
			if phase != "complete" {
				if _, err := e.Preflight(context.Background(), cr, store, b); Reason(err) != "RecoveryPending" {
					t.Fatal("partial lost acknowledgement not fail-closed", err)
				}
			}
			if err := e.RestoreCheckpoint(context.Background(), plan, accepted, cr, store, b, authorize); err != nil {
				t.Fatal("exact recovery retry did not resolve durable write", err)
			}
			updates := 0
			for _, event := range w.events {
				if event == "target-update" {
					updates++
				}
			}
			if updates != 1 {
				t.Fatal("duplicate target write after lost acknowledgement", updates)
			}
			if reviewRecord(t, e).Rollout.Intent.Eligible {
				t.Fatal("recovery armed rollout without signed authorization")
			}
		})
	}
}

type recoveryJournalAdvanceWriter struct {
	client.Client
	advanced *bool
}

func (w recoveryJournalAdvanceWriter) Update(ctx context.Context, obj client.Object, options ...client.UpdateOption) error {
	if err := w.Client.Update(ctx, obj, options...); err != nil {
		return err
	}
	if obj.GetName() == "target" {
		*w.advanced = true
	}
	return nil
}
func TestRecoveryConcurrentJournalAdvanceLeavesPendingWithoutFalseCompletion(t *testing.T) {
	e, cr, store, b, w, plan, accepted := recoverySetup(t, true)
	advanced := false
	e.Writer = recoveryJournalAdvanceWriter{Client: e.Writer, advanced: &advanced}
	check := func(context.Context) error {
		if advanced {
			return fail("RecoveryJournalChanged")
		}
		return nil
	}
	if err := e.RestoreCheckpoint(context.Background(), plan, accepted, cr, store, b, check); Reason(err) != "RecoveryJournalChanged" {
		t.Fatal("concurrent commit not detected", err)
	}
	if _, err := e.Preflight(context.Background(), cr, store, b); Reason(err) != "RecoveryPending" {
		t.Fatal("concurrent commit produced false complete", err)
	}
	if string(targetFor(t, e).Data["DEMO_VALUE"]) != "canary-value-2" {
		t.Fatal("last fully verified values lost")
	}
	if len(w.events) != 2 || w.events[0] != "state" || w.events[1] != "target-update" {
		t.Fatal("unexpected completion after journal advance", w.events)
	}
}
