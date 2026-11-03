package syncer

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/rollout"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func authorize(context.Context) error { return nil }

func rolloutSetup(t *testing.T) (Engine, *api.SekvyrSecret, *api.SekvyrStore, api.Binding, *reviewWriter) {
	t.Helper()
	_, _, fingerprint := reviewReader(t, false, true)
	e, cr, store, b, w := reviewEngine(t, fingerprint)
	_ = appsv1.AddToScheme(w.Client.Scheme())
	cr.Generation = 1
	store.Generation = 1
	cr.Spec.StoreRef = api.StoreReference{Name: store.Name, UID: string(store.UID)}
	cr.Spec.Binding = b.Name
	cr.Spec.Rollout = api.RequestedRollout{Enabled: true, Deployments: []string{"app"}}
	b.Rollout.AllowedDeployments = []string{"app"}
	e.RolloutPolicy = rollout.Policy{Enabled: true, AllowedDeployments: []string{"app"}}
	e.Now = func() time.Time { return time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC) }
	return e, cr, store, b, w
}
func targetFor(t *testing.T, e Engine) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if e.Reader.Get(context.Background(), client.ObjectKey{Namespace: e.Config.Namespace, Name: "target"}, &s) != nil {
		t.Fatal("target missing")
	}
	return &s
}
func testDeployment(e Engine) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: e.Config.Namespace, UID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "target"}}}}}}}}}}
}

func TestRolloutEqualPlaintextAndForgedPublicMetadataNeverArm(t *testing.T) {
	ctx := context.Background()
	e, cr, store, b, w := rolloutSetup(t)
	first, _, _ := reviewReader(t, false, true)
	created, err := e.Sync(ctx, cr, store, b, first, authorize)
	if err != nil {
		t.Fatal(err)
	}
	if created.RolloutGuard != nil || reviewRecord(t, e).Rollout.Intent.Eligible {
		t.Fatal("initial rollout armed")
	}
	second, _, _ := reviewReader(t, true, true)
	equal, err := e.Sync(ctx, cr, store, b, second, authorize)
	if err != nil || equal.Changed || equal.Revision != created.Revision || equal.RolloutGuard != nil {
		t.Fatal("equal plaintext armed", err)
	}
	// Attacker changes only public target revision+intent, preserving verified bytes.
	target := targetFor(t, e)
	forged := reviewRecord(t, e).Rollout.Intent
	forged.Eligible = true
	forged.Context.TargetUID = string(target.UID)
	forged.Deployments = []rollout.DeploymentRef{{Name: "app", UID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}}
	forged.Revision = "99999999999999999999999999999999"
	raw, _ := rollout.Encode(forged)
	target.Annotations[intentAnnotation] = string(raw)
	target.Annotations[revisionAnnotation] = forged.Revision
	_ = w.Client.Update(ctx, target)
	result, err := e.Sync(ctx, cr, store, b, second, authorize)
	if err != nil || result.Changed || result.RolloutGuard != nil || result.RolloutReason != "RolloutStateAmbiguous" {
		t.Fatal("metadata forged permission", err, result.RolloutReason)
	}
}
func TestRolloutProtectedCandidateResolvesUIDAndPersistsNestedReceipt(t *testing.T) {
	ctx := context.Background()
	e, cr, store, b, w := rolloutSetup(t)
	first, _, _ := reviewReader(t, false, true)
	if _, err := e.Sync(ctx, cr, store, b, first, authorize); err != nil {
		t.Fatal(err)
	}
	second, _, _ := reviewReader(t, true, false)
	changed, err := e.Sync(ctx, cr, store, b, second, authorize)
	if err != nil || !changed.Changed || changed.RolloutReason != "DeploymentUnavailable" {
		t.Fatal("missing durable candidate", err, changed.RolloutReason)
	}
	candidate := reviewRecord(t, e).Rollout
	if !candidate.Intent.Eligible || candidate.Intent.Deployments[0].UID != "" {
		t.Fatal("candidate invalid")
	}
	if w.Client.Create(ctx, testDeployment(e)) != nil {
		t.Fatal("deployment fixture")
	}
	resumed, err := e.Sync(ctx, cr, store, b, second, authorize)
	if err != nil || resumed.Changed || resumed.Revision != changed.Revision || resumed.RolloutGuard == nil {
		t.Fatal("candidate not resumed", err, resumed.RolloutReason)
	}
	target := targetFor(t, e)
	i, err := rollout.Decode(target.Annotations[intentAnnotation])
	if err != nil || i.Deployments[0].UID == "" {
		t.Fatal("missing resolved UID", err)
	}
	if err = resumed.RolloutGuard.Confirm(ctx, target, i); err != nil {
		t.Fatal(err)
	}
	ref := i.Deployments[0]
	before := len(w.events)
	if err = resumed.RolloutGuard.MarkApplied(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if len(w.events) != before+1 || len(reviewRecord(t, e).Rollout.Applied) != 1 {
		t.Fatal("nested receipt mutation was not durable")
	}
	// A new guard after process/reconcile restart reads the protected receipt.
	again, err := e.Sync(ctx, cr, store, b, second, authorize)
	if err != nil || again.RolloutGuard == nil {
		t.Fatal(err)
	}
	applied, err := again.RolloutGuard.Applied(ctx, ref)
	if err != nil || !applied {
		t.Fatal("receipt lost", err)
	}
	// Neither data tampering nor cancelled authorization can use that guard.
	target.Data["tamper"] = []byte("public-canary")
	if again.RolloutGuard.Confirm(ctx, target, i) == nil {
		t.Fatal("unverified bytes authorized")
	}
	beforeTarget := targetFor(t, e)
	if err = e.CancelRollout(ctx, cr, store, b); err != nil {
		t.Fatal(err)
	}
	afterTarget := targetFor(t, e)
	if beforeTarget.ResourceVersion != afterTarget.ResourceVersion || !reviewRecord(t, e).Rollout.Cancelled {
		t.Fatal("cancel changed target or was not durable")
	}
	cancelled, err := e.Sync(ctx, cr, store, b, second, authorize)
	if err != nil || cancelled.RolloutGuard != nil {
		t.Fatal("revocation resumed old intent", err)
	}
}
func TestRolloutAuthorizationPrecedesDataCASAndNoMissingAuthRearm(t *testing.T) {
	ctx := context.Background()
	e, cr, store, b, w := rolloutSetup(t)
	first, _, _ := reviewReader(t, false, true)
	if _, err := e.Sync(ctx, cr, store, b, first, authorize); err != nil {
		t.Fatal(err)
	}
	_ = w.Client.Create(ctx, testDeployment(e))
	old := targetFor(t, e)
	w.failTarget = true
	second, _, _ := reviewReader(t, true, false)
	if _, err := e.Sync(ctx, cr, store, b, second, authorize); Reason(err) != "TargetConflict" {
		t.Fatal(err)
	}
	prepared := reviewRecord(t, e).Rollout
	if !prepared.Intent.Eligible || prepared.Intent.Revision == old.Annotations[revisionAnnotation] {
		t.Fatal("no prepared authorization")
	}
	current := targetFor(t, e)
	if current.Annotations[revisionAnnotation] != old.Annotations[revisionAnnotation] {
		t.Fatal("failed target CAS changed revision")
	}
	// A later successful verified data update may create a new authorized revision.
	w.failTarget = false
	recovered, err := e.Sync(ctx, cr, store, b, second, authorize)
	if err != nil || !recovered.Changed || recovered.RolloutGuard == nil {
		t.Fatal("data retry failed", err)
	}
	// Missing protected authorization is never synthesized by equal-data sync.
	var secret corev1.Secret
	_ = w.Client.Get(ctx, client.ObjectKey{Namespace: e.Config.Namespace, Name: e.Config.StateSecret.Name}, &secret)
	var state State
	_ = json.Unmarshal(secret.Data[StateKey], &state)
	for key, r := range state.Bindings {
		r.Rollout = nil
		state.Bindings[key] = r
	}
	secret.Data[StateKey], _ = json.Marshal(state)
	_ = w.Client.Update(ctx, &secret)
	equal, err := e.Sync(ctx, cr, store, b, second, authorize)
	if err != nil || equal.RolloutGuard != nil || reviewRecord(t, e).Rollout != nil {
		t.Fatal("missing auth rearmed", err)
	}
}

func TestRolloutStaleCancellationDoesNotRevokeNewContextOrAuthorization(t *testing.T) {
	ctx := context.Background()
	e, cr, store, b, w := rolloutSetup(t)
	first, _, _ := reviewReader(t, false, true)
	_, _ = e.Sync(ctx, cr, store, b, first, authorize)
	_ = w.Client.Create(ctx, testDeployment(e))
	second, _, _ := reviewReader(t, true, false)
	current, err := e.Sync(ctx, cr, store, b, second, authorize)
	if err != nil || current.RolloutGuard == nil {
		t.Fatal(err)
	}
	cr.Generation++
	if err = e.CancelRollout(ctx, cr, store, b); err != nil || reviewRecord(t, e).Rollout.Cancelled {
		t.Fatal("wrong generation cancelled active intent", err)
	}
	cr.Generation--
	expected := e.expected(cr, store, b)
	key := expected.StoreUID + "/" + expected.BindingID
	_, err = e.state().update(ctx, key, expected, func(r *Record) error {
		next := r.Rollout.Intent
		next.Revision = "abcdefabcdefabcdefabcdefabcdefab"
		a, err := rollout.Authorize(next)
		if err != nil {
			return err
		}
		r.Rollout = a
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = current.RolloutGuard.Cancel(ctx); Reason(err) != "RolloutAuthorizationChanged" || reviewRecord(t, e).Rollout.Cancelled {
		t.Fatal("stale guard cancelled newer authorization", err)
	}
}

func TestRolloutDisableGenerationDoesNotBlockDataSyncOrCancelNewContext(t *testing.T) {
	ctx := context.Background()
	e, cr, store, b, w := rolloutSetup(t)
	first, _, _ := reviewReader(t, false, true)
	if _, err := e.Sync(ctx, cr, store, b, first, authorize); err != nil {
		t.Fatal(err)
	}
	_ = w.Client.Create(ctx, testDeployment(e))
	second, _, _ := reviewReader(t, true, false)
	if _, err := e.Sync(ctx, cr, store, b, second, authorize); err != nil {
		t.Fatal(err)
	}
	cr.Generation++
	cr.Spec.Rollout.Enabled = false
	if err := e.CancelRollout(ctx, cr, store, b); err != nil {
		t.Fatal("disabled CR blocked Secret sync", err)
	}
	if reviewRecord(t, e).Rollout.Cancelled {
		t.Fatal("changed context cancelled another generation")
	}
	result, err := e.Sync(ctx, cr, store, b, second, authorize)
	if err != nil || result.Changed || result.RolloutGuard != nil || result.RolloutReason != "RolloutInvalidated" {
		t.Fatal("disabled data sync failed", err, result.RolloutReason)
	}
	// A newer context may be independently authorized; an older in-flight
	// cancellation must not invalidate it or report a blocking data error.
	expected := e.expected(cr, store, b)
	key := expected.StoreUID + "/" + expected.BindingID
	_, err = e.state().update(ctx, key, expected, func(r *Record) error {
		next := r.Rollout.Intent
		next.Context = rollout.NewContext(cr, store, b, e.Config.BootstrapGeneration, r.TargetUID)
		a, err := rollout.Authorize(next)
		if err != nil {
			return err
		}
		r.Rollout = a
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	stale := cr.DeepCopy()
	stale.Generation--
	if err = e.CancelRollout(ctx, stale, store, b); err != nil || reviewRecord(t, e).Rollout.Cancelled {
		t.Fatal("stale caller cancelled newer context", err)
	}
}
