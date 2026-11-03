package syncer

import (
	"context"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Replaying Kubernetes content with a NEW API resourceVersion is an ordinary
// administrative restore. Even fresh nonce-signed old witness answers must not
// let a restored checkpoint lower the separate live canonical journal head.
func TestCanonicalHeadGateRejectsRestoredStateAndValidOldWitnessBeforeWrites(t *testing.T) {
	ctx := context.Background()
	first, _, fingerprint := reviewReader(t, false, true)
	e, cr, store, b, w := reviewEngine(t, fingerprint)
	if _, err := e.Sync(ctx, cr, store, b, first, authorize); err != nil {
		t.Fatal(err)
	}
	var oldState, oldTarget corev1.Secret
	_ = e.Reader.Get(ctx, client.ObjectKey{Namespace: e.Config.Namespace, Name: e.Config.StateSecret.Name}, &oldState)
	_ = e.Reader.Get(ctx, client.ObjectKey{Namespace: e.Config.Namespace, Name: b.Target.Name}, &oldTarget)
	second, canonical, _ := reviewReader(t, true, false)
	if _, err := e.Sync(ctx, cr, store, b, second, authorize); err != nil {
		t.Fatal(err)
	}
	for _, old := range []*corev1.Secret{&oldState, &oldTarget} {
		var current corev1.Secret
		if err := e.Reader.Get(ctx, client.ObjectKeyFromObject(old), &current); err != nil {
			t.Fatal(err)
		}
		current.Data = old.Data
		current.Annotations = old.Annotations
		if err := w.Client.Update(ctx, &current); err != nil {
			t.Fatal(err)
		}
	}
	w.events = nil
	checks := 0
	e.VerifyHead = func(_ context.Context, h witness.Head) error {
		checks++
		if h != canonical {
			return fail("CanonicalHeadMismatch")
		}
		return nil
	}
	oldReader, _, _ := reviewReader(t, false, true)
	if _, err := e.Sync(ctx, cr, store, b, oldReader, authorize); Reason(err) != "CanonicalHeadMismatch" {
		t.Fatal("valid old witness response bypassed live journal", err)
	}
	if checks != 1 || len(w.events) != 0 {
		t.Fatal("canonical gate ran after protected or target mutation")
	}
	if _, err := e.Sync(ctx, cr, store, b, second, authorize); err != nil {
		t.Fatal("current canonical snapshot rejected", err)
	}
	if reviewRecord(t, e).Head.Sequence != "2" || string(targetFor(t, e).Data["DEMO_VALUE"]) != "canary-value-2" {
		t.Fatal("current snapshot not restored")
	}
}
