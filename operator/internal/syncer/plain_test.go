package syncer

import (
	"context"
	"encoding/json"
	"testing"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/panelauth"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func plainSnapshot(t *testing.T, value string) *panelauth.PlainSnapshot {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"project": "app", "environment": "test", "values": []map[string]string{{"name": "TOKEN", "path": "/", "value": value}}, "e2e": false, "project_key": nil})
	snapshot, err := panelauth.DecodePlainSnapshot(raw, "app", "test")
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func plainEngine(t *testing.T) (Engine, *api.SekvyrSecret, *api.SekvyrStore, api.Binding, *reviewWriter) {
	e, cr, store, binding, writer := reviewEngine(t, "public-plain-node-fingerprint")
	binding.Encryption = api.Encryption{Mode: "Plain"}
	binding.Source.ViewID = ""
	binding.Source.Environment = "test"
	return e, cr, store, binding, writer
}

func TestPlainDataTransactionsHaveExplicitModeAndNoWitnessClaims(t *testing.T) {
	e, cr, store, binding, writer := plainEngine(t)
	allow := func(context.Context) error { return nil }
	first, err := e.SyncPlain(context.Background(), cr, store, binding, plainSnapshot(t, "first-public-canary"), allow)
	if err != nil || !first.Plain || !first.Changed || first.Head != (witness.Head{}) {
		t.Fatal("Plain initial synchronization failed", err)
	}
	record := reviewRecord(t, e)
	target := targetFor(t, e)
	if record.Mode != "Plain" || record.Head != nil || target.Annotations[checkpointAnnotation] != "" || string(target.Data["TOKEN"]) != "first-public-canary" || record.TargetUID == "" {
		t.Fatal("Plain state fabricated a witness checkpoint or lost ownership")
	}
	writer.events = nil
	equal, err := e.SyncPlain(context.Background(), cr, store, binding, plainSnapshot(t, "first-public-canary"), allow)
	if err != nil || equal.Changed || equal.Revision != first.Revision || len(writer.events) != 0 {
		t.Fatal("equal Plain snapshot rewrote data or revision", err)
	}
	changed, err := e.SyncPlain(context.Background(), cr, store, binding, plainSnapshot(t, "second-public-canary"), allow)
	if err != nil || !changed.Changed || changed.Revision == first.Revision || string(targetFor(t, e).Data["TOKEN"]) != "second-public-canary" {
		t.Fatal("changed Plain data did not converge", err)
	}
}

func TestPlainCannotSatisfyE2EOrHAAndZeroResponseCannotDelete(t *testing.T) {
	allow := func(context.Context) error { return nil }
	for _, mode := range []string{"e2e", "ha", "zero", "project", "environment", "group", "lost-state", "replaced-state"} {
		t.Run(mode, func(t *testing.T) {
			e, cr, store, binding, writer := plainEngine(t)
			snapshot := plainSnapshot(t, "public-canary")
			switch mode {
			case "e2e":
				binding.Encryption = api.Encryption{Mode: "E2E", Protocol: "e2e2"}
			case "ha":
				e.Config.HA = &installation.HAConfig{Trial: true}
			case "zero":
				snapshot = &panelauth.PlainSnapshot{}
				binding.Target.AllowEmpty = true
			case "project":
				binding.Source.Project = "other-project"
			case "environment":
				binding.Source.Environment = "other-env"
			case "group":
				binding.Source.Group = "other-group"
			default:
				var state corev1.Secret
				_ = e.Reader.Get(context.Background(), client.ObjectKey{Namespace: e.Config.Namespace, Name: e.Config.StateSecret.Name}, &state)
				if mode == "lost-state" {
					_ = writer.Client.Delete(context.Background(), &state)
				} else {
					state.UID = "99999999-9999-4999-8999-999999999999"
					_ = writer.Client.Update(context.Background(), &state)
				}
			}
			if _, err := e.SyncPlain(context.Background(), cr, store, binding, snapshot, allow); err == nil || len(writer.events) != 0 {
				t.Fatal("invalid Plain context wrote data or accepted unverified empty response")
			}
		})
	}
}

func TestPlainOwnershipAndStateFailurePreserveTarget(t *testing.T) {
	e, cr, store, binding, writer := plainEngine(t)
	allow := func(context.Context) error { return nil }
	_, err := e.SyncPlain(context.Background(), cr, store, binding, plainSnapshot(t, "first-public-canary"), allow)
	if err != nil {
		t.Fatal(err)
	}
	before := targetFor(t, e).DeepCopy()
	writer.failState = true
	if _, err = e.SyncPlain(context.Background(), cr, store, binding, plainSnapshot(t, "second-public-canary"), allow); err == nil {
		t.Fatal("failed protected intent persistence allowed a target update")
	}
	if !equalData(before.Data, targetFor(t, e).Data) || before.Annotations[revisionAnnotation] != targetFor(t, e).Annotations[revisionAnnotation] {
		t.Fatal("failed state mutation changed target bytes/revision")
	}
	writer.failState = false
	binding.Encryption = api.Encryption{Mode: "E2E", Protocol: "e2e2"}
	if _, err = e.Preflight(context.Background(), cr, store, binding); Reason(err) != "OwnershipConflict" {
		t.Fatal("a persisted Plain record can be reinterpreted as E2E2", err)
	}
}
