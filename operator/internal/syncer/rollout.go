package syncer

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/rollout"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func (e Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e Engine) confirmRolloutAuthorization(ctx context.Context, key string, expected Record, head witness.Head, targetUID, hash string) error {
	if err := e.state().confirm(ctx, key, expected, head, targetUID); err != nil {
		return err
	}
	_, state, err := e.state().load(ctx)
	if err != nil {
		return err
	}
	record, ok := state.Bindings[key]
	if !ok || !sameIdentity(record, expected) || !recordHeadMatches(record, head) || record.TargetUID != targetUID || record.Rollout == nil || record.Rollout.Cancelled || record.Rollout.IntentHash != hash {
		return fail("RolloutAuthorizationChanged")
	}
	return nil
}

type rolloutGuard struct {
	engine                    Engine
	key                       string
	expected                  Record
	head                      witness.Head
	targetUID, revision, hash string
	data                      map[string][]byte
}

func (e Engine) rolloutGuard(cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding, head witness.Head, target *corev1.Secret, data map[string][]byte, a *rollout.Authorization) rollout.Guard {
	if a == nil || a.Cancelled || !rollout.ValidAuthorization(a) {
		return nil
	}
	expected := e.expected(cr, store, b)
	copied := map[string][]byte{}
	for k, v := range data {
		copied[k] = append([]byte(nil), v...)
	}
	return &rolloutGuard{engine: e, key: expected.StoreUID + "/" + expected.BindingID, expected: expected, head: head, targetUID: string(target.UID), revision: a.Intent.Revision, hash: a.IntentHash, data: copied}
}
func (g *rolloutGuard) record(ctx context.Context) (Record, error) {
	_, state, err := g.engine.state().load(ctx)
	if err != nil {
		return Record{}, err
	}
	r, ok := state.Bindings[g.key]
	if !ok || !sameIdentity(r, g.expected) || r.TargetUID != g.targetUID || !recordHeadMatches(r, g.head) || r.Rollout == nil || r.Rollout.Cancelled || r.Rollout.IntentHash != g.hash || r.Rollout.Intent.Revision != g.revision {
		return Record{}, &rollout.Error{Reason: "RolloutStateAmbiguous"}
	}
	return r, nil
}
func (g *rolloutGuard) Confirm(ctx context.Context, target *corev1.Secret, i rollout.Intent) error {
	if target == nil || string(target.UID) != g.targetUID || target.Name != g.expected.TargetName || target.Namespace != g.engine.Config.Namespace || !target.DeletionTimestamp.IsZero() || !equalData(target.Data, g.data) || target.Annotations[revisionAnnotation] != g.revision {
		return &rollout.Error{Reason: "RolloutTargetChanged"}
	}
	parsed, err := rollout.Decode(target.Annotations[intentAnnotation])
	if err != nil {
		return &rollout.Error{Reason: "IntentInvalid"}
	}
	got, err := rollout.Hash(parsed)
	if err != nil || got != g.hash {
		return &rollout.Error{Reason: "RolloutStateAmbiguous"}
	}
	requested, err := rollout.Hash(i)
	if err != nil || requested != g.hash {
		return &rollout.Error{Reason: "RolloutStateAmbiguous"}
	}
	_, err = g.record(ctx)
	return err
}
func (g *rolloutGuard) Applied(ctx context.Context, d rollout.DeploymentRef) (bool, error) {
	r, err := g.record(ctx)
	if err != nil {
		return false, err
	}
	for _, done := range r.Rollout.Applied {
		if done == d {
			return true, nil
		}
	}
	return false, nil
}
func (g *rolloutGuard) MarkApplied(ctx context.Context, d rollout.DeploymentRef) error {
	_, err := g.engine.state().update(ctx, g.key, g.expected, func(r *Record) error {
		if r.TargetUID != g.targetUID || !recordHeadMatches(*r, g.head) || r.Rollout == nil || r.Rollout.Cancelled || r.Rollout.IntentHash != g.hash {
			return &rollout.Error{Reason: "RolloutStateAmbiguous"}
		}
		found := false
		for _, wanted := range r.Rollout.Intent.Deployments {
			if wanted == d && d.UID != "" {
				found = true
			}
		}
		if !found {
			return &rollout.Error{Reason: "DeploymentReplaced"}
		}
		for _, done := range r.Rollout.Applied {
			if done == d {
				return nil
			}
		}
		r.Rollout.Applied = append(r.Rollout.Applied, d)
		sort.Slice(r.Rollout.Applied, func(a, b int) bool { return r.Rollout.Applied[a].Name < r.Rollout.Applied[b].Name })
		return nil
	})
	return err
}
func (g *rolloutGuard) Cancel(ctx context.Context) error {
	_, err := g.engine.state().update(ctx, g.key, g.expected, func(r *Record) error {
		if r.TargetUID != g.targetUID || !recordHeadMatches(*r, g.head) || r.Rollout == nil || r.Rollout.IntentHash != g.hash || r.Rollout.Intent.Revision != g.revision {
			return fail("RolloutAuthorizationChanged")
		}
		r.Rollout.Cancelled = true
		return nil
	})
	return err
}

// CancelRollout invalidates an existing protected candidate after a terminal
// authorization failure. It never fetches panel data or writes the target.
func (e Engine) CancelRollout(ctx context.Context, cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding) error {
	expected := e.expected(cr, store, b)
	key := expected.StoreUID + "/" + expected.BindingID
	_, state, err := e.state().load(ctx)
	if err != nil {
		return err
	}
	record, exists := state.Bindings[key]
	if !exists {
		return nil
	}
	if !sameIdentity(record, expected) {
		return fail("OwnershipConflict")
	}
	if record.Rollout == nil || !record.Rollout.Intent.Eligible {
		return nil
	}
	if record.Rollout.Intent.Context != rollout.NewContext(cr, store, b, e.Config.BootstrapGeneration, record.TargetUID) {
		// Different generations already invalidate the old intent. A stale
		// cancellation must neither revoke a newer context nor block data sync.
		return nil
	}
	hash := record.Rollout.IntentHash
	_, err = e.state().update(ctx, key, expected, func(r *Record) error {
		if r.TargetUID != record.TargetUID || r.Mode != record.Mode || (r.Mode == "Plain" && (r.Head != nil || record.Head != nil)) || (r.Mode != "Plain" && (r.Head == nil || record.Head == nil || *r.Head != *record.Head)) || r.Rollout == nil || r.Rollout.IntentHash != hash || r.Rollout.Intent.Context != rollout.NewContext(cr, store, b, e.Config.BootstrapGeneration, record.TargetUID) {
			return nil
		}
		r.Rollout.Cancelled = true
		return nil
	})
	return err
}

// Equal plaintext never creates eligibility. Only exact protected authorization
// may resume, including one-time completion of a previously unresolved UID.
func (e Engine) resumeRollout(ctx context.Context, cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding, head witness.Head, target *corev1.Secret, data map[string][]byte, revalidate func(context.Context) error) (rollout.Guard, string) {
	expected := e.expected(cr, store, b)
	key := expected.StoreUID + "/" + expected.BindingID
	_, state, err := e.state().load(ctx)
	if err != nil {
		return nil, "RolloutStateAmbiguous"
	}
	r, ok := state.Bindings[key]
	if !ok || !sameIdentity(r, expected) || !recordHeadMatches(r, head) || r.TargetUID != string(target.UID) || r.Rollout == nil {
		return nil, "RolloutStateAmbiguous"
	}
	if r.Rollout.Cancelled {
		return nil, "Cancelled"
	}
	current, err := rollout.Decode(target.Annotations[intentAnnotation])
	if err != nil {
		return nil, "RolloutStateAmbiguous"
	}
	hash, err := rollout.Hash(current)
	if err != nil || hash != r.Rollout.IntentHash || current.Revision != target.Annotations[revisionAnnotation] {
		return nil, "RolloutStateAmbiguous"
	}
	if !current.Eligible {
		return nil, "Ineligible"
	}
	if current.Context != rollout.NewContext(cr, store, b, e.Config.BootstrapGeneration, string(target.UID)) {
		return nil, "RolloutInvalidated"
	}
	reason := rollout.Allowed(e.RolloutPolicy, cr, store, b)
	if reason != "" {
		return e.rolloutGuard(cr, store, b, head, target, data, r.Rollout), reason
	}
	resolved, reason := rollout.Resolve(ctx, e.Reader, current)
	resolvedHash, _ := rollout.Hash(resolved)
	if resolvedHash != hash {
		if revalidate(ctx) != nil {
			return nil, "RolloutAuthorizationChanged"
		}
		updated, updateErr := e.state().update(ctx, key, expected, func(record *Record) error {
			if !recordHeadMatches(*record, head) || record.TargetUID != string(target.UID) || record.Rollout == nil || record.Rollout.Cancelled || record.Rollout.IntentHash != hash {
				return fail("HeadChanged")
			}
			record.Rollout.Intent = resolved
			record.Rollout.IntentHash = resolvedHash
			return nil
		})
		if updateErr != nil {
			return nil, "RolloutStateAmbiguous"
		}
		raw, _ := json.Marshal(resolved)
		target.Annotations[intentAnnotation] = string(raw)
		if revalidate(ctx) != nil || e.confirmRolloutAuthorization(ctx, key, expected, head, string(target.UID), resolvedHash) != nil {
			return nil, "RolloutAuthorizationChanged"
		}
		if updateErr = e.Writer.Update(ctx, target); updateErr != nil {
			if apierrors.IsConflict(updateErr) {
				return nil, "TargetConflict"
			}
			return nil, "TargetWriteFailed"
		}
		r = updated
	}
	return e.rolloutGuard(cr, store, b, head, target, data, r.Rollout), reason
}
