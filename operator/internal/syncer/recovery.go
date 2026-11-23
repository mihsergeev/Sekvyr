package syncer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/recovery"
	"github.com/mihsergeev/Sekvyr/operator/internal/rollout"
	"github.com/mihsergeev/Sekvyr/operator/internal/verification"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// StateDigest covers protected metadata only; no plaintext secret digest is
// published in a recovery plan. An absent state.json is the hash of empty bytes.
func StateDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// RestoreCheckpoint is an explicit administrative operation, never called by
// normal reconciliation. The caller verifies a fresh signed plan and E2E2 read,
// and supplies an online exact-journal-cursor check before EACH mutation.
// Prepared progress blocks normal runtime until both target and state are done.
func (e Engine) RestoreCheckpoint(ctx context.Context, plan *recovery.Accepted, accepted *verification.Accepted, cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding, revalidate func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || plan == nil || accepted == nil || revalidate == nil || e.Config.HA == nil {
		return fail("RecoveryRequired")
	}
	p := plan.Body()
	head := accepted.Head()
	if p.InstallationID != e.Config.InstallationID || p.BootstrapGeneration != e.Config.BootstrapGeneration || p.StateSecretName != e.Config.StateSecret.Name || p.StateSecretUID != e.Config.StateSecret.UID || p.IdentityKeySecretUID != e.Config.IdentityKeySecret.UID || p.TrustBundleSecretUID != e.Config.TrustBundleSecret.UID || p.Scope.LogID != e.Config.HA.Journal.LogID || p.GenesisHash != e.Config.HA.Journal.GenesisHash {
		return fail("RecoveryBindingMismatch")
	}
	if head != plan.Head() || p.NodeFingerprint != e.NodeFingerprint || cr.Namespace != e.Config.Namespace || store.Namespace != e.Config.Namespace || !cr.DeletionTimestamp.IsZero() || !store.DeletionTimestamp.IsZero() || cr.Name != p.Binding.CRName || string(cr.UID) != p.Binding.CRUID || cr.Generation != p.Binding.CRGeneration || store.Name != p.Binding.StoreName || string(store.UID) != p.Binding.StoreUID || store.Generation != p.Binding.StoreGeneration || b.ID != p.Binding.BindingID || bindingIdentity(b) != p.Binding.Identity || b.Source.ViewID != p.Binding.ViewID || b.Target.Name != p.Binding.TargetName || !e.Config.TargetAllowed(b.Target.Name) || e.Config.Protected(b.Target.Name, types.UID(p.Binding.TargetUID)) {
		return fail("RecoveryBindingMismatch")
	}
	data, err := selectData(accepted.Values(), b)
	if err != nil {
		return err
	}
	var stateSecret, target corev1.Secret
	if e.Reader.Get(ctx, types.NamespacedName{Namespace: e.Config.Namespace, Name: e.Config.StateSecret.Name}, &stateSecret) != nil || !e.state().acceptsSecret(&stateSecret) {
		return fail("StateReplaced")
	}
	if e.Reader.Get(ctx, types.NamespacedName{Namespace: e.Config.Namespace, Name: p.Binding.TargetName}, &target) != nil || string(target.UID) != p.Binding.TargetUID || target.Type != corev1.SecretTypeOpaque || target.Immutable != nil && *target.Immutable || !target.DeletionTimestamp.IsZero() {
		return fail("TargetReservationMissing")
	}
	if !targetOwnerMatches(&target, cr, b) {
		return fail("OwnershipConflict")
	}
	expected := e.expected(cr, store, b)
	expected.TargetUID = string(target.UID)
	copyHead := head
	expected.Head = &copyHead
	key := expected.StoreUID + "/" + expected.BindingID
	stateRaw := stateSecret.Data[StateKey]
	confirmState := func() (*corev1.Secret, error) {
		var latest corev1.Secret
		if e.Reader.Get(ctx, types.NamespacedName{Namespace: e.Config.Namespace, Name: e.Config.StateSecret.Name}, &latest) != nil || !e.state().acceptsSecret(&latest) || !bytes.Equal(latest.Data[StateKey], stateRaw) {
			return nil, fail("RecoveryStateChanged")
		}
		return &latest, nil
	}
	confirmTarget := func() bool {
		fresh, err := e.target(ctx, expected)
		return err == nil && fresh != nil && targetOwnerMatches(fresh, cr, b) && recoveryTargetMatches(fresh, data, head, expected.Rollout)
	}
	var state State
	resume := strict(stateRaw, &state, stateLimit) == nil && state.Recovery != nil && state.Recovery.ID == p.RecoveryID && state.Recovery.PlanHash == plan.Hash()
	if resume {
		r, ok := state.Bindings[key]
		if state.Version != 1 || state.InstallationID != e.Config.InstallationID || state.BootstrapGeneration != e.Config.BootstrapGeneration || state.TrustBundleUID != e.Config.TrustBundleSecret.UID || state.NodeFingerprint != e.NodeFingerprint || len(state.Bindings) != 1 || !ok || !sameIdentity(r, expected) || r.TargetUID != expected.TargetUID || r.Head == nil || *r.Head != head || r.Rollout == nil || !rollout.ValidAuthorization(r.Rollout) {
			return fail("RecoveryProgressInvalid")
		}
		expected = r
		if state.Recovery.Phase == "complete" {
			if err = revalidate(ctx); err != nil {
				return err
			}
			if _, err = confirmState(); err != nil {
				return err
			}
			if !confirmTarget() {
				return fail("RecoveryAlreadyCompleted")
			}
			return nil
		}
		if state.Recovery.Phase != "prepared" {
			return fail("RecoveryProgressInvalid")
		}
	} else {
		if StateDigest(stateRaw) != p.ExpectedStateSHA256 {
			return fail("RecoveryStateChanged")
		}
		// A completed state may only be replaced by a different independently
		// enrolled bootstrap generation, never by re-signing an old reset plan.
		replaceReviewedPending := state.Version == 1 && state.InstallationID == e.Config.InstallationID && state.BootstrapGeneration == e.Config.BootstrapGeneration && state.Recovery != nil && state.Recovery.Phase == "prepared" && state.Recovery.ID != p.RecoveryID && state.Recovery.PlanHash != plan.Hash()
		if state.Version == 1 && state.BootstrapGeneration >= e.Config.BootstrapGeneration && len(stateRaw) > 0 && !replaceReviewedPending {
			return fail("RecoveryAlreadyCompleted")
		}
		revision := target.Annotations[revisionAnnotation]
		if !equalData(target.Data, data) || !rollout.ValidRevision(revision) {
			nonce := make([]byte, 16)
			if _, err = rand.Read(nonce); err != nil {
				return fail("RandomUnavailable")
			}
			revision = hex.EncodeToString(nonce)
		}
		rolloutPolicy := e.RolloutPolicy
		rolloutPolicy.Enabled = rolloutPolicy.Enabled && p.AllowRollout && !equalData(target.Data, data)
		intent, _ := rollout.Prepare(ctx, e.Reader, rolloutPolicy, cr, store, b, &target, revision, e.Config.BootstrapGeneration, e.now(), nil)
		expected.Rollout, err = rollout.Authorize(intent)
		if err != nil {
			return fail("RolloutStateInvalid")
		}
		state = State{Version: 1, InstallationID: e.Config.InstallationID, BootstrapGeneration: e.Config.BootstrapGeneration, TrustBundleUID: e.Config.TrustBundleSecret.UID, NodeFingerprint: e.NodeFingerprint, Bindings: map[string]Record{key: expected}, Recovery: &RecoveryProgress{ID: p.RecoveryID, PlanHash: plan.Hash(), Phase: "prepared"}}
		raw, err := json.Marshal(state)
		if err != nil || len(raw) > stateLimit {
			return fail("StateCapacity")
		}
		if stateSecret.Data == nil {
			stateSecret.Data = map[string][]byte{}
		}
		stateRaw = raw
		stateSecret.Data[StateKey] = raw
		if err = revalidate(ctx); err != nil {
			return err
		}
		if err = e.Writer.Update(ctx, &stateSecret); err != nil {
			return fail("RecoveryStateWriteFailed")
		}
	}
	if !recoveryTargetMatches(&target, data, head, expected.Rollout) {
		if target.Annotations == nil {
			target.Annotations = map[string]string{}
		}
		checkpoint, _ := json.Marshal(head)
		intentRaw, _ := rollout.Encode(expected.Rollout.Intent)
		target.Data = data
		target.Annotations[checkpointAnnotation] = string(checkpoint)
		target.Annotations[revisionAnnotation] = expected.Rollout.Intent.Revision
		target.Annotations[intentAnnotation] = string(intentRaw)
		if err = revalidate(ctx); err != nil {
			return err
		}
		if _, err = confirmState(); err != nil {
			return err
		}
		if err = e.Writer.Update(ctx, &target); err != nil {
			return fail("RecoveryTargetWriteFailed")
		}
	}
	// Check both objects after the online authorization, then finalize by CAS.
	if err = revalidate(ctx); err != nil {
		return err
	}
	latest, err := confirmState()
	if err != nil {
		return err
	}
	if !confirmTarget() {
		return fail("RecoveryTargetChanged")
	}
	state.Recovery.Phase = "complete"
	raw, _ := json.Marshal(state)
	latest.Data[StateKey] = raw
	if err = e.Writer.Update(ctx, latest); err != nil {
		return fail("RecoveryFinalizeFailed")
	}
	return nil
}
func recoveryTargetMatches(target *corev1.Secret, data map[string][]byte, head interface{}, auth *rollout.Authorization) bool {
	if target == nil || auth == nil || !equalData(target.Data, data) || target.Annotations[revisionAnnotation] != auth.Intent.Revision {
		return false
	}
	checkpoint, _ := json.Marshal(head)
	intentRaw, _ := rollout.Encode(auth.Intent)
	return target.Annotations[checkpointAnnotation] == string(checkpoint) && target.Annotations[intentAnnotation] == string(intentRaw)
}
