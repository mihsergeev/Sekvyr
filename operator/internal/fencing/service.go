package fencing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Service struct {
	Config     Config
	Journal    Ledger
	Reader     client.Reader
	Writer     client.Client
	Auth       Authenticator
	SigningKey ed25519.PrivateKey
	Now        func() time.Time
}

func (*Service) String() string   { return "fencer service [redacted]" }
func (*Service) GoString() string { return "fencer service [redacted]" }
func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) read(ctx context.Context) (journal.CurrentState, journal.Enrollment, error) {
	if s == nil || s.Journal == nil || ctx == nil || ctx.Err() != nil {
		return journal.CurrentState{}, journal.Enrollment{}, fail("JournalUnavailable")
	}
	state, err := s.Journal.ReadCurrent(ctx, s.Config.LogID, s.Config.MinimumCursor)
	if err != nil {
		return state, journal.Enrollment{}, fail("JournalUnavailable")
	}
	enrollment, ok := state.Enrollments[s.Config.InstallationID]
	if ok && (enrollment.OperatorServiceAccount == enrollment.FencerServiceAccount || enrollment.OperatorServiceAccountUID == enrollment.FencerServiceAccountUID) {
		return state, enrollment, fail("IdentityRoleCollision")
	}
	if !ok || enrollment.Namespace != s.Config.Namespace || enrollment.NamespaceUID != s.Config.NamespaceUID ||
		enrollment.OperatorServiceAccountUID != s.Config.OperatorServiceAccountUID || enrollment.Lease.UID != s.Config.LeaseUID || enrollment.FencerServiceAccount != s.Config.FencerServiceAccount ||
		enrollment.FencerServiceAccountUID != s.Config.FencerServiceAccountUID || state.Scope.LogID != s.Config.LogID {
		return state, enrollment, fail("EnrollmentMismatch")
	}
	return state, enrollment, nil
}

func (s *Service) lease(ctx context.Context, enrollment journal.Enrollment, identity Identity) (string, error) {
	if s.Reader == nil {
		return "", fail("LeaseUnavailable")
	}
	var lease coordinationv1.Lease
	if s.Reader.Get(ctx, types.NamespacedName{Namespace: enrollment.Namespace, Name: enrollment.Lease.Name}, &lease) != nil ||
		string(lease.UID) != enrollment.Lease.UID || !lease.DeletionTimestamp.IsZero() || lease.Spec.HolderIdentity == nil ||
		!strings.HasPrefix(*lease.Spec.HolderIdentity, identity.PodName+"_") || len(*lease.Spec.HolderIdentity) <= len(identity.PodName)+1 ||
		lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil || *lease.Spec.LeaseDurationSeconds < 1 {
		return "", fail("LeaseMismatch")
	}
	now := s.now()
	renewed := lease.Spec.RenewTime.Time
	if renewed.After(now) || !now.Before(renewed.Add(time.Duration(*lease.Spec.LeaseDurationSeconds)*time.Second)) {
		return "", fail("LeaseExpired")
	}
	return *lease.Spec.HolderIdentity, nil
}

func (s *Service) identify(ctx context.Context, token string, enrollment journal.Enrollment) (Identity, string, error) {
	if s.Auth == nil {
		return Identity{}, "", fail("AuthenticationDenied")
	}
	identity, err := s.Auth.Authenticate(ctx, token, enrollment)
	if err != nil {
		return Identity{}, "", fail(Reason(err))
	}
	holder, err := s.lease(ctx, enrollment, identity)
	return identity, holder, err
}

func (s *Service) Acquire(ctx context.Context, token string, generation int64, expectedHolder string) (*Session, error) {
	if len(s.SigningKey) != ed25519.PrivateKeySize {
		return nil, fail("SigningKeyUnavailable")
	}
	if expectedHolder == "" {
		return nil, fail("LeaseMismatch")
	}
	for attempt := 0; attempt < maxCASAttempts; attempt++ {
		state, enrollment, err := s.read(ctx)
		if err != nil {
			return nil, err
		}
		if enrollment.BootstrapGeneration != generation {
			return nil, fail("BootstrapMismatch")
		}
		identity, holder, err := s.identify(ctx, token, enrollment)
		if err != nil {
			return nil, err
		}
		if holder != expectedHolder {
			return nil, fail("LeaseMismatch")
		}
		if current, _, currentErr := currentGrant(state, s.Config.InstallationID, false); currentErr == nil &&
			current.Body.OwnerPodUID == identity.PodUID && current.Body.LeaseHolderIdentity == holder {
			_, _, activeErr := currentGrant(state, s.Config.InstallationID, true)
			return sessionFrom(state, s.Config.InstallationID, activeErr == nil)
		}
		term, previous := uint64(0), journal.ZeroHash
		if old, exists := state.Grants[s.Config.InstallationID]; exists {
			term, err = e2e2.Counter(old.Body.Term, false)
			if err != nil {
				return nil, fail("GrantInvalid")
			}
			previous, err = journal.FenceGrantHash(old.Body)
			if err != nil {
				return nil, fail("GrantInvalid")
			}
		}
		if term == math.MaxUint64 {
			return nil, fail("TermExhausted")
		}
		grant, err := journal.SignFenceGrant(journal.FenceGrant{Format: "sekvyr-fence-grant-v1", Scope: state.Scope,
			GenesisHash: state.GenesisHash, InstallationID: enrollment.InstallationID, BootstrapGeneration: generation,
			OwnerPodUID: identity.PodUID, LeaseHolderIdentity: holder, Term: strconv.FormatUint(term+1, 10),
			PreviousGrantHash: previous, AuthorityDigest: state.AuthorityDigest, Snapshot: state.Snapshot, Objects: append([]journal.ObjectRef(nil), enrollment.AllowedObjects...)}, s.SigningKey)
		if err != nil {
			return nil, fail("SigningKeyUnavailable")
		}
		raw, err := encodeWire(grant)
		if err != nil {
			return nil, err
		}
		// This direct Lease GET is intentionally repeated for EVERY CAS attempt.
		freshHolder, err := s.lease(ctx, enrollment, identity)
		if err != nil || freshHolder != holder {
			return nil, fail("LeaseMismatch")
		}
		updated, err := s.Journal.AppendFenceGrantCAS(ctx, s.Config.LogID, state.Cursor, raw)
		if err != nil {
			if journal.Reason(err) == "CASConflict" {
				continue
			}
			return nil, fail("JournalUnavailable")
		}
		result, err := sessionFrom(updated, s.Config.InstallationID, false)
		if err != nil {
			return nil, err
		}
		expected, _ := journal.FenceGrantHash(grant.Body)
		if result.hash != expected {
			return nil, fail("GrantChanged")
		}
		return result, nil
	}
	return nil, fail("CASConflict")
}

func (s *Service) authorized(ctx context.Context, token, hash string, active bool) (journal.CurrentState, journal.Enrollment, Identity, *Session, error) {
	state, enrollment, err := s.read(ctx)
	if err != nil {
		return state, enrollment, Identity{}, nil, err
	}
	identity, holder, err := s.identify(ctx, token, enrollment)
	if err != nil {
		return state, enrollment, identity, nil, err
	}
	session, err := sessionFrom(state, s.Config.InstallationID, active)
	if err != nil {
		return state, enrollment, identity, nil, err
	}
	if session.hash != hash || session.grant.Body.OwnerPodUID != identity.PodUID || session.grant.Body.LeaseHolderIdentity != holder {
		return state, enrollment, identity, nil, fail("GrantChanged")
	}
	return state, enrollment, identity, session, nil
}

func objectFor(ref journal.ObjectRef) (client.Object, error) {
	switch {
	case ref.APIVersion == "v1" && ref.Kind == "Secret":
		return &corev1.Secret{}, nil
	case ref.APIVersion == "apps/v1" && ref.Kind == "Deployment":
		return &appsv1.Deployment{}, nil
	default:
		return nil, fail("ObjectDenied")
	}
}

func (s *Service) getObject(ctx context.Context, ref journal.ObjectRef) (client.Object, error) {
	object, err := objectFor(ref)
	if err != nil || s.Reader == nil {
		return nil, fail("ObjectDenied")
	}
	if s.Reader.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, object) != nil {
		return nil, fail("ObjectMissing")
	}
	if string(object.GetUID()) != ref.UID || object.GetResourceVersion() == "" || !object.GetDeletionTimestamp().IsZero() {
		return nil, fail("ObjectReplaced")
	}
	return object, nil
}

func (s *Service) barrier(ctx context.Context, session *Session, ref journal.ObjectRef) error {
	object, err := s.getObject(ctx, ref)
	if err != nil {
		return err
	}
	old := object.GetAnnotations()[FenceAnnotation]
	if old == session.fence {
		return nil
	}
	if old != "" {
		fence, err := DecodeFence(old)
		if err != nil {
			return err
		}
		oldTerm, _ := e2e2.Counter(fence.Term, false)
		newTerm, _ := e2e2.Counter(session.grant.Body.Term, false)
		if fence.InstallationID != session.grant.Body.InstallationID || fence.BootstrapGeneration > session.grant.Body.BootstrapGeneration || oldTerm >= newTerm {
			return fail("FenceNotIncreasing")
		}
	}
	patch := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": ref.UID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": object.GetResourceVersion()}}
	if object.GetAnnotations() == nil {
		patch = append(patch, map[string]any{"op": "add", "path": "/metadata/annotations", "value": map[string]string{FenceAnnotation: session.fence}})
	} else {
		patch = append(patch, map[string]any{"op": "add", "path": "/metadata/annotations/" + strings.ReplaceAll(FenceAnnotation, "/", "~1"), "value": session.fence})
	}
	raw, _ := json.Marshal(patch)
	if s.Writer == nil || s.Writer.Patch(ctx, object, client.RawPatch(types.JSONPatchType, raw)) != nil {
		return fail("BarrierConflict")
	}
	return nil
}

func (s *Service) verifyBarriers(ctx context.Context, session *Session) error {
	for _, ref := range session.grant.Body.Objects {
		object, err := s.getObject(ctx, ref)
		if err != nil {
			return err
		}
		if object.GetAnnotations()[FenceAnnotation] != session.fence {
			return fail("BarriersIncomplete")
		}
	}
	return nil
}

func (s *Service) Barriers(ctx context.Context, token, hash string) (*Session, error) {
	for attempt := 0; attempt < maxCASAttempts; attempt++ {
		_, _, _, session, err := s.authorized(ctx, token, hash, false)
		if err != nil {
			return nil, err
		}
		for _, ref := range session.grant.Body.Objects {
			_, _, _, fresh, err := s.authorized(ctx, token, hash, false)
			if err != nil {
				return nil, err
			}
			if err = s.barrier(ctx, fresh, ref); err != nil {
				return nil, err
			}
		}
		state, enrollment, identity, fresh, err := s.authorized(ctx, token, hash, false)
		if err != nil {
			return nil, err
		}
		if err = s.verifyBarriers(ctx, fresh); err != nil {
			return nil, err
		}
		if _, _, activeErr := currentGrant(state, s.Config.InstallationID, true); activeErr == nil {
			return sessionFrom(state, s.Config.InstallationID, true)
		}
		body := fresh.grant.Body
		activation, err := journal.SignFenceActivation(journal.FenceActivation{Format: "sekvyr-fence-activation-v1", Scope: body.Scope,
			GenesisHash: body.GenesisHash, InstallationID: body.InstallationID, BootstrapGeneration: body.BootstrapGeneration,
			OwnerPodUID: body.OwnerPodUID, LeaseHolderIdentity: body.LeaseHolderIdentity, Term: body.Term, GrantHash: hash,
			AuthorityDigest: body.AuthorityDigest, Snapshot: body.Snapshot, Objects: append([]journal.ObjectRef(nil), body.Objects...)}, s.SigningKey)
		if err != nil {
			return nil, fail("SigningKeyUnavailable")
		}
		raw, err := encodeWire(activation)
		if err != nil {
			return nil, err
		}
		holder, err := s.lease(ctx, enrollment, identity)
		if err != nil || holder != body.LeaseHolderIdentity {
			return nil, fail("LeaseMismatch")
		}
		updated, err := s.Journal.AppendFenceActivationCAS(ctx, s.Config.LogID, state.Cursor, raw)
		if err != nil {
			if journal.Reason(err) == "CASConflict" {
				continue
			}
			return nil, fail("JournalUnavailable")
		}
		result, err := sessionFrom(updated, s.Config.InstallationID, true)
		if err != nil || result.hash != hash {
			return nil, fail("GrantChanged")
		}
		return result, nil
	}
	return nil, fail("CASConflict")
}

func (s *Service) Ready(ctx context.Context, token, hash string) (*Session, error) {
	_, _, _, session, err := s.authorized(ctx, token, hash, true)
	if err != nil {
		return nil, err
	}
	if err = s.verifyBarriers(ctx, session); err != nil {
		return nil, err
	}
	return session, nil
}
