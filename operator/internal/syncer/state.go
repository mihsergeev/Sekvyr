// Package syncer persists accepted authority before updating namespace-scoped
// targets. Deployment execution is isolated in the opt-in rollout package.
package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/rollout"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const StateKey = "state.json"
const stateLimit = 512 << 10

type Error struct{ Reason string }

func (e *Error) Error() string { return "secret synchronization: " + e.Reason }
func fail(reason string) error { return &Error{Reason: reason} }
func Reason(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	var i *installation.Failure
	if errors.As(err, &i) {
		return i.Reason
	}
	return "SynchronizationFailed"
}

type State struct {
	Version             int               `json:"version"`
	InstallationID      string            `json:"installationID"`
	BootstrapGeneration int64             `json:"bootstrapGeneration"`
	TrustBundleUID      string            `json:"trustBundleUID"`
	NodeFingerprint     string            `json:"nodeFingerprint"`
	Bindings            map[string]Record `json:"bindings"`
	Recovery            *RecoveryProgress `json:"recovery,omitempty"`
}
type RecoveryProgress struct {
	ID       string `json:"id"`
	PlanHash string `json:"planHash"`
	Phase    string `json:"phase"`
}
type Record struct {
	Mode       string                 `json:"mode,omitempty"`
	CRUID      string                 `json:"crUID"`
	CRName     string                 `json:"crName"`
	StoreUID   string                 `json:"storeUID"`
	BindingID  string                 `json:"bindingID"`
	Identity   string                 `json:"identity"`
	TargetName string                 `json:"targetName"`
	TargetUID  string                 `json:"targetUID"`
	Head       *witness.Head          `json:"head"`
	Rollout    *rollout.Authorization `json:"rollout,omitempty"`
}
type stateStore struct {
	cfg         installation.Config
	reader      client.Reader
	writer      client.Client
	fingerprint string
}

func strict(raw []byte, out any, max int) error {
	canonical, err := e2e2.Canonical(raw, max)
	if err != nil {
		return fail("StateInvalid")
	}
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return fail("StateInvalid")
	}
	round, err := json.Marshal(out)
	if err != nil {
		return fail("StateInvalid")
	}
	round, err = e2e2.Canonical(round, max)
	if err != nil || !bytes.Equal(round, canonical) {
		return fail("StateInvalid")
	}
	return nil
}
func (s stateStore) load(ctx context.Context) (*corev1.Secret, State, error) {
	var secret corev1.Secret
	var state State
	err := s.reader.Get(ctx, types.NamespacedName{Namespace: s.cfg.Namespace, Name: s.cfg.StateSecret.Name}, &secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, state, fail("StateMissing")
		}
		return nil, state, fail("StateUnavailable")
	}
	if string(secret.UID) != s.cfg.StateSecret.UID || secret.Type != corev1.SecretTypeOpaque || secret.Immutable != nil && *secret.Immutable {
		return nil, state, fail("StateReplaced")
	}
	if strict(secret.Data[StateKey], &state, stateLimit) != nil || state.Version != 1 || state.InstallationID != s.cfg.InstallationID || state.BootstrapGeneration != s.cfg.BootstrapGeneration || state.TrustBundleUID != s.cfg.TrustBundleSecret.UID || state.NodeFingerprint != s.fingerprint || state.Bindings == nil || len(state.Bindings) > 64 {
		return nil, state, fail("StateInvalid")
	}
	if state.Recovery != nil {
		if !installation.ValidUUID(state.Recovery.ID) || len(state.Recovery.PlanHash) != 64 {
			return nil, state, fail("StateInvalid")
		}
		if state.Recovery.Phase == "prepared" {
			return nil, state, fail("RecoveryPending")
		}
		if state.Recovery.Phase != "complete" {
			return nil, state, fail("StateInvalid")
		}
	}
	for key, r := range state.Bindings {
		if key != r.StoreUID+"/"+r.BindingID || !installation.ValidUUID(r.StoreUID) || !installation.ValidUUID(r.BindingID) || !installation.ValidUUID(r.CRUID) || !installation.ValidName(r.CRName) || !installation.ValidName(r.TargetName) || r.Identity == "" || r.TargetUID != "" && !installation.ValidUUID(r.TargetUID) {
			return nil, state, fail("StateInvalid")
		}
		if r.Mode == "Plain" {
			if r.Head != nil || s.cfg.HA != nil {
				return nil, state, fail("StateInvalid")
			}
		} else if r.Mode != "" || r.Head == nil || !validHead(*r.Head) {
			return nil, state, fail("StateInvalid")
		}
		if !rollout.ValidAuthorization(r.Rollout) {
			return nil, state, fail("StateInvalid")
		}
	}
	return &secret, state, nil
}
func validHead(h witness.Head) bool {
	if !e2e2.ValidScope(e2e2.Scope{RealmID: h.Scope.RealmID, ProjectID: h.Scope.ProjectID, EnvironmentID: h.Scope.EnvironmentID, ViewID: h.Scope.ViewID, LogID: h.Scope.LogID}) || len(h.EnvelopeHash) != 64 || h.EnvelopeHash == e2e2.ZeroHash {
		return false
	}
	for _, c := range []byte(h.EnvelopeHash) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	for _, c := range []string{h.Sequence, h.ReadKeyEpoch, h.PublisherPolicyEpoch, h.WitnessEpoch} {
		if _, err := e2e2.Counter(c, false); err != nil {
			return false
		}
	}
	return true
}
func monotonic(old, next witness.Head) error {
	if !validHead(old) || !validHead(next) || old.Scope != next.Scope || old.WitnessEpoch != next.WitnessEpoch {
		return fail("CheckpointMismatch")
	}
	a, _ := e2e2.Counter(old.Sequence, false)
	b, _ := e2e2.Counter(next.Sequence, false)
	if b < a {
		return fail("RollbackDetected")
	}
	if a == b && old != next {
		return fail("ForkDetected")
	}
	for _, pair := range [][2]string{{old.ReadKeyEpoch, next.ReadKeyEpoch}, {old.PublisherPolicyEpoch, next.PublisherPolicyEpoch}} {
		a, _ := e2e2.Counter(pair[0], false)
		b, _ := e2e2.Counter(pair[1], false)
		if b < a {
			return fail("EpochRollback")
		}
	}
	return nil
}
func sameIdentity(a, b Record) bool {
	return a.Mode == b.Mode && a.CRUID == b.CRUID && a.CRName == b.CRName && a.StoreUID == b.StoreUID && a.BindingID == b.BindingID && a.Identity == b.Identity && a.TargetName == b.TargetName
}

// Plain records never carry a witness head. A zero temporary argument is only
// meaningful together with the explicit protected Plain mode discriminator.
func recordHeadMatches(r Record, head witness.Head) bool {
	if r.Mode == "Plain" {
		return r.Head == nil && head == (witness.Head{})
	}
	return r.Mode == "" && r.Head != nil && *r.Head == head
}

// update uses Kubernetes resourceVersion CAS and NEVER creates/reset state.
func (s stateStore) update(ctx context.Context, key string, expected Record, fn func(*Record) error) (Record, error) {
	for attempt := 0; attempt < 5; attempt++ {
		secret, state, err := s.load(ctx)
		if err != nil {
			return Record{}, err
		}
		record, exists := state.Bindings[key]
		if exists && !sameIdentity(record, expected) {
			return Record{}, fail("OwnershipConflict")
		}
		if !exists {
			if len(state.Bindings) >= 64 {
				return Record{}, fail("StateCapacity")
			}
			record = expected
		}
		// Nested authorization/progress must not alias the no-op comparison.
		beforeRaw, _ := json.Marshal(record)
		var before Record
		if json.Unmarshal(beforeRaw, &before) != nil {
			return Record{}, fail("StateInvalid")
		}
		if err := fn(&record); err != nil {
			return Record{}, err
		}
		if exists && reflect.DeepEqual(before, record) {
			return record, nil
		}
		state.Bindings[key] = record
		raw, err := json.Marshal(state)
		if err != nil || len(raw) > stateLimit {
			return Record{}, fail("StateCapacity")
		}
		secret.Data[StateKey] = raw
		if ctx.Err() != nil {
			return Record{}, fail("Cancelled")
		}
		if err = s.writer.Update(ctx, secret); err == nil {
			return record, nil
		} else if !apierrors.IsConflict(err) {
			return Record{}, fail("StateWriteFailed")
		}
	}
	return Record{}, fail("StateConflict")
}

func (s stateStore) confirm(ctx context.Context, key string, expected Record, head witness.Head, targetUID string) error {
	_, state, err := s.load(ctx)
	if err != nil {
		return err
	}
	record, exists := state.Bindings[key]
	if !exists || !sameIdentity(record, expected) || record.TargetUID != targetUID {
		return fail("OwnershipConflict")
	}
	if !recordHeadMatches(record, head) {
		return fail("HeadChanged")
	}
	return nil
}
