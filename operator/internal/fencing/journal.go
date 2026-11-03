package fencing

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
)

// Ledger must read the independent canonical journal online and verify its
// administrator registration, retention receipts and complete ordered history.
// No ETag/head cache or caller-provided authority may implement this boundary.
type Ledger interface {
	ReadCurrent(context.Context, string, journal.Cursor) (journal.CurrentState, error)
	AppendFenceGrantCAS(context.Context, string, journal.Cursor, []byte) (journal.CurrentState, error)
	AppendFenceActivationCAS(context.Context, string, journal.Cursor, []byte) (journal.CurrentState, error)
}

func currentGrant(state journal.CurrentState, installation string, active bool) (journal.SignedFenceGrant, string, error) {
	grant, present := state.CurrentGrant(installation)
	enrollment, enrolled := state.Enrollments[installation]
	if !present || !enrolled || journal.VerifyFenceGrant(grant, state.Authority) != nil || grant.Body.Scope != state.Scope ||
		grant.Body.GenesisHash != state.GenesisHash || grant.Body.InstallationID != installation ||
		grant.Body.Snapshot != state.Snapshot ||
		!reflect.DeepEqual(grant.Body.Objects, enrollment.AllowedObjects) {
		return journal.SignedFenceGrant{}, "", fail("GrantUnavailable")
	}
	hash, err := journal.FenceGrantHash(grant.Body)
	if err != nil {
		return journal.SignedFenceGrant{}, "", fail("GrantInvalid")
	}
	if active {
		activation, exists := state.Activations[installation]
		_, activated := state.ActiveGrant(installation)
		if !exists || !activated || journal.VerifyFenceActivation(activation, state.Authority) != nil ||
			activation.Body.Scope != grant.Body.Scope || activation.Body.GenesisHash != grant.Body.GenesisHash ||
			activation.Body.InstallationID != installation || activation.Body.BootstrapGeneration != grant.Body.BootstrapGeneration ||
			activation.Body.Snapshot != grant.Body.Snapshot ||
			!reflect.DeepEqual(activation.Body.Objects, grant.Body.Objects) {
			return journal.SignedFenceGrant{}, "", fail("BarriersIncomplete")
		}
	}
	return cloneGrant(grant), hash, nil
}

func cloneGrant(grant journal.SignedFenceGrant) journal.SignedFenceGrant {
	grant.Body.Objects = append([]journal.ObjectRef(nil), grant.Body.Objects...)
	return grant
}

type Session struct {
	grant journal.SignedFenceGrant
	hash  string
	fence string
	ready bool
}

func (*Session) String() string   { return "fencing session [redacted]" }
func (*Session) GoString() string { return "fencing session [redacted]" }
func (s *Session) Grant() journal.SignedFenceGrant {
	if s == nil {
		return journal.SignedFenceGrant{}
	}
	return cloneGrant(s.grant)
}
func (s *Session) Hash() string {
	if s == nil {
		return ""
	}
	return s.hash
}
func (s *Session) Fence() string {
	if s == nil {
		return ""
	}
	return s.fence
}

func sessionFrom(state journal.CurrentState, installation string, active bool) (*Session, error) {
	grant, hash, err := currentGrant(state, installation, active)
	if err != nil {
		return nil, err
	}
	fence, err := EncodeFence(Fence{InstallationID: installation, BootstrapGeneration: grant.Body.BootstrapGeneration,
		Term: grant.Body.Term, OwnerPodUID: grant.Body.OwnerPodUID, GrantHash: hash})
	if err != nil {
		return nil, err
	}
	return &Session{grant: grant, hash: hash, fence: fence, ready: active}, nil
}

func encodeWire(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maxWireBytes {
		return nil, fail("EncodingInvalid")
	}
	return raw, nil
}
