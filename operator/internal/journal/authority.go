package journal

import (
	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

// Apply validates the entire record before returning a fresh state. It does not
// mutate its input, perform network I/O, or turn a candidate into a commit.
func Apply(previous CurrentState, r Record) (CurrentState, error) {
	state := cloneState(previous)
	switch r.Kind {
	case "snapshot":
		if r.Envelope == nil || r.Genesis != nil || r.Transition != nil || r.FenceGrant != nil || r.FenceActivation != nil {
			return CurrentState{}, Failure("RecordInvalid")
		}
		if err := applySnapshot(&state, *r.Envelope, ""); err != nil {
			return CurrentState{}, err
		}
	case "transition":
		if r.Transition == nil || r.Genesis != nil || r.Envelope != nil || r.FenceGrant != nil || r.FenceActivation != nil {
			return CurrentState{}, Failure("RecordInvalid")
		}
		if err := applyTransition(&state, *r.Transition); err != nil {
			return CurrentState{}, err
		}
	case "fence-grant":
		if r.FenceGrant == nil || r.Genesis != nil || r.Envelope != nil || r.Transition != nil || r.FenceActivation != nil {
			return CurrentState{}, Failure("RecordInvalid")
		}
		if err := applyGrant(&state, *r.FenceGrant); err != nil {
			return CurrentState{}, err
		}
	case "fence-activation":
		if r.FenceActivation == nil || r.Genesis != nil || r.Envelope != nil || r.Transition != nil || r.FenceGrant != nil {
			return CurrentState{}, Failure("RecordInvalid")
		}
		if err := applyActivation(&state, *r.FenceActivation); err != nil {
			return CurrentState{}, err
		}
	default:
		return CurrentState{}, Failure("RecordInvalid")
	}
	return state, nil
}
func applySnapshot(s *CurrentState, envelope e2e2.Envelope, action string) error {
	raw, err := canonical(envelope, e2e2.MaxEnvelopeBytes)
	if err != nil {
		return err
	}
	hash, err := e2e2.EnvelopeHash(raw)
	if err != nil {
		return Failure("EnvelopeInvalid")
	}
	next, err := nextCounter(s.Snapshot.Sequence)
	if err != nil {
		return err
	}
	v, err := e2e2.VerifyEnvelope(raw, e2e2.Expected{Scope: s.Scope, Sequence: next, EnvelopeHash: hash, ReadKeyEpoch: s.Authority.ReadKeyEpoch, PublisherPolicyEpoch: s.Authority.PublisherPolicyEpoch, PublisherKeys: keysMap(s.Authority.PublisherKeys)})
	if err != nil {
		return Failure("EnvelopeInvalid")
	}
	h := v.Header()
	if h.PreviousHash != s.Snapshot.EnvelopeHash {
		return Failure("EnvelopeFork")
	}
	if action != "" {
		if h.Action != action {
			return Failure("ActivationSnapshotInvalid")
		}
	} else if h.Action != "initial" && h.Action != "migrate" && h.Action != "update" {
		return Failure("AuthorityTransitionRequired")
	}
	if h.Action == "restore" {
		found := false
		for _, known := range s.History {
			if h.RestoredFrom != nil && known == *h.RestoredFrom && known != ZeroHash {
				found = true
			}
		}
		if !found {
			return Failure("RecoveryInvalid")
		}
	}
	s.Snapshot = Snapshot{Sequence: next, EnvelopeHash: hash, ReadKeyEpoch: h.ReadKeyEpoch, PublisherPolicyEpoch: h.PublisherPolicyEpoch}
	s.History[next] = hash
	return nil
}
func applyTransition(s *CurrentState, t SignedTransition) error {
	b := t.Body
	if b.Format != "sekvyr-authority-transition-v1" || b.Scope != s.Scope || b.GenesisHash != s.GenesisHash || b.Expected != s.Cursor || b.PreviousAuthorityDigest != s.AuthorityDigest || !validAuthority(b.Authority) || verifyValue(TransitionDomain, b, t.KeyID, t.Signature, s.Authority.AdminKey, MaxRecordBytes) != nil {
		return Failure("TransitionInvalid")
	}
	revision, err := nextCounter(s.Authority.Revision)
	if err != nil || b.Authority.Revision != revision {
		return Failure("AuthorityEpochInvalid")
	}
	want := s.Authority
	want.Revision = revision
	requiredAction := ""
	requireSnapshot := false
	switch b.Kind {
	case "rotate-admin":
		if b.Authority.AdminKey == want.AdminKey {
			return Failure("TransitionInvalid")
		}
		want.AdminKey = b.Authority.AdminKey
	case "rotate-publisher":
		want.PublisherPolicyEpoch, _ = nextCounter(want.PublisherPolicyEpoch)
		want.PublisherKeys = b.Authority.PublisherKeys
		if same(want.PublisherKeys, s.Authority.PublisherKeys) {
			return Failure("TransitionInvalid")
		}
		requireSnapshot = true
		requiredAction = "update"
	case "rotate-read-key":
		want.ReadKeyEpoch, _ = nextCounter(want.ReadKeyEpoch)
		requireSnapshot = true
		requiredAction = "rotate-read-key"
	case "rotate-witness":
		want.WitnessEpoch, _ = nextCounter(want.WitnessEpoch)
		if b.Authority.WitnessKey == want.WitnessKey {
			return Failure("TransitionInvalid")
		}
		want.WitnessKey = b.Authority.WitnessKey
	case "rotate-fencer":
		want.FencerEpoch, _ = nextCounter(want.FencerEpoch)
		want.FencerKeys = b.Authority.FencerKeys
		if same(want.FencerKeys, s.Authority.FencerKeys) {
			return Failure("TransitionInvalid")
		}
	case "enroll-installation":
		if b.Enrollment == nil {
			return Failure("EnrollmentInvalid")
		}
	case "recover":
		if b.RecoveryFrom == nil || !validRecovery(*b.RecoveryFrom) || b.RecoveryFrom.LogID != s.Scope.LogID || b.RecoveryFrom.GenesisHash != s.GenesisHash || b.RecoveryFrom.MinimumCursor != s.Cursor || s.History[b.RecoveryFrom.SnapshotSequence] != b.RecoveryFrom.EnvelopeHash {
			return Failure("RecoveryInvalid")
		}
		if !validRecoveryAuthority(s.Authority, b.Authority) {
			return Failure("AuthorityEpochInvalid")
		}
		want = b.Authority
		requireSnapshot = true
		requiredAction = "restore"
	default:
		return Failure("TransitionInvalid")
	}
	if !same(want, b.Authority) {
		return Failure("AuthorityEpochInvalid")
	}
	if b.Kind != "recover" && b.RecoveryFrom != nil {
		return Failure("TransitionInvalid")
	}
	if b.Kind != "enroll-installation" && b.Kind != "recover" && b.Enrollment != nil {
		return Failure("TransitionInvalid")
	}
	if requireSnapshot != (b.ActivatingEnvelope != nil) {
		return Failure("ActivationSnapshotRequired")
	}
	if b.Enrollment != nil {
		e := *b.Enrollment
		if !validEnrollment(e) {
			return Failure("EnrollmentInvalid")
		}
		if old, exists := s.Enrollments[e.InstallationID]; exists && e.BootstrapGeneration <= old.BootstrapGeneration {
			return Failure("EnrollmentGenerationInvalid")
		}
		if len(s.Enrollments) >= 64 {
			if _, exists := s.Enrollments[e.InstallationID]; !exists {
				return Failure("EnrollmentCapacity")
			}
		}
		s.Enrollments[e.InstallationID] = e
	}
	roles, roleErr := authorityRoles(b.Authority, s.KeyRoles)
	if roleErr != nil {
		return roleErr
	}
	s.KeyRoles = roles
	s.Authority = b.Authority
	if b.ActivatingEnvelope != nil {
		if err := applySnapshot(s, *b.ActivatingEnvelope, requiredAction); err != nil {
			return err
		}
	}
	s.AuthorityDigest, err = authorityDigest(*s)
	return err
}
func validRecoveryAuthority(old, next Authority) bool {
	witness, _ := nextCounter(old.WitnessEpoch)
	if next.WitnessEpoch != witness {
		return false
	}
	pairs := [][2]string{{old.PublisherPolicyEpoch, next.PublisherPolicyEpoch}, {old.ReadKeyEpoch, next.ReadKeyEpoch}, {old.FencerEpoch, next.FencerEpoch}}
	for _, pair := range pairs {
		n, _ := nextCounter(pair[0])
		if pair[1] != pair[0] && pair[1] != n {
			return false
		}
	}
	if !same(old.PublisherKeys, next.PublisherKeys) && next.PublisherPolicyEpoch == old.PublisherPolicyEpoch {
		return false
	}
	if !same(old.FencerKeys, next.FencerKeys) && next.FencerEpoch == old.FencerEpoch {
		return false
	}
	return true
}
func applyGrant(s *CurrentState, g SignedFenceGrant) error {
	b := g.Body
	e, exists := s.Enrollments[b.InstallationID]
	if !exists || VerifyFenceGrant(g, s.Authority) != nil || b.Scope != s.Scope || b.GenesisHash != s.GenesisHash || b.AuthorityDigest != s.AuthorityDigest || b.Snapshot != s.Snapshot || b.BootstrapGeneration != e.BootstrapGeneration || !same(b.Objects, e.AllowedObjects) {
		return Failure("GrantInvalid")
	}
	expectedTerm := "1"
	previousHash := ZeroHash
	if previous, ok := s.Grants[b.InstallationID]; ok {
		expectedTerm, _ = nextCounter(previous.Body.Term)
		previousHash, _ = FenceGrantHash(previous.Body)
	}
	if b.Term != expectedTerm || b.PreviousGrantHash != previousHash {
		return Failure("GrantCASConflict")
	}
	s.Grants[b.InstallationID] = g
	return nil
}
func applyActivation(s *CurrentState, a SignedFenceActivation) error {
	b := a.Body
	g, current := s.CurrentGrant(b.InstallationID)
	if !current || b.Format != "sekvyr-fence-activation-v1" || b.Scope != s.Scope || b.GenesisHash != s.GenesisHash || b.AuthorityDigest != s.AuthorityDigest || b.Snapshot != s.Snapshot || b.Snapshot != g.Body.Snapshot || b.BootstrapGeneration != g.Body.BootstrapGeneration || b.Term != g.Body.Term || b.OwnerPodUID != g.Body.OwnerPodUID || b.LeaseHolderIdentity != g.Body.LeaseHolderIdentity || !same(b.Objects, g.Body.Objects) || VerifyFenceActivation(a, s.Authority) != nil {
		return Failure("ActivationInvalid")
	}
	hash, _ := FenceGrantHash(g.Body)
	if b.GrantHash != hash {
		return Failure("GrantCASConflict")
	}
	s.Activations[b.InstallationID] = a
	return nil
}
