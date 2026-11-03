package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
const headDomain = "sekvyr-e2e2/head/v1"

// Error contains only a fixed public reason. Wire input and underlying codec
// errors never become status messages or logs.
type Error struct{ Reason string }

func (e *Error) Error() string   { return "witness verification: " + e.Reason }
func reject(reason string) error { return &Error{Reason: reason} }

// Trust must come from independent bootstrap configuration, never from a proof
// or an untrusted transport. Policy rotation requires a new authorized bundle.
type Trust struct {
	Scope                Scope
	WitnessEpoch         string
	KeyID                string
	PublicKey            ed25519.PublicKey
	PublisherPolicyEpoch string
	Checkpoint           Floor
}

// PinnedVerifier authenticates signed head assertions. It does not prove that a
// malicious witness obeys its ledger contract, persist checkpoints, generate
// nonces or maintain a replay cache. Callers generate a fresh CSPRNG nonce for
// every request and provide their durable local high-watermark on every call.
type PinnedVerifier struct{ trust Trust }

func NewPinnedVerifier(trust Trust) (*PinnedVerifier, error) {
	if !validScope(trust.Scope) || !e2e2.ValidEd25519PublicKey(trust.PublicKey) ||
		trust.KeyID != e2e2.KeyID(trust.PublicKey) {
		return nil, reject("TrustInvalid")
	}
	if _, err := e2e2.Counter(trust.WitnessEpoch, false); err != nil {
		return nil, reject("TrustInvalid")
	}
	if _, err := e2e2.Counter(trust.PublisherPolicyEpoch, false); err != nil {
		return nil, reject("TrustInvalid")
	}
	if _, ok := validFloor(trust.Checkpoint); !ok {
		return nil, reject("TrustInvalid")
	}
	trust.PublicKey = append(ed25519.PublicKey(nil), trust.PublicKey...)
	return &PinnedVerifier{trust: trust}, nil
}

func (v *PinnedVerifier) VerifyHead(ctx context.Context, challenge Challenge, raw []byte) (Head, error) {
	if ctx == nil || ctx.Err() != nil {
		return Head{}, reject("Cancelled")
	}
	if v == nil || len(v.trust.PublicKey) != ed25519.PublicKeySize {
		return Head{}, reject("TrustInvalid")
	}
	if challenge.Scope != v.trust.Scope || len(challenge.Nonce) != 32 {
		return Head{}, reject("ChallengeInvalid")
	}
	floorSeq, ok := validFloor(challenge.Floor)
	if !ok {
		return Head{}, reject("ChallengeInvalid")
	}
	pinnedSeq, _ := validFloor(v.trust.Checkpoint)
	expectedFloor := v.trust.Checkpoint
	if err := atLeast(challenge.Floor, floorSeq, v.trust.Checkpoint, pinnedSeq); err != nil {
		return Head{}, err
	}
	var local *Head
	if challenge.HighWatermark != nil {
		copy := *challenge.HighWatermark
		local = &copy
		seq, valid := validHead(*local)
		if !valid || local.Scope != v.trust.Scope || local.WitnessEpoch != v.trust.WitnessEpoch ||
			(seq > 0 && local.PublisherPolicyEpoch != v.trust.PublisherPolicyEpoch) {
			return Head{}, reject("ChallengeInvalid")
		}
		if seq == pinnedSeq && local.EnvelopeHash != v.trust.Checkpoint.EnvelopeHash {
			return Head{}, reject("ForkDetected")
		}
		if err := atLeast(challenge.Floor, floorSeq, Floor{local.Sequence, local.EnvelopeHash}, seq); err != nil {
			return Head{}, err
		}
		if seq > pinnedSeq {
			expectedFloor = Floor{local.Sequence, local.EnvelopeHash}
		}
	}
	// A higher but unanchored request floor must not replace the independent
	// checkpoint. The proof attests only the exact historical floor it signs.
	if challenge.Floor != expectedFloor {
		return Head{}, reject("ChallengeInvalid")
	}
	var proof e2e2.HeadProof
	if e2e2.DecodeStrict(raw, &proof, e2e2.MaxHeadProofBytes) != nil || e2e2.ValidateHeadProof(proof) != nil {
		return Head{}, reject("ProofInvalid")
	}
	bodyJSON, err := json.Marshal(proof.Body)
	if err != nil {
		return Head{}, reject("ProofInvalid")
	}
	body, err := e2e2.Canonical(bodyJSON, e2e2.MaxHeadProofBytes)
	if err != nil {
		return Head{}, reject("ProofInvalid")
	}
	signature, err := e2e2.DecodeBase64(proof.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(v.trust.PublicKey, append(e2e2.Domain(headDomain), body...), signature) {
		return Head{}, reject("SignatureInvalid")
	}
	b := proof.Body
	head := Head{Scope: Scope{b.RealmID, b.ProjectID, b.EnvironmentID, b.ViewID, b.LogID}, WitnessEpoch: b.WitnessEpoch,
		Sequence: b.Sequence, EnvelopeHash: b.EnvelopeHash, ReadKeyEpoch: b.ReadKeyEpoch, PublisherPolicyEpoch: b.PublisherPolicyEpoch}
	if head.Scope != v.trust.Scope || b.WitnessKeyID != v.trust.KeyID || b.WitnessEpoch != v.trust.WitnessEpoch {
		return Head{}, reject("TrustMismatch")
	}
	seq, _ := e2e2.Counter(b.Sequence, true)
	if seq > 0 && b.PublisherPolicyEpoch != v.trust.PublisherPolicyEpoch {
		return Head{}, reject("TrustMismatch")
	}
	nonce, err := e2e2.DecodeBase64(b.RequestNonce, 32)
	if err != nil || !bytes.Equal(nonce, challenge.Nonce) {
		return Head{}, reject("NonceMismatch")
	}
	if b.FloorSequence != challenge.Floor.Sequence || b.FloorHash != challenge.Floor.EnvelopeHash {
		return Head{}, reject("FloorMismatch")
	}
	if err := atLeast(Floor{head.Sequence, head.EnvelopeHash}, seq, challenge.Floor, floorSeq); err != nil {
		return Head{}, err
	}
	if local != nil {
		localSeq, _ := e2e2.Counter(local.Sequence, true)
		read, _ := e2e2.Counter(head.ReadKeyEpoch, true)
		localRead, _ := e2e2.Counter(local.ReadKeyEpoch, true)
		policy, _ := e2e2.Counter(head.PublisherPolicyEpoch, true)
		localPolicy, _ := e2e2.Counter(local.PublisherPolicyEpoch, true)
		if seq == localSeq && (head.ReadKeyEpoch != local.ReadKeyEpoch || head.PublisherPolicyEpoch != local.PublisherPolicyEpoch) {
			return Head{}, reject("ForkDetected")
		}
		if read < localRead || policy < localPolicy {
			return Head{}, reject("EpochRollback")
		}
	}
	if ctx.Err() != nil {
		return Head{}, reject("Cancelled")
	}
	return head, nil
}

func atLeast(candidate Floor, seq uint64, floor Floor, min uint64) error {
	if seq < min {
		return reject("RollbackDetected")
	}
	if seq == min && candidate.EnvelopeHash != floor.EnvelopeHash {
		return reject("ForkDetected")
	}
	return nil
}

func validFloor(floor Floor) (uint64, bool) {
	seq, err := e2e2.Counter(floor.Sequence, true)
	if err != nil || !validHash(floor.EnvelopeHash) || (seq == 0) != (floor.EnvelopeHash == zeroHash) {
		return 0, false
	}
	return seq, true
}

func validHead(head Head) (uint64, bool) {
	seq, ok := validFloor(Floor{head.Sequence, head.EnvelopeHash})
	if !ok || !validScope(head.Scope) {
		return 0, false
	}
	if _, err := e2e2.Counter(head.WitnessEpoch, false); err != nil {
		return 0, false
	}
	read, err := e2e2.Counter(head.ReadKeyEpoch, true)
	if err != nil {
		return 0, false
	}
	policy, err := e2e2.Counter(head.PublisherPolicyEpoch, true)
	if err != nil {
		return 0, false
	}
	if seq == 0 {
		return seq, read == 0 && policy == 0
	}
	return seq, read > 0 && policy > 0
}

func validHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, c := range []byte(hash) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validScope(scope Scope) bool {
	return e2e2.ValidScope(e2e2.Scope{RealmID: scope.RealmID, ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID, ViewID: scope.ViewID, LogID: scope.LogID})
}
