// Package verification joins independently pinned trust, nonce-bound witness
// proofs, signed reader wraps and whole-view snapshot verification. It performs
// no Kubernetes mutation, checkpoint persistence or automatic publication.
package verification

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
)

const HeadRetries = 3
const requestTimeout = 30 * time.Second

// Error exposes a stable reason without transport errors or secret material.
type Error struct{ Reason string }

func (e *Error) Error() string   { return "snapshot verification: " + e.Reason }
func reject(reason string) error { return &Error{Reason: reason} }

// Source is an untrusted data transport. Its implementation must enforce stream
// bounds and cancellation; the reader checks the returned wire bounds again.
// The envelope is requested by exact authenticated hash, never by a panel pointer.
type Source interface {
	EnvelopeByHash(context.Context, witness.Scope, string) ([]byte, error)
	ReaderWrap(context.Context, witness.Scope, string, string, string, string) ([]byte, error)
}

// Trust is administrator-provisioned, independent of the panel and of incoming
// proof/snapshot bytes. Policy changes require a new authorized trust bundle.
type Trust struct {
	Scope                witness.Scope
	PublisherPolicyEpoch string
	PublisherKeys        map[string]ed25519.PublicKey
	WitnessEpoch         string
	WitnessKeyID         string
	WitnessPublicKey     ed25519.PublicKey
	MinimumCheckpoint    witness.Floor
	NodeFingerprint      string
	WitnessOrigin        string
}

type Reader struct {
	trust         Trust
	node          *ecdh.PrivateKey
	witnessClient witness.Client
	verifier      *witness.PinnedVerifier
	source        Source
}

// Accepted cannot be constructed with plaintext or an authenticated current head
// by an arbitrary caller. A returned head is VERIFIED, not durably persisted.
// Stage 4 must persist it before any target write and preserve failure handling.
type Accepted struct {
	values []Value
	head   witness.Head
}

type Value struct {
	path, name string
	data       []byte
}

func (v Value) Path() string      { return v.path }
func (v Value) Name() string      { return v.name }
func (v Value) Data() []byte      { return bytes.Clone(v.data) }
func (Value) String() string      { return "verified value [redacted]" }
func (Value) GoString() string    { return "verified value [redacted]" }
func (Accepted) String() string   { return "verified snapshot [redacted]" }
func (Accepted) GoString() string { return "verified snapshot [redacted]" }
func (a *Accepted) Head() witness.Head {
	if a == nil {
		return witness.Head{}
	}
	return a.head
}
func (a *Accepted) Values() []Value {
	if a == nil {
		return nil
	}
	values := make([]Value, len(a.values))
	for i, v := range a.values {
		values[i] = Value{v.path, v.name, bytes.Clone(v.data)}
	}
	return values
}

func NewReader(trust Trust, node *ecdh.PrivateKey, heads witness.Client, source Source) (*Reader, error) {
	if node == nil || node.Curve() != ecdh.P256() || heads == nil || source == nil || len(trust.PublisherKeys) == 0 || len(trust.PublisherKeys) > 16 {
		return nil, reject("TrustInvalid")
	}
	fingerprint, err := e2e2.NodeKeyFingerprint(node.PublicKey())
	if err != nil || fingerprint != trust.NodeFingerprint {
		return nil, reject("NodeKeyMismatch")
	}
	if _, err := e2e2.Counter(trust.MinimumCheckpoint.Sequence, false); err != nil {
		return nil, reject("TrustInvalid")
	}
	verifier, err := witness.NewPinnedVerifier(witness.Trust{Scope: trust.Scope, WitnessEpoch: trust.WitnessEpoch,
		KeyID: trust.WitnessKeyID, PublicKey: trust.WitnessPublicKey, PublisherPolicyEpoch: trust.PublisherPolicyEpoch, Checkpoint: trust.MinimumCheckpoint})
	if err != nil {
		return nil, reject("TrustInvalid")
	}
	keys := make(map[string]ed25519.PublicKey, len(trust.PublisherKeys))
	for id, key := range trust.PublisherKeys {
		if !e2e2.ValidEd25519PublicKey(key) || e2e2.KeyID(key) != id {
			return nil, reject("TrustInvalid")
		}
		keys[id] = bytes.Clone(key)
	}
	trust.PublisherKeys = keys
	trust.WitnessPublicKey = bytes.Clone(trust.WitnessPublicKey)
	return &Reader{trust: trust, node: node, witnessClient: heads, verifier: verifier, source: source}, nil
}

// ReadCurrent requires live nonce-bound witness answers on every attempt. Local
// state is a trusted durable high-watermark supplied by the later state adapter,
// bound to installation ID, bootstrap generation and this trust identity by
// that adapter, not a panel cache or a checkpoint copied between trust bundles.
// nil means explicitly bootstrapping a new installation from
// an independent minimum checkpoint; lost state must be rejected by the caller's
// installation gate, never silently turned into nil here.
func (r *Reader) ReadCurrent(ctx context.Context, local *witness.Head) (*Accepted, error) {
	if r == nil || r.verifier == nil {
		return nil, reject("TrustInvalid")
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, reject("Cancelled")
	}
	floor := r.trust.MinimumCheckpoint
	var high *witness.Head
	if local != nil {
		copy := *local
		high = &copy
		seq, err := e2e2.Counter(copy.Sequence, false)
		min, _ := e2e2.Counter(floor.Sequence, false)
		if err != nil {
			return nil, reject("CheckpointInvalid")
		}
		if seq == min && copy.EnvelopeHash != floor.EnvelopeHash {
			return nil, reject("ForkDetected")
		}
		if seq > min {
			floor = witness.Floor{Sequence: copy.Sequence, EnvelopeHash: copy.EnvelopeHash}
		}
	}
	seen := make(map[[32]byte]bool, HeadRetries*2)
	for attempt := 0; attempt < HeadRetries; attempt++ {
		first, err := r.head(ctx, floor, high, seen)
		if err != nil {
			return nil, err
		}
		if first.Sequence == "0" {
			return nil, reject("CanonicalSnapshotUnavailable")
		}
		raw, err := r.envelope(ctx, first)
		if err != nil {
			return nil, err
		}
		verified, err := e2e2.VerifyEnvelope(raw, e2e2.Expected{Scope: codecScope(first.Scope), Sequence: first.Sequence,
			EnvelopeHash: first.EnvelopeHash, ReadKeyEpoch: first.ReadKeyEpoch, PublisherPolicyEpoch: first.PublisherPolicyEpoch, PublisherKeys: r.trust.PublisherKeys})
		if err != nil {
			return nil, cryptoFailure(err)
		}
		// When the immediately preceding canonical head is known, require the
		// signed link as well. Larger jumps rely on the honest witness's signed
		// proof that the exact floor belongs to its canonical history.
		seq, _ := e2e2.Counter(first.Sequence, false)
		prior, _ := e2e2.Counter(floor.Sequence, false)
		if seq > prior && seq-prior == 1 && verified.Header().PreviousHash != floor.EnvelopeHash {
			return nil, reject("ForkDetected")
		}
		wrapped, err := r.wrapper(ctx, first)
		if err != nil {
			return nil, err
		}
		key, err := e2e2.UnwrapReader(wrapped, r.node, verified)
		if err != nil {
			return nil, cryptoFailure(err)
		}
		plain, err := verified.Decrypt(key)
		clear(key)
		if err != nil {
			return nil, cryptoFailure(err)
		}
		second, err := r.head(ctx, witness.Floor{Sequence: first.Sequence, EnvelopeHash: first.EnvelopeHash}, &first, seen)
		if err != nil {
			return nil, err
		}
		if second != first {
			copy := second
			high = &copy
			floor = witness.Floor{Sequence: second.Sequence, EnvelopeHash: second.EnvelopeHash}
			continue
		}
		if ctx.Err() != nil {
			return nil, reject("Cancelled")
		}
		values := make([]Value, len(plain.Entries))
		for i, entry := range plain.Entries {
			values[i] = Value{entry.Path, entry.Name, []byte(entry.Value)}
		}
		return &Accepted{values: values, head: second}, nil
	}
	return nil, reject("HeadChanged")
}

func (r *Reader) head(ctx context.Context, floor witness.Floor, high *witness.Head, seen map[[32]byte]bool) (witness.Head, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil || seen[nonce] {
		return witness.Head{}, reject("RandomUnavailable")
	}
	seen[nonce] = true
	challenge := witness.Challenge{Scope: r.trust.Scope, Nonce: bytes.Clone(nonce[:]), Floor: floor}
	if high != nil {
		copy := *high
		challenge.HighWatermark = &copy
	}
	// Validate ALL local constraints before any transport call. An invalid
	// local watermark must not be sent to the independent witness.
	if err := r.validateLocal(floor, high); err != nil {
		return witness.Head{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	// The transport receives a separate challenge copy; it cannot mutate the
	// nonce/floor/high-watermark which will be used for signature verification.
	wire := challenge
	wire.Nonce = bytes.Clone(challenge.Nonce)
	if high != nil {
		copy := *high
		wire.HighWatermark = &copy
	}
	raw, err := r.witnessClient.Head(requestCtx, wire)
	if err != nil {
		return witness.Head{}, reject("WitnessUnavailable")
	}
	if requestCtx.Err() != nil {
		return witness.Head{}, reject("WitnessUnavailable")
	}
	head, err := r.verifier.VerifyHead(requestCtx, challenge, raw)
	if err != nil {
		var safe *witness.Error
		if errors.As(err, &safe) {
			return witness.Head{}, reject(safe.Reason)
		}
		return witness.Head{}, reject("WitnessInvalid")
	}
	return head, nil
}

func (r *Reader) validateLocal(floor witness.Floor, local *witness.Head) error {
	if local == nil {
		return nil
	}
	if local.Scope != r.trust.Scope || local.WitnessEpoch != r.trust.WitnessEpoch || local.PublisherPolicyEpoch != r.trust.PublisherPolicyEpoch {
		return reject("CheckpointInvalid")
	}
	for _, counter := range []string{local.Sequence, local.ReadKeyEpoch, local.PublisherPolicyEpoch} {
		if _, err := e2e2.Counter(counter, false); err != nil {
			return reject("CheckpointInvalid")
		}
	}
	if len(local.EnvelopeHash) != 64 {
		return reject("CheckpointInvalid")
	}
	for _, c := range []byte(local.EnvelopeHash) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return reject("CheckpointInvalid")
		}
	}
	if local.EnvelopeHash == string(bytes.Repeat([]byte{'0'}, 64)) {
		return reject("CheckpointInvalid")
	}
	seq, _ := e2e2.Counter(local.Sequence, false)
	min, _ := e2e2.Counter(floor.Sequence, false)
	if seq > min {
		return reject("CheckpointInvalid")
	}
	if seq == min && local.EnvelopeHash != floor.EnvelopeHash {
		return reject("ForkDetected")
	}
	return nil
}

func (r *Reader) envelope(ctx context.Context, head witness.Head) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	raw, err := r.source.EnvelopeByHash(requestCtx, head.Scope, head.EnvelopeHash)
	if requestCtx.Err() != nil {
		return nil, reject("CanonicalSnapshotUnavailable")
	}
	if err != nil {
		return nil, sourceFailure(err, "CanonicalSnapshotUnavailable")
	}
	if len(raw) == 0 || len(raw) > e2e2.MaxEnvelopeBytes {
		return nil, reject("SnapshotBounds")
	}
	return raw, nil
}
func (r *Reader) wrapper(ctx context.Context, head witness.Head) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	raw, err := r.source.ReaderWrap(requestCtx, head.Scope, head.EnvelopeHash, head.ReadKeyEpoch, head.PublisherPolicyEpoch, r.trust.NodeFingerprint)
	if requestCtx.Err() != nil {
		return nil, reject("ReadKeyUnavailable")
	}
	if err != nil {
		return nil, sourceFailure(err, "ReadKeyUnavailable")
	}
	if len(raw) == 0 || len(raw) > e2e2.MaxReaderWrapBytes {
		return nil, reject("WrapperBounds")
	}
	return raw, nil
}

// Only an explicit fixed reason allowlist crosses the untrusted source boundary.
// Terminal denials invalidate pending rollout authority; availability errors only
// freeze it. Never expose upstream text, URLs or authentication response bodies.
func sourceFailure(err error, fallback string) error {
	var safe interface{ SourceReason() string }
	if errors.As(err, &safe) {
		switch safe.SourceReason() {
		case "AccessDenied", "AuthenticationDenied", "ScopeDenied", "PanelUnavailable", "RateLimited", "UpgradeRequired", "ProjectedTokenUnavailable", "ProjectedTokenExpired", "ProjectedTokenInvalid", "ProjectedIdentityMismatch":
			return reject(safe.SourceReason())
		}
	}
	return reject(fallback)
}
func cryptoFailure(err error) error {
	var safe *e2e2.Error
	if errors.As(err, &safe) {
		return reject(safe.Reason)
	}
	return reject("SnapshotInvalid")
}
func codecScope(s witness.Scope) e2e2.Scope {
	return e2e2.Scope{RealmID: s.RealmID, ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID, ViewID: s.ViewID, LogID: s.LogID}
}
