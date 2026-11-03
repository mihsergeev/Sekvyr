// Package witness defines the external canonical authority boundary.
// No service, storage adapter, in-memory ledger or trust fallback is supplied.
package witness

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("witness verification is not implemented")

// Scope is the complete independently pinned source identity, not a routing label.
type Scope struct {
	RealmID       string
	ProjectID     string
	EnvironmentID string
	ViewID        string
	LogID         string
}

// Floor is only a previously accepted sequence/hash constraint. It is not a
// verified current head and must never substitute for a nonce-bound head proof.
type Floor struct {
	Sequence     string
	EnvelopeHash string
}

// Head is public metadata. Constructing it does not authenticate it. Only a
// PinnedVerifier result authenticates a nonce-bound assertion by the independently
// pinned witness. The witness, not this reader verifier, verifies the journal.
type Head struct {
	Scope                Scope
	WitnessEpoch         string
	Sequence             string
	EnvelopeHash         string
	ReadKeyEpoch         string
	PublisherPolicyEpoch string
}

type Challenge struct {
	Scope Scope
	Nonce []byte
	Floor Floor
	// HighWatermark is an independently persisted, validated local constraint,
	// never a substitute for a fresh proof. The caller must not mutate it or
	// Nonce while verification is in progress.
	HighWatermark *Head
}

// Client is an untrusted transport: a response must pass a separate verifier.
type Client interface {
	Head(context.Context, Challenge) ([]byte, error)
}
type Verifier interface {
	VerifyHead(context.Context, Challenge, []byte) (Head, error)
}

// CanonicalLedger must be a linearizable durable external journal, not a panel or operator cache.
// Authority must be replayed and verified from the independently trusted genesis,
// including publisher policies and revocations, read-key epochs, witness key/epoch
// transitions and administrative recovery. A restored configuration or cached head
// cannot authorize a transition or supply a fresh signed proof. The canonical append
// must be durable before any proof acknowledging that append is signed or returned.
// No in-memory fallback or implementation is supplied by this scaffold.
type CanonicalLedger interface {
	ReadHead(context.Context, Scope) (Head, error)
	CompareAndAppend(context.Context, Head, []byte) (Head, error)
}
