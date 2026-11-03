package witnessservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

type Service struct {
	root          string
	registrations map[string]Registration
	fetchers      map[string]StagedFetcher
	signing       ed25519.PrivateKey
	slots         chan struct{}
}

func (Service) String() string   { return "development witness service [redacted]" }
func (Service) GoString() string { return "development witness service [redacted]" }

func New(root string, cfg Config, signing ed25519.PrivateKey, allowDevelopment bool, factory FetcherFactory) (*Service, error) {
	if !allowDevelopment {
		return nil, fail("DevelopmentProfileNotAuthorized")
	}
	if !filepath.IsAbs(root) || len(signing) != ed25519.PrivateKeySize || !ed25519.NewKeyFromSeed(signing[:32]).Equal(signing) || factory == nil {
		return nil, fail("ConfigInvalid")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fail("LedgerUnavailable")
	}
	// Apply exactly the same validation for Go callers as for JSON config files.
	raw, err := canonical(cfg, 64<<10)
	if err != nil {
		return nil, fail("ConfigInvalid")
	}
	cfg, err = DecodeConfig(raw)
	if err != nil {
		return nil, err
	}
	s := &Service{root: root, registrations: map[string]Registration{}, fetchers: map[string]StagedFetcher{}, signing: append(ed25519.PrivateKey(nil), signing...), slots: make(chan struct{}, 4)}
	for _, reg := range cfg.Registrations {
		var body GenesisBody
		startup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = withLog(startup, root, reg, func(_ string, state *logState) error {
			pub, _ := e2e2.DecodeBase64(state.genesis.WitnessPublicKey, 32)
			if !ed25519.PublicKey(pub).Equal(signing.Public()) {
				return fail("SigningKeyMismatch")
			}
			body = state.genesis
			return nil
		})
		cancel()
		if err != nil {
			return nil, err
		}
		fetcher, err := factory(body, reg)
		if err != nil || fetcher == nil {
			return nil, fail("StagingFetcherInvalid")
		}
		s.registrations[reg.LogID] = reg
		s.fetchers[reg.LogID] = fetcher
	}
	return s, nil
}

// Head signs only while holding the same exclusive journal lock used for CAS.
// Every call replays and synchronizes the canonical journal; no cached head can
// issue a receipt. The configured independent minimum checkpoint is checked too.
func (s *Service) Head(ctx context.Context, log string, request HeadRequest) ([]byte, error) {
	if s == nil {
		return nil, fail("ServiceUnavailable")
	}
	reg, ok := s.registrations[log]
	if !ok {
		return nil, fail("LogUnknown")
	}
	nonce, err := e2e2.DecodeBase64(request.RequestNonce, 32)
	if err != nil || !validCheckpoint(Checkpoint{request.FloorSequence, request.FloorHash}) {
		return nil, fail("ChallengeInvalid")
	}
	var proof []byte
	err = withLog(ctx, s.root, reg, func(_ string, state *logState) error {
		if state.history[request.FloorSequence] != request.FloorHash {
			return fail("FloorUnknownOrFork")
		}
		head := state.head
		body := e2e2.HeadBody{Format: "sekvyr-e2e2-head-v1", Scope: state.genesis.Scope, WitnessEpoch: head.WitnessEpoch, Sequence: head.Sequence, EnvelopeHash: head.EnvelopeHash, ReadKeyEpoch: head.ReadKeyEpoch, PublisherPolicyEpoch: head.PublisherPolicyEpoch, RequestNonce: base64.RawURLEncoding.EncodeToString(nonce), WitnessKeyID: state.genesis.WitnessKeyID, FloorSequence: request.FloorSequence, FloorHash: request.FloorHash}
		canonicalBody, err := canonical(body, e2e2.MaxHeadProofBytes)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return fail("Cancelled")
		}
		signed := e2e2.HeadProof{Body: body, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.signing, append(e2e2.Domain("sekvyr-e2e2/head/v1"), canonicalBody...)))}
		proof, err = canonical(signed, e2e2.MaxHeadProofBytes)
		return err
	})
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func (s *Service) Commit(ctx context.Context, log string, request CommitRequest) (CommitResponse, error) {
	if s == nil {
		return CommitResponse{}, fail("ServiceUnavailable")
	}
	reg, ok := s.registrations[log]
	if !ok {
		return CommitResponse{}, fail("LogUnknown")
	}
	if !validHash(request.EnvelopeHash, false) || !validCheckpoint(Checkpoint{request.Expected.Sequence, request.Expected.EnvelopeHash}) {
		return CommitResponse{}, fail("CommitInvalid")
	}
	if _, err := e2e2.Counter(request.Expected.WitnessEpoch, false); err != nil {
		return CommitResponse{}, fail("CommitInvalid")
	}
	if _, err := e2e2.Counter(request.Expected.PublisherPolicyEpoch, true); err != nil {
		return CommitResponse{}, fail("CommitInvalid")
	}
	var response CommitResponse
	err := withLog(ctx, s.root, reg, func(path string, state *logState) error {
		head := state.head
		if request.Expected.Sequence != head.Sequence || request.Expected.EnvelopeHash != head.EnvelopeHash || request.Expected.WitnessEpoch != head.WitnessEpoch || request.Expected.PublisherPolicyEpoch != head.PublisherPolicyEpoch {
			return fail("CASConflict")
		}
		seq, _ := e2e2.Counter(head.Sequence, true)
		if seq >= maxRecords-1 {
			return fail("LedgerCapacityOrCorruption")
		}
		raw, err := s.fetchers[log].Fetch(ctx, state.genesis.Scope, request.EnvelopeHash)
		if err != nil || len(raw) == 0 || len(raw) > e2e2.MaxEnvelopeBytes {
			return fail("StagedEnvelopeUnavailable")
		}
		raw = bytes.Clone(raw)
		next, err := verifyNext(raw, state)
		if err != nil {
			return err
		}
		if next.EnvelopeHash != request.EnvelopeHash {
			return fail("StagedEnvelopeHashMismatch")
		}
		var envelope e2e2.Envelope
		if e2e2.DecodeStrict(raw, &envelope, e2e2.MaxEnvelopeBytes) != nil {
			return fail("EnvelopeInvalid")
		}
		record, err := canonical(commitRecord{Format: "sekvyr-witness-commit-v1", Envelope: envelope}, e2e2.MaxEnvelopeBytes+1024)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return fail("Cancelled")
		}
		if err = appendRecord(path, seq+1, record); err != nil {
			return err
		}
		response = CommitResponse{Sequence: strconv.FormatUint(seq+1, 10), EnvelopeHash: next.EnvelopeHash}
		return nil
	})
	if err != nil {
		return CommitResponse{}, err
	}
	return response, nil
}

// Decode requests through the shared strict codec: duplicate, unknown and
// case-insensitive aliases are not accepted at this authority boundary.
func decodeHead(raw []byte) (HeadRequest, error) {
	var req HeadRequest
	if e2e2.DecodeStrict(raw, &req, 2048) != nil {
		return req, fail("RequestInvalid")
	}
	return req, nil
}
func decodeCommit(raw []byte) (CommitRequest, error) {
	var req CommitRequest
	if e2e2.DecodeStrict(raw, &req, 2048) != nil {
		return req, fail("RequestInvalid")
	}
	return req, nil
}
