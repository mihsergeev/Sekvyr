package provision

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
)

func execute(command string, raw []byte, f files, now time.Time) (artifacts, error) {
	return executePrepared(command, raw, f, now, nil)
}

func executePrepared(command string, raw []byte, f files, now time.Time, info *preparationInfo) (artifacts, error) {
	decode := func(v any) error {
		if journal.DecodeStrict(raw, v, MaxInputBytes) != nil {
			return ErrInvalid
		}
		return nil
	}
	switch command {
	case "keygen":
		var r KeygenRequest
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return keygen(r.Role)
	case "public":
		var r PublicRequest
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return publicArtifact(f, r)
	case "genesis":
		var r GenesisRequest
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return genesis(f, r)
	case "snapshot":
		var r SnapshotRequest
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return snapshot(f, r)
	case "transition":
		var r TransitionRequest
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return transition(f, r)
	case "bootstrap":
		var r BootstrapRequest
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return bootstrapPrepared(f, r, info)
	case "recovery":
		var r RecoveryRequest
		if decode(&r) != nil {
			return nil, ErrInvalid
		}
		return recoveryPlan(f, r, now)
	default:
		return nil, ErrInvalid
	}
}
func genesis(f files, r GenesisRequest) (artifacts, error) {
	var body journal.GenesisBody
	if decodeFile(f, r.BodyFile, &body, 128<<10) != nil {
		return nil, ErrInvalid
	}
	pub, err := publicFile(f, r.AdminPublicFile, "admin")
	if err != nil || body.Authority.AdminKey != pub.journalKey() {
		return nil, ErrAuthority
	}
	private, err := edKey(f, r.AdminKeyFile)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	if e2e2.KeyID(private.Public().(ed25519.PublicKey)) != pub.KeyID {
		return nil, ErrAuthority
	}
	signed, err := journal.SignGenesis(body, private)
	if err != nil {
		return nil, ErrInvalid
	}
	record := journal.NewGenesisRecord(signed)
	hash, err := journal.RecordHash(record)
	if err != nil {
		return nil, ErrInvalid
	}
	registration := journal.Registration{LogID: body.Scope.LogID, GenesisHash: hash, AdminPublicKey: pub.PublicKey, MinimumCursor: journal.Cursor{JournalSequence: "0", RecordHash: hash}}
	raw, err := journal.EncodeRecord(record)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err = journal.Replay(registration, []journal.StoredSlot{{Raw: raw}}); err != nil {
		return nil, ErrAuthority
	}
	reg, err := encode(registration, 16<<10)
	if err != nil {
		return nil, err
	}
	chain, err := encode([]journal.Record{record}, journal.MaxRecordBytes)
	if err != nil {
		return nil, err
	}
	return artifacts{"record.json": raw, "registration.json": reg, "records.json": chain}, nil
}
func transition(f files, r TransitionRequest) (artifacts, error) {
	p, err := replay(f, r.Chain)
	if err != nil {
		return nil, err
	}
	var b journal.TransitionBody
	if decodeFile(f, r.BodyFile, &b, journal.MaxRecordBytes) != nil {
		return nil, ErrInvalid
	}
	if b.Expected != p.state.Cursor || b.Scope != p.state.Scope || b.GenesisHash != p.state.GenesisHash || b.PreviousAuthorityDigest != p.state.AuthorityDigest {
		return nil, ErrAuthority
	}
	key, err := edKey(f, r.AdminKeyFile)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	signed, err := journal.SignTransition(b, key)
	if err != nil {
		return nil, ErrInvalid
	}
	record, err := p.candidate("transition")
	if err != nil {
		return nil, err
	}
	record.Transition = &signed
	if err = p.validateCandidate(record); err != nil {
		return nil, err
	}
	raw, err := journal.EncodeRecord(record)
	if err != nil {
		return nil, ErrInvalid
	}
	transition, err := encode(signed, journal.MaxRecordBytes)
	if err != nil {
		return nil, err
	}
	return artifacts{"record.json": raw, "transition.json": transition}, nil
}
func snapshot(f files, r SnapshotRequest) (artifacts, error) {
	p, err := replay(f, r.Chain)
	if err != nil {
		return nil, err
	}
	var header e2e2.Header
	var plain e2e2.Plaintext
	if decodeFile(f, r.HeaderFile, &header, 64<<10) != nil || decodeFile(f, r.PlaintextFile, &plain, e2e2.MaxPlaintextBytes) != nil {
		return nil, ErrInvalid
	}
	next, err := nextCounter(p.state.Snapshot.Sequence)
	if err != nil || header.Scope != p.state.Scope || header.Sequence != next || header.PreviousHash != p.state.Snapshot.EnvelopeHash {
		return nil, ErrAuthority
	}
	pub, err := publicFile(f, r.PublisherPublicFile, "publisher")
	if err != nil || pub.KeyID != header.PublisherKeyID {
		return nil, ErrAuthority
	}
	if role, known := p.state.KeyRoles[pub.KeyID]; known && role != "publisher" {
		return nil, ErrAuthority
	}
	currentPub := false
	for _, k := range p.state.Authority.PublisherKeys {
		if k == pub.journalKey() {
			currentPub = true
		}
	}
	current := currentPub && header.ReadKeyEpoch == p.state.Authority.ReadKeyEpoch && header.PublisherPolicyEpoch == p.state.Authority.PublisherPolicyEpoch && header.Action != "restore" && header.Action != "rotate-read-key"
	if r.Pending == current {
		return nil, ErrAuthority
	}
	if r.Pending {
		nextRead, _ := nextCounter(p.state.Authority.ReadKeyEpoch)
		nextPolicy, _ := nextCounter(p.state.Authority.PublisherPolicyEpoch)
		if header.ReadKeyEpoch != p.state.Authority.ReadKeyEpoch && header.ReadKeyEpoch != nextRead {
			return nil, ErrAuthority
		}
		if header.PublisherPolicyEpoch != p.state.Authority.PublisherPolicyEpoch && header.PublisherPolicyEpoch != nextPolicy {
			return nil, ErrAuthority
		}
		if !currentPub && header.PublisherPolicyEpoch != nextPolicy {
			return nil, ErrAuthority
		}
		switch header.Action {
		case "rotate-read-key":
			if header.ReadKeyEpoch != nextRead || header.PublisherPolicyEpoch != p.state.Authority.PublisherPolicyEpoch || !currentPub {
				return nil, ErrAuthority
			}
		case "update":
			if header.PublisherPolicyEpoch != nextPolicy || header.ReadKeyEpoch != p.state.Authority.ReadKeyEpoch {
				return nil, ErrAuthority
			}
		case "restore":
			known := false
			for _, hash := range p.state.History {
				if header.RestoredFrom != nil && *header.RestoredFrom == hash && hash != e2e2.ZeroHash {
					known = true
				}
			}
			if !known {
				return nil, ErrAuthority
			}
		default:
			return nil, ErrAuthority
		}
	}
	key, err := edKey(f, r.PublisherKeyFile)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if e2e2.KeyID(key.Public().(ed25519.PublicKey)) != pub.KeyID {
		return nil, ErrAuthority
	}
	readKey, err := f.ReadFile(r.ReadKeyFile, 32)
	if err != nil || len(readKey) != 32 {
		return nil, ErrInvalid
	}
	defer clear(readKey)
	envelope, err := e2e2.SealSnapshot(header, plain, readKey, key)
	if err != nil {
		return nil, ErrInvalid
	}
	hash, err := e2e2.EnvelopeHash(envelope)
	if err != nil {
		return nil, ErrInvalid
	}
	public, _ := e2e2.DecodeBase64(pub.PublicKey, 32)
	verified, err := e2e2.VerifyEnvelope(envelope, e2e2.Expected{Scope: p.state.Scope, Sequence: next, EnvelopeHash: hash, ReadKeyEpoch: header.ReadKeyEpoch, PublisherPolicyEpoch: header.PublisherPolicyEpoch, PublisherKeys: map[string]ed25519.PublicKey{pub.KeyID: public}})
	if err != nil {
		return nil, ErrInvalid
	}
	decoded, err := verified.Decrypt(readKey)
	if err != nil {
		return nil, ErrInvalid
	}
	want, err := encode(plain, e2e2.MaxPlaintextBytes)
	if err != nil {
		return nil, err
	}
	defer clear(want)
	got, err := encode(decoded, e2e2.MaxPlaintextBytes)
	if err != nil {
		return nil, err
	}
	defer clear(got)
	if !bytes.Equal(want, got) {
		return nil, ErrInvalid
	}
	node, err := publicFile(f, r.RecipientPublicFile, "node")
	if err != nil {
		return nil, err
	}
	nodeBytes, _ := e2e2.DecodeBase64(node.PublicKey, 65)
	recipient, err := ecdh.P256().NewPublicKey(nodeBytes)
	if err != nil {
		return nil, ErrInvalid
	}
	wrapContext := e2e2.WrapContext{Protocol: "e2e2-reader-key-v1", Scope: p.state.Scope, ReadKeyEpoch: header.ReadKeyEpoch, PublisherPolicyEpoch: header.PublisherPolicyEpoch, PublisherKeyID: pub.KeyID, RecipientFingerprint: node.KeyID}
	wrap, err := e2e2.WrapReader(wrapContext, readKey, recipient, key)
	if err != nil {
		return nil, ErrInvalid
	}
	var wrapped e2e2.ReaderWrap
	if e2e2.DecodeStrict(wrap, &wrapped, e2e2.MaxReaderWrapBytes) != nil || e2e2.ValidateReaderWrap(wrapped) != nil || wrapped.Body.Context != wrapContext {
		return nil, ErrInvalid
	}
	body, err := encode(wrapped.Body, e2e2.MaxReaderWrapBytes)
	if err != nil {
		return nil, err
	}
	signature, _ := e2e2.DecodeBase64(wrapped.Signature, 64)
	if !ed25519.Verify(public, append(e2e2.Domain("sekvyr-e2e2/reader-wrap-sign/v1"), body...), signature) {
		return nil, ErrInvalid
	}
	status, err := encode(struct {
		Pending   bool `json:"pending"`
		Committed bool `json:"committed"`
	}{Pending: r.Pending, Committed: false}, 1024)
	if err != nil {
		return nil, err
	}
	artifacts := artifacts{"envelope.json": envelope, "reader-wrap.json": wrap, "candidate.json": status}
	if !r.Pending {
		var wire e2e2.Envelope
		if json.Unmarshal(envelope, &wire) != nil {
			return nil, ErrInvalid
		}
		record, err := p.candidate("snapshot")
		if err != nil {
			return nil, err
		}
		record.Envelope = &wire
		if err = p.validateCandidate(record); err != nil {
			return nil, err
		}
		raw, err := journal.EncodeRecord(record)
		if err != nil {
			return nil, ErrInvalid
		}
		artifacts["record.json"] = raw
	}
	return artifacts, nil
}
