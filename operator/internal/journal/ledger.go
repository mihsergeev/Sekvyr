package journal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/url"
	"strconv"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

func New(storage Storage, registrations []Registration, now func() time.Time) (*Ledger, error) {
	if storage == nil || len(registrations) < 1 || len(registrations) > 64 {
		return nil, Failure("ConfigInvalid")
	}
	l := &Ledger{Storage: storage, Registrations: map[string]Registration{}, Now: now}
	for _, r := range registrations {
		pub, err := e2e2.DecodeBase64(r.AdminPublicKey, 32)
		if !validUUID(r.LogID) || !validHash(r.GenesisHash, false) || err != nil || !e2e2.ValidEd25519PublicKey(pub) || !validCursor(r.MinimumCursor) {
			return nil, Failure("ConfigInvalid")
		}
		if _, exists := l.Registrations[r.LogID]; exists {
			return nil, Failure("ConfigInvalid")
		}
		l.Registrations[r.LogID] = r
	}
	return l, nil
}
func (l *Ledger) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}
func (l *Ledger) registration(log string) (Registration, error) {
	if l == nil || l.Storage == nil {
		return Registration{}, Failure("JournalUnavailable")
	}
	r, ok := l.Registrations[log]
	if !ok {
		return r, Failure("LogUnknown")
	}
	return r, nil
}
func (l *Ledger) slots(ctx context.Context, log string) ([]StoredSlot, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, Failure("Cancelled")
	}
	slots, err := l.Storage.ReadAll(ctx, log)
	if err != nil {
		return nil, err
	}
	if len(slots) < 1 || len(slots) > MaxRecords {
		return nil, Failure("JournalMissingOrCapacity")
	}
	total := 0
	for _, slot := range slots {
		if len(slot.Raw) < 1 || len(slot.Raw) > MaxRecordBytes || len(slot.Raw) > MaxReplayBytes-total {
			return nil, Failure("JournalCapacity")
		}
		total += len(slot.Raw)
		until, err := time.Parse(time.RFC3339Nano, slot.Receipt.RetainUntil)
		if slot.Receipt.VersionID == "" || len(slot.Receipt.VersionID) > 1024 || slot.Receipt.Mode != "COMPLIANCE" || err != nil || !until.After(l.now()) {
			return nil, Failure("RetentionInvalid")
		}
	}
	return slots, nil
}
func (l *Ledger) ReadCurrent(ctx context.Context, log string, minimum Cursor) (CurrentState, error) {
	reg, err := l.registration(log)
	if err != nil {
		return CurrentState{}, err
	}
	slots, err := l.slots(ctx, log)
	if err != nil {
		return CurrentState{}, err
	}
	state, err := Replay(reg, slots)
	if err != nil {
		return CurrentState{}, err
	}
	floors := []Cursor{reg.MinimumCursor}
	if minimum != (Cursor{}) {
		if !validCursor(minimum) {
			return CurrentState{}, Failure("FloorInvalid")
		}
		floors = append(floors, minimum)
	}
	for _, floor := range floors {
		n, _ := e2e2.Counter(floor.JournalSequence, true)
		if n >= uint64(len(slots)) {
			return CurrentState{}, Failure("JournalBelowCheckpoint")
		}
		record, _ := DecodeRecord(slots[n].Raw)
		hash, _ := RecordHash(record)
		if hash != floor.RecordHash {
			return CurrentState{}, Failure("JournalCheckpointFork")
		}
	}
	return cloneState(state), nil
}
func Replay(reg Registration, slots []StoredSlot) (CurrentState, error) {
	var state CurrentState
	for index, slot := range slots {
		r, err := DecodeRecord(slot.Raw)
		if err != nil {
			return CurrentState{}, err
		}
		if r.Format != "sekvyr-journal-record-v1" || r.LogID != reg.LogID || r.JournalSequence != strconv.Itoa(index) {
			return CurrentState{}, Failure("JournalGap")
		}
		payloads := 0
		for _, present := range []bool{r.Genesis != nil, r.Envelope != nil, r.Transition != nil, r.FenceGrant != nil, r.FenceActivation != nil} {
			if present {
				payloads++
			}
		}
		if payloads != 1 {
			return CurrentState{}, Failure("RecordInvalid")
		}
		hash, err := RecordHash(r)
		if err != nil {
			return CurrentState{}, err
		}
		if index == 0 {
			if r.Kind != "genesis" || r.Genesis == nil || r.PreviousRecordHash != ZeroHash || hash != reg.GenesisHash {
				return CurrentState{}, Failure("GenesisMismatch")
			}
			state, err = genesisState(reg, *r.Genesis, hash)
			if err != nil {
				return CurrentState{}, err
			}
		} else {
			if r.PreviousRecordHash != state.Cursor.RecordHash {
				return CurrentState{}, Failure("JournalFork")
			}
			state, err = Apply(state, r)
			if err != nil {
				return CurrentState{}, err
			}
		}
		state.Cursor = Cursor{JournalSequence: r.JournalSequence, RecordHash: hash}
	}
	if len(slots) == 0 {
		return CurrentState{}, Failure("JournalMissing")
	}
	return state, nil
}
func genesisState(reg Registration, g SignedGenesis, hash string) (CurrentState, error) {
	pub, err := e2e2.DecodeBase64(reg.AdminPublicKey, 32)
	if err != nil {
		return CurrentState{}, Failure("GenesisInvalid")
	}
	key, err := KeyFromPublic(ed25519.PublicKey(pub))
	if err != nil {
		return CurrentState{}, err
	}
	b := g.Body
	u, urlErr := url.Parse(b.PanelOrigin)
	if b.Format != "sekvyr-journal-genesis-v1" || !e2e2.ValidScope(b.Scope) || b.Scope.LogID != reg.LogID || !validAuthority(b.Authority) || b.Authority.AdminKey != key || urlErr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return CurrentState{}, Failure("GenesisInvalid")
	}
	if verifyValue(GenesisDomain, b, g.KeyID, g.Signature, key, 128<<10) != nil {
		return CurrentState{}, Failure("GenesisInvalid")
	}
	if b.RecoveryFrom != nil && !validRecovery(*b.RecoveryFrom) {
		return CurrentState{}, Failure("RecoveryInvalid")
	}
	state := CurrentState{Scope: b.Scope, GenesisHash: hash, Cursor: Cursor{JournalSequence: "0", RecordHash: hash}, Snapshot: Snapshot{Sequence: "0", EnvelopeHash: ZeroHash, ReadKeyEpoch: "0", PublisherPolicyEpoch: "0"}, Authority: b.Authority, PanelOrigin: b.PanelOrigin, Enrollments: map[string]Enrollment{}, Grants: map[string]SignedFenceGrant{}, Activations: map[string]SignedFenceActivation{}, History: map[string]string{"0": ZeroHash}}
	state.KeyRoles, err = authorityRoles(state.Authority, nil)
	if err != nil {
		return CurrentState{}, err
	}
	state.AuthorityDigest, err = authorityDigest(state)
	return state, err
}
func NewGenesisRecord(g SignedGenesis) Record {
	return Record{Format: "sekvyr-journal-record-v1", LogID: g.Body.Scope.LogID, JournalSequence: "0", PreviousRecordHash: ZeroHash, Kind: "genesis", Genesis: &g}
}
func (l *Ledger) InitializeCAS(ctx context.Context, log string, raw []byte) (CurrentState, error) {
	reg, err := l.registration(log)
	if err != nil {
		return CurrentState{}, err
	}
	if reg.MinimumCursor != (Cursor{JournalSequence: "0", RecordHash: reg.GenesisHash}) {
		return CurrentState{}, Failure("InitializationFloorInvalid")
	}
	r, err := DecodeRecord(raw)
	if err != nil {
		return CurrentState{}, err
	}
	if _, err = Replay(reg, []StoredSlot{{Raw: raw}}); err != nil {
		return CurrentState{}, err
	}
	encoded, err := EncodeRecord(r)
	if err != nil {
		return CurrentState{}, err
	}
	if _, err = l.Storage.PutIfAbsent(ctx, log, 0, encoded); err != nil {
		if state, ok, _ := l.resolveExact(ctx, log, 0, encoded); ok {
			return state, nil
		}
		return CurrentState{}, err
	}
	return l.ReadCurrent(ctx, log, reg.MinimumCursor)
}
func (l *Ledger) append(ctx context.Context, log string, expected Cursor, record Record) (CurrentState, error) {
	if !validCursor(expected) {
		return CurrentState{}, Failure("FloorInvalid")
	}
	seq, err := nextCounter(expected.JournalSequence)
	if err != nil {
		return CurrentState{}, err
	}
	n, _ := e2e2.Counter(seq, false)
	if n >= MaxRecords {
		return CurrentState{}, Failure("JournalCapacity")
	}
	record.Format = "sekvyr-journal-record-v1"
	record.LogID = log
	record.JournalSequence = seq
	record.PreviousRecordHash = expected.RecordHash
	raw, err := EncodeRecord(record)
	if err != nil {
		return CurrentState{}, err
	}
	current, err := l.ReadCurrent(ctx, log, Cursor{})
	if err != nil {
		return CurrentState{}, err
	}
	if current.Cursor != expected {
		if state, ok, resolveErr := l.resolveExact(ctx, log, n, raw); ok {
			return state, nil
		} else if resolveErr != nil {
			return CurrentState{}, resolveErr
		}
		return CurrentState{}, Failure("CASConflict")
	}
	if _, err = Apply(current, record); err != nil {
		return CurrentState{}, err
	}
	if _, err = l.Storage.PutIfAbsent(ctx, log, n, raw); err != nil {
		if Reason(err) == "CASConflict" || Reason(err) == "StorageUnavailable" {
			if state, ok, resolveErr := l.resolveExact(ctx, log, n, raw); ok {
				return state, nil
			} else if resolveErr != nil {
				return CurrentState{}, resolveErr
			}
		}
		return CurrentState{}, err
	}
	hash, _ := RecordHash(record)
	return l.ReadCurrent(ctx, log, Cursor{JournalSequence: seq, RecordHash: hash})
}

// resolveExact acknowledges only the original canonical bytes in the original
// slot, after a complete online replay. It never rebases or creates another slot.
func (l *Ledger) resolveExact(ctx context.Context, log string, sequence uint64, raw []byte) (CurrentState, bool, error) {
	state, err := l.ReadCurrent(ctx, log, Cursor{})
	if err != nil {
		return CurrentState{}, false, err
	}
	slots, err := l.slots(ctx, log)
	if err != nil {
		return CurrentState{}, false, err
	}
	reg, _ := l.registration(log)
	if _, err = Replay(reg, slots); err != nil {
		return CurrentState{}, false, err
	}
	if sequence >= uint64(len(slots)) || !bytes.Equal(slots[sequence].Raw, raw) {
		return state, false, nil
	}
	record, err := DecodeRecord(raw)
	if err != nil {
		return CurrentState{}, false, err
	}
	hash, err := RecordHash(record)
	if err != nil {
		return CurrentState{}, false, err
	}
	latest, err := l.ReadCurrent(ctx, log, Cursor{JournalSequence: fmtCounter(sequence), RecordHash: hash})
	return latest, err == nil, err
}
func (l *Ledger) AppendSnapshotCAS(ctx context.Context, log string, expected Cursor, raw []byte) (CurrentState, error) {
	var env e2e2.Envelope
	if e2e2.DecodeStrict(raw, &env, e2e2.MaxEnvelopeBytes) != nil {
		return CurrentState{}, Failure("EnvelopeInvalid")
	}
	return l.append(ctx, log, expected, Record{Kind: "snapshot", Envelope: &env})
}
func (l *Ledger) AppendTransitionCAS(ctx context.Context, log string, expected Cursor, raw []byte) (CurrentState, error) {
	var t SignedTransition
	if DecodeStrict(raw, &t, MaxRecordBytes) != nil {
		return CurrentState{}, Failure("TransitionInvalid")
	}
	return l.append(ctx, log, expected, Record{Kind: "transition", Transition: &t})
}
func (l *Ledger) AppendFenceGrantCAS(ctx context.Context, log string, expected Cursor, raw []byte) (CurrentState, error) {
	var grant SignedFenceGrant
	if DecodeStrict(raw, &grant, 64<<10) != nil {
		return CurrentState{}, Failure("GrantInvalid")
	}
	s, err := l.ReadCurrent(ctx, log, Cursor{})
	if err != nil {
		return CurrentState{}, err
	}
	if s.Cursor == expected {
		if prior, ok := s.CurrentGrant(grant.Body.InstallationID); ok && same(prior, grant) {
			return s, nil
		}
	}
	return l.append(ctx, log, expected, Record{Kind: "fence-grant", FenceGrant: &grant})
}
func (l *Ledger) AppendFenceActivationCAS(ctx context.Context, log string, expected Cursor, raw []byte) (CurrentState, error) {
	var activation SignedFenceActivation
	if DecodeStrict(raw, &activation, 64<<10) != nil {
		return CurrentState{}, Failure("ActivationInvalid")
	}
	s, err := l.ReadCurrent(ctx, log, Cursor{})
	if err != nil {
		return CurrentState{}, err
	}
	if s.Cursor == expected {
		if prior, ok := s.Activations[activation.Body.InstallationID]; ok && same(prior, activation) {
			if _, active := s.ActiveGrant(activation.Body.InstallationID); active {
				return s, nil
			}
		}
	}
	return l.append(ctx, log, expected, Record{Kind: "fence-activation", FenceActivation: &activation})
}
func (l *Ledger) ReadRecord(ctx context.Context, log string, sequence string) ([]byte, error) {
	if _, err := l.ReadCurrent(ctx, log, Cursor{}); err != nil {
		return nil, err
	}
	n, err := e2e2.Counter(sequence, true)
	if err != nil {
		return nil, Failure("RecordUnknown")
	}
	slots, err := l.slots(ctx, log)
	if err != nil {
		return nil, err
	}
	reg, _ := l.registration(log)
	if _, err = Replay(reg, slots); err != nil {
		return nil, err
	}
	if n >= uint64(len(slots)) {
		return nil, Failure("RecordUnknown")
	}
	return append([]byte(nil), slots[n].Raw...), nil
}
func validRecovery(r RecoveryLink) bool {
	_, err := e2e2.Counter(r.SnapshotSequence, false)
	return validUUID(r.LogID) && validHash(r.GenesisHash, false) && validCursor(r.MinimumCursor) && err == nil && validHash(r.EnvelopeHash, false)
}
