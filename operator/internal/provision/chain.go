package provision

import (
	"strconv"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
)

type replayed struct {
	registration journal.Registration
	records      []journal.Record
	state        journal.CurrentState
}

func replay(f files, c ChainFiles) (replayed, error) {
	var out replayed
	if decodeFile(f, c.RegistrationFile, &out.registration, 16<<10) != nil || decodeFile(f, c.RecordsFile, &out.records, MaxInputBytes) != nil {
		return out, ErrInvalid
	}
	if len(out.records) < 1 || len(out.records) > journal.MaxRecords {
		return out, ErrInvalid
	}
	slots := make([]journal.StoredSlot, len(out.records))
	total := 0
	for i, r := range out.records {
		b, err := journal.EncodeRecord(r)
		if err != nil || len(b) > journal.MaxReplayBytes-total {
			return out, ErrInvalid
		}
		total += len(b)
		slots[i].Raw = b
	}
	state, err := journal.Replay(out.registration, slots)
	if err != nil {
		return out, ErrAuthority
	}
	// Replay validates the cryptographic prefix, not its separately pinned floor.
	n, err := e2e2.Counter(out.registration.MinimumCursor.JournalSequence, true)
	if err != nil || n >= uint64(len(out.records)) {
		return out, ErrAuthority
	}
	hash, err := journal.RecordHash(out.records[n])
	if err != nil || hash != out.registration.MinimumCursor.RecordHash || state.Cursor != c.ExpectedCursor {
		return out, ErrAuthority
	}
	out.state = state
	return out, nil
}
func nextCounter(s string) (string, error) {
	n, e := e2e2.Counter(s, true)
	if e != nil || n == ^uint64(0) {
		return "", ErrInvalid
	}
	return strconv.FormatUint(n+1, 10), nil
}
func (p replayed) candidate(kind string) (journal.Record, error) {
	n, err := nextCounter(p.state.Cursor.JournalSequence)
	if err != nil {
		return journal.Record{}, err
	}
	return journal.Record{Format: "sekvyr-journal-record-v1", LogID: p.state.Scope.LogID, JournalSequence: n, PreviousRecordHash: p.state.Cursor.RecordHash, Kind: kind}, nil
}
func (p replayed) validateCandidate(record journal.Record) error {
	if len(p.records) >= journal.MaxRecords {
		return ErrInvalid
	}
	slots := make([]journal.StoredSlot, 0, len(p.records)+1)
	for _, r := range append(append([]journal.Record{}, p.records...), record) {
		b, e := journal.EncodeRecord(r)
		if e != nil {
			return ErrInvalid
		}
		slots = append(slots, journal.StoredSlot{Raw: b})
	}
	if _, err := journal.Replay(p.registration, slots); err != nil {
		return ErrAuthority
	}
	return nil
}
