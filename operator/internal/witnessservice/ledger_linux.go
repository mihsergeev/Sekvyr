//go:build linux

package witnessservice

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
)

const maxRecords = 4096
const maxReplayBytes = 512 << 20

type logState struct {
	genesis GenesisBody
	head    witness.Head
	history map[string]string
	keys    map[string]ed25519.PublicKey
}

func recordName(sequence uint64) string { return fmt.Sprintf("%020d.json", sequence) }

// Initialize is an OFFLINE administrator action. Runtime never calls it. A
// partial initialization or existing directory is refused, never overwritten.
func Initialize(root string, raw []byte, admin ed25519.PublicKey) (string, error) {
	g, hash, err := verifyGenesis(raw, admin)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(root) {
		return "", fail("LedgerPathInvalid")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fail("LedgerUnavailable")
	}
	path := filepath.Join(root, g.Body.LogID)
	if os.Mkdir(path, 0700) != nil {
		return "", fail("InitializationDenied")
	}
	dir, err := os.Open(path)
	if err != nil {
		return "", fail("LedgerUnavailable")
	}
	defer dir.Close()
	lock, err := os.OpenFile(filepath.Join(path, "lock"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", fail("LedgerUnavailable")
	}
	err = lock.Sync()
	lock.Close()
	if err != nil {
		return "", fail("LedgerDurabilityFailed")
	}
	canonical, err := canonical(g, 64<<10)
	if err != nil {
		return "", err
	}
	if err = appendRecord(path, 0, canonical); err != nil {
		return "", err
	}
	parent, err := os.Open(root)
	if err != nil {
		return "", fail("LedgerUnavailable")
	}
	defer parent.Close()
	if parent.Sync() != nil {
		return "", fail("LedgerDurabilityFailed")
	}
	return hash, nil
}

func appendRecord(path string, sequence uint64, raw []byte) error {
	f, err := os.OpenFile(filepath.Join(path, recordName(sequence)), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fail("LedgerAppendFailed")
	}
	n, writeErr := f.Write(raw)
	if writeErr != nil || n != len(raw) {
		f.Close()
		return fail("LedgerAppendFailed")
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return fail("LedgerDurabilityFailed")
	}
	if f.Close() != nil {
		return fail("LedgerDurabilityFailed")
	}
	dir, err := os.Open(path)
	if err != nil {
		return fail("LedgerUnavailable")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return fail("LedgerDurabilityFailed")
	}
	return nil
}

func withLog(ctx context.Context, root string, reg Registration, fn func(string, *logState) error) error {
	if ctx == nil || ctx.Err() != nil {
		return fail("Cancelled")
	}
	path := filepath.Join(root, reg.LogID)
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fail("LedgerUnavailable")
	}
	lock, err := os.OpenFile(filepath.Join(path, "lock"), os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail("LedgerUnavailable")
	}
	defer lock.Close()
	if st, e := lock.Stat(); e != nil || !st.Mode().IsRegular() {
		return fail("LedgerUnavailable")
	}
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return fail("LedgerUnavailable")
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fail("Cancelled")
		case <-timer.C:
		}
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	state, err := replay(ctx, path, reg)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return fail("Cancelled")
	}
	return fn(path, state)
}

func replay(ctx context.Context, path string, reg Registration) (*logState, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fail("LedgerUnavailable")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() == "lock" {
			continue
		}
		if !entry.Type().IsRegular() {
			return nil, fail("LedgerCorrupt")
		}
		names = append(names, entry.Name())
	}
	if len(names) == 0 || len(names) > maxRecords {
		return nil, fail("LedgerCapacityOrCorruption")
	}
	sort.Strings(names)
	admin, err := e2e2.DecodeBase64(reg.AdminPublicKey, 32)
	if err != nil {
		return nil, fail("ConfigInvalid")
	}
	state := &logState{history: map[string]string{}, keys: map[string]ed25519.PublicKey{}}
	var total int64
	for index, name := range names {
		if ctx.Err() != nil {
			return nil, fail("Cancelled")
		}
		if name != recordName(uint64(index)) {
			return nil, fail("LedgerGap")
		}
		f, err := os.OpenFile(filepath.Join(path, name), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, fail("LedgerCorrupt")
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > e2e2.MaxEnvelopeBytes+1024 {
			f.Close()
			return nil, fail("LedgerCorrupt")
		}
		total += info.Size()
		if total > maxReplayBytes {
			f.Close()
			return nil, fail("LedgerCapacityOrCorruption")
		}
		raw, readErr := io.ReadAll(io.LimitReader(f, e2e2.MaxEnvelopeBytes+1025))
		syncErr := f.Sync()
		f.Close()
		if readErr != nil || syncErr != nil || int64(len(raw)) != info.Size() {
			return nil, fail("LedgerCorrupt")
		}
		if index == 0 {
			g, hash, err := verifyGenesis(raw, admin)
			if err != nil || hash != reg.GenesisHash || g.Body.LogID != reg.LogID {
				return nil, fail("GenesisMismatch")
			}
			state.genesis = g.Body
			state.head = witness.Head{Scope: toWitness(g.Body.Scope), WitnessEpoch: g.Body.WitnessEpoch, Sequence: "0", EnvelopeHash: e2e2.ZeroHash, ReadKeyEpoch: "0", PublisherPolicyEpoch: "0"}
			state.history["0"] = e2e2.ZeroHash
			for _, key := range g.Body.PublisherKeys {
				pub, _ := e2e2.DecodeBase64(key.PublicKey, 32)
				state.keys[key.KeyID] = pub
			}
			continue
		}
		var record commitRecord
		if e2e2.DecodeStrict(raw, &record, e2e2.MaxEnvelopeBytes+1024) != nil || record.Format != "sekvyr-witness-commit-v1" {
			return nil, fail("LedgerCorrupt")
		}
		envelope, err := canonical(record.Envelope, e2e2.MaxEnvelopeBytes)
		if err != nil {
			return nil, fail("LedgerCorrupt")
		}
		head, err := verifyNext(envelope, state)
		if err != nil {
			return nil, fail("LedgerCorrupt")
		}
		if head.Sequence != strconv.Itoa(index) {
			return nil, fail("LedgerGap")
		}
		state.head = head
		state.history[head.Sequence] = head.EnvelopeHash
	}
	min, err := e2e2.Counter(reg.MinimumCheckpoint.Sequence, true)
	seq, _ := e2e2.Counter(state.head.Sequence, true)
	if err != nil || seq < min || state.history[reg.MinimumCheckpoint.Sequence] != reg.MinimumCheckpoint.EnvelopeHash {
		return nil, fail("LedgerBelowIndependentCheckpoint")
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil, fail("LedgerUnavailable")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return nil, fail("LedgerDurabilityFailed")
	}
	return state, nil
}

func verifyNext(raw []byte, state *logState) (witness.Head, error) {
	seq, err := e2e2.Counter(state.head.Sequence, true)
	if err != nil || seq == ^uint64(0) {
		return witness.Head{}, fail("SequenceExhausted")
	}
	next := strconv.FormatUint(seq+1, 10)
	hash, err := e2e2.EnvelopeHash(raw)
	if err != nil {
		return witness.Head{}, fail("EnvelopeInvalid")
	}
	verified, err := e2e2.VerifyEnvelope(raw, e2e2.Expected{Scope: state.genesis.Scope, Sequence: next, EnvelopeHash: hash, ReadKeyEpoch: state.genesis.ReadKeyEpoch, PublisherPolicyEpoch: state.genesis.PublisherPolicyEpoch, PublisherKeys: state.keys})
	if err != nil {
		return witness.Head{}, fail("EnvelopeInvalid")
	}
	header := verified.Header()
	if header.PreviousHash != state.head.EnvelopeHash {
		return witness.Head{}, fail("EnvelopeFork")
	}
	if header.Action != "initial" && header.Action != "migrate" && header.Action != "update" {
		return witness.Head{}, fail("AuthorityTransitionNotSupported")
	}
	return witness.Head{Scope: state.head.Scope, WitnessEpoch: state.genesis.WitnessEpoch, Sequence: next, EnvelopeHash: hash, ReadKeyEpoch: header.ReadKeyEpoch, PublisherPolicyEpoch: header.PublisherPolicyEpoch}, nil
}
func toWitness(s e2e2.Scope) witness.Scope {
	return witness.Scope{RealmID: s.RealmID, ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID, ViewID: s.ViewID, LogID: s.LogID}
}
