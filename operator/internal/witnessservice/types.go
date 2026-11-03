// Package witnessservice implements the explicit development filesystem witness.
// The filesystem profile is not WORM and is never production-ready by itself.
package witnessservice

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/panelauth"
)

const genesisDomain = "sekvyr-e2e2/witness-genesis/v1"
const genesisHashDomain = "sekvyr-e2e2/witness-genesis-hash/v1"
const DevelopmentProfile = "development-filesystem-not-worm"

type Error struct{ Reason string }

func (e *Error) Error() string { return "witness service: " + e.Reason }
func fail(reason string) error { return &Error{Reason: reason} }

type PublicKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}
type GenesisBody struct {
	Format string `json:"format"`
	e2e2.Scope
	PanelOrigin          string      `json:"panel_origin"`
	WitnessEpoch         string      `json:"witness_epoch"`
	WitnessPublicKey     string      `json:"witness_public_key"`
	WitnessKeyID         string      `json:"witness_key_id"`
	PublisherPolicyEpoch string      `json:"publisher_policy_epoch"`
	PublisherKeys        []PublicKey `json:"publisher_keys"`
	ReadKeyEpoch         string      `json:"read_key_epoch"`
	AdminKeyID           string      `json:"admin_key_id"`
}
type Genesis struct {
	Body      GenesisBody `json:"body"`
	Signature string      `json:"signature"`
}
type Checkpoint struct {
	Sequence     string `json:"sequence"`
	EnvelopeHash string `json:"envelope_hash"`
}

// Registration belongs to independent, read-only administrator configuration.
// Secret material belongs only in the token file, never in this JSON or journal.
type Registration struct {
	LogID             string     `json:"log_id"`
	GenesisHash       string     `json:"genesis_hash"`
	AdminPublicKey    string     `json:"admin_public_key"`
	MinimumCheckpoint Checkpoint `json:"minimum_checkpoint"`
	StagingTokenFile  string     `json:"staging_token_file"`
	PanelCAFile       string     `json:"panel_ca_file"`
}
type Config struct {
	Format        string         `json:"format"`
	Registrations []Registration `json:"registrations"`
}
type StagedFetcher interface {
	Fetch(context.Context, e2e2.Scope, string) ([]byte, error)
}
type FetcherFactory func(GenesisBody, Registration) (StagedFetcher, error)

type HeadRequest struct {
	RequestNonce  string `json:"request_nonce"`
	FloorSequence string `json:"floor_sequence"`
	FloorHash     string `json:"floor_hash"`
}
type Expected struct {
	WitnessEpoch         string `json:"witness_epoch"`
	Sequence             string `json:"sequence"`
	EnvelopeHash         string `json:"envelope_hash"`
	PublisherPolicyEpoch string `json:"publisher_policy_epoch"`
}
type CommitRequest struct {
	EnvelopeHash string   `json:"envelope_hash"`
	Expected     Expected `json:"expected"`
}
type CommitResponse struct {
	Sequence     string `json:"sequence"`
	EnvelopeHash string `json:"envelope_hash"`
}
type commitRecord struct {
	Format   string        `json:"format"`
	Envelope e2e2.Envelope `json:"envelope"`
}

func canonical(value any, max int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fail("EncodingInvalid")
	}
	out, err := e2e2.Canonical(raw, max)
	if err != nil {
		return nil, fail("EncodingInvalid")
	}
	return out, nil
}
func hashGenesis(genesis Genesis) (string, error) {
	raw, err := canonical(genesis, 64<<10)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(e2e2.Domain(genesisHashDomain), raw...))
	return hex.EncodeToString(sum[:]), nil
}
func validHash(hash string, zero bool) bool {
	if len(hash) != 64 || (!zero && hash == e2e2.ZeroHash) {
		return false
	}
	for _, c := range []byte(hash) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validCheckpoint(point Checkpoint) bool {
	seq, err := e2e2.Counter(point.Sequence, true)
	return err == nil && validHash(point.EnvelopeHash, true) && (seq == 0) == (point.EnvelopeHash == e2e2.ZeroHash)
}
func validLog(log string) bool {
	return e2e2.ValidScope(e2e2.Scope{RealmID: log, ProjectID: log, EnvironmentID: log, ViewID: log, LogID: log})
}
func DecodeConfig(raw []byte) (Config, error) {
	var cfg Config
	if e2e2.DecodeStrict(raw, &cfg, 64<<10) != nil || cfg.Format != "sekvyr-witness-config-v1" || len(cfg.Registrations) == 0 || len(cfg.Registrations) > 64 {
		return Config{}, fail("ConfigInvalid")
	}
	seen := map[string]bool{}
	for _, reg := range cfg.Registrations {
		pub, err := e2e2.DecodeBase64(reg.AdminPublicKey, 32)
		if !validLog(reg.LogID) || seen[reg.LogID] || !validHash(reg.GenesisHash, false) || !validCheckpoint(reg.MinimumCheckpoint) || err != nil || !e2e2.ValidEd25519PublicKey(pub) || reg.StagingTokenFile == "" {
			return Config{}, fail("ConfigInvalid")
		}
		seen[reg.LogID] = true
	}
	return cfg, nil
}
func verifyGenesis(raw []byte, admin ed25519.PublicKey) (Genesis, string, error) {
	var g Genesis
	if e2e2.DecodeStrict(raw, &g, 64<<10) != nil || !e2e2.ValidEd25519PublicKey(admin) {
		return Genesis{}, "", fail("GenesisInvalid")
	}
	b := g.Body
	if b.Format != "sekvyr-witness-genesis-v1" || !e2e2.ValidScope(b.Scope) || b.AdminKeyID != e2e2.KeyID(admin) || len(b.PublisherKeys) == 0 || len(b.PublisherKeys) > 16 {
		return Genesis{}, "", fail("GenesisInvalid")
	}
	origin, err := panelauth.CanonicalOrigin(b.PanelOrigin)
	if err != nil || origin != b.PanelOrigin {
		return Genesis{}, "", fail("GenesisInvalid")
	}
	for _, counter := range []string{b.WitnessEpoch, b.PublisherPolicyEpoch, b.ReadKeyEpoch} {
		if _, err := e2e2.Counter(counter, false); err != nil {
			return Genesis{}, "", fail("GenesisInvalid")
		}
	}
	witness, err := e2e2.DecodeBase64(b.WitnessPublicKey, 32)
	if err != nil || !e2e2.ValidEd25519PublicKey(witness) || e2e2.KeyID(witness) != b.WitnessKeyID {
		return Genesis{}, "", fail("GenesisInvalid")
	}
	seen := map[string]bool{}
	for _, key := range b.PublisherKeys {
		public, err := e2e2.DecodeBase64(key.PublicKey, 32)
		if err != nil || !e2e2.ValidEd25519PublicKey(public) || e2e2.KeyID(public) != key.KeyID || seen[key.KeyID] {
			return Genesis{}, "", fail("GenesisInvalid")
		}
		seen[key.KeyID] = true
	}
	body, err := canonical(b, 64<<10)
	if err != nil {
		return Genesis{}, "", fail("GenesisInvalid")
	}
	signature, err := e2e2.DecodeBase64(g.Signature, 64)
	if err != nil || !ed25519.Verify(admin, append(e2e2.Domain(genesisDomain), body...), signature) {
		return Genesis{}, "", fail("GenesisInvalid")
	}
	hash, err := hashGenesis(g)
	return g, hash, err
}
