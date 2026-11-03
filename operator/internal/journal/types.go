// Package journal implements the trial canonical, conditionally appended journal.
// Its storage gateway is independent of witness replicas; this profile does not
// assert production WORM independence or Byzantine signer tolerance.
package journal

import (
	"context"
	"errors"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
)

const Profile = "trial-canonical-journal-v1"
const ZeroHash = e2e2.ZeroHash
const MaxRecords = 4096
const MaxRecordBytes = e2e2.MaxEnvelopeBytes + (256 << 10)
const MaxReplayBytes = 512 << 20
const GenesisDomain = "sekvyr-e2e2/journal-genesis/v1"
const RecordHashDomain = "sekvyr-e2e2/journal-record-hash/v1"
const TransitionDomain = "sekvyr-e2e2/authority-transition/v1"
const AuthorityHashDomain = "sekvyr-e2e2/authority-state-hash/v1"
const FenceGrantDomain = "sekvyr-e2e2/fence-grant/v1"
const FenceGrantHashDomain = "sekvyr-e2e2/fence-grant-hash/v1"

type Error struct{ Reason string }

func (e *Error) Error() string    { return "canonical journal: " + e.Reason }
func Failure(reason string) error { return &Error{Reason: reason} }
func Reason(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return "JournalUnavailable"
}

type Key struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}
type Cursor struct {
	JournalSequence string `json:"journal_sequence"`
	RecordHash      string `json:"record_hash"`
}
type Snapshot struct {
	Sequence             string `json:"sequence"`
	EnvelopeHash         string `json:"envelope_hash"`
	ReadKeyEpoch         string `json:"read_key_epoch"`
	PublisherPolicyEpoch string `json:"publisher_policy_epoch"`
}
type Authority struct {
	Revision             string `json:"revision"`
	AdminKey             Key    `json:"admin_key"`
	PublisherPolicyEpoch string `json:"publisher_policy_epoch"`
	PublisherKeys        []Key  `json:"publisher_keys"`
	ReadKeyEpoch         string `json:"read_key_epoch"`
	WitnessEpoch         string `json:"witness_epoch"`
	WitnessKey           Key    `json:"witness_key"`
	FencerEpoch          string `json:"fencer_epoch"`
	FencerKeys           []Key  `json:"fencer_keys"`
}
type ObjectRef struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}
type Enrollment struct {
	InstallationID            string      `json:"installation_id"`
	BootstrapGeneration       int64       `json:"bootstrap_generation"`
	Namespace                 string      `json:"namespace"`
	NamespaceUID              string      `json:"namespace_uid"`
	OperatorServiceAccount    string      `json:"operator_service_account"`
	OperatorServiceAccountUID string      `json:"operator_service_account_uid"`
	FencerServiceAccount      string      `json:"fencer_service_account"`
	FencerServiceAccountUID   string      `json:"fencer_service_account_uid"`
	Lease                     ObjectRef   `json:"lease"`
	NodeFingerprint           string      `json:"node_fingerprint"`
	IdentityKeySecretUID      string      `json:"identity_key_secret_uid"`
	TrustBundleSecretUID      string      `json:"trust_bundle_secret_uid"`
	AllowedObjects            []ObjectRef `json:"allowed_objects"`
}
type FenceGrant struct {
	Format              string      `json:"format"`
	Scope               e2e2.Scope  `json:"scope"`
	GenesisHash         string      `json:"genesis_hash"`
	InstallationID      string      `json:"installation_id"`
	BootstrapGeneration int64       `json:"bootstrap_generation"`
	OwnerPodUID         string      `json:"owner_pod_uid"`
	LeaseHolderIdentity string      `json:"lease_holder_identity"`
	Term                string      `json:"term"`
	PreviousGrantHash   string      `json:"previous_grant_hash"`
	AuthorityDigest     string      `json:"authority_digest"`
	Snapshot            Snapshot    `json:"snapshot"`
	Objects             []ObjectRef `json:"objects"`
}
type SignedFenceGrant struct {
	Body      FenceGrant `json:"body"`
	KeyID     string     `json:"key_id"`
	Signature string     `json:"signature"`
}
type FenceActivation struct {
	Format              string      `json:"format"`
	Scope               e2e2.Scope  `json:"scope"`
	GenesisHash         string      `json:"genesis_hash"`
	InstallationID      string      `json:"installation_id"`
	BootstrapGeneration int64       `json:"bootstrap_generation"`
	OwnerPodUID         string      `json:"owner_pod_uid"`
	LeaseHolderIdentity string      `json:"lease_holder_identity"`
	Term                string      `json:"term"`
	GrantHash           string      `json:"grant_hash"`
	AuthorityDigest     string      `json:"authority_digest"`
	Snapshot            Snapshot    `json:"snapshot"`
	Objects             []ObjectRef `json:"objects"`
}
type SignedFenceActivation struct {
	Body      FenceActivation `json:"body"`
	KeyID     string          `json:"key_id"`
	Signature string          `json:"signature"`
}
type RecoveryLink struct {
	LogID            string `json:"log_id"`
	GenesisHash      string `json:"genesis_hash"`
	MinimumCursor    Cursor `json:"minimum_cursor"`
	SnapshotSequence string `json:"snapshot_sequence"`
	EnvelopeHash     string `json:"envelope_hash"`
}
type GenesisBody struct {
	Format       string        `json:"format"`
	Scope        e2e2.Scope    `json:"scope"`
	PanelOrigin  string        `json:"panel_origin"`
	Authority    Authority     `json:"authority"`
	RecoveryFrom *RecoveryLink `json:"recovery_from"`
}
type SignedGenesis struct {
	Body      GenesisBody `json:"body"`
	KeyID     string      `json:"key_id"`
	Signature string      `json:"signature"`
}
type TransitionBody struct {
	Format                  string         `json:"format"`
	Scope                   e2e2.Scope     `json:"scope"`
	GenesisHash             string         `json:"genesis_hash"`
	Expected                Cursor         `json:"expected"`
	PreviousAuthorityDigest string         `json:"previous_authority_digest"`
	Kind                    string         `json:"kind"`
	Authority               Authority      `json:"authority"`
	Enrollment              *Enrollment    `json:"enrollment"`
	ActivatingEnvelope      *e2e2.Envelope `json:"activating_envelope"`
	RecoveryFrom            *RecoveryLink  `json:"recovery_from"`
}
type SignedTransition struct {
	Body      TransitionBody `json:"body"`
	KeyID     string         `json:"key_id"`
	Signature string         `json:"signature"`
}

// All payload fields are required on the wire; exactly one is non-null.
type Record struct {
	Format             string                 `json:"format"`
	LogID              string                 `json:"log_id"`
	JournalSequence    string                 `json:"journal_sequence"`
	PreviousRecordHash string                 `json:"previous_record_hash"`
	Kind               string                 `json:"kind"`
	Genesis            *SignedGenesis         `json:"genesis"`
	Envelope           *e2e2.Envelope         `json:"envelope"`
	Transition         *SignedTransition      `json:"transition"`
	FenceGrant         *SignedFenceGrant      `json:"fence_grant"`
	FenceActivation    *SignedFenceActivation `json:"fence_activation"`
}
type RetentionReceipt struct {
	VersionID   string `json:"version_id"`
	Mode        string `json:"mode"`
	RetainUntil string `json:"retain_until"`
}
type StoredSlot struct {
	Raw     []byte
	Receipt RetentionReceipt
}
type Registration struct {
	LogID          string `json:"log_id"`
	GenesisHash    string `json:"genesis_hash"`
	AdminPublicKey string `json:"admin_public_key"`
	MinimumCursor  Cursor `json:"minimum_cursor"`
}
type CurrentState struct {
	Scope           e2e2.Scope                       `json:"scope"`
	GenesisHash     string                           `json:"genesis_hash"`
	Cursor          Cursor                           `json:"cursor"`
	Snapshot        Snapshot                         `json:"snapshot"`
	Authority       Authority                        `json:"authority"`
	AuthorityDigest string                           `json:"authority_digest"`
	PanelOrigin     string                           `json:"panel_origin"`
	Enrollments     map[string]Enrollment            `json:"enrollments"`
	Grants          map[string]SignedFenceGrant      `json:"grants"`
	Activations     map[string]SignedFenceActivation `json:"activations"`
	History         map[string]string                `json:"history"`
	KeyRoles        map[string]string                `json:"key_roles"`
}

func (s CurrentState) Head() witness.Head {
	return witness.Head{Scope: witness.Scope{RealmID: s.Scope.RealmID, ProjectID: s.Scope.ProjectID, EnvironmentID: s.Scope.EnvironmentID, ViewID: s.Scope.ViewID, LogID: s.Scope.LogID}, WitnessEpoch: s.Authority.WitnessEpoch, Sequence: s.Snapshot.Sequence, EnvelopeHash: s.Snapshot.EnvelopeHash, ReadKeyEpoch: s.Snapshot.ReadKeyEpoch, PublisherPolicyEpoch: s.Snapshot.PublisherPolicyEpoch}
}
func (s CurrentState) CurrentGrant(installation string) (SignedFenceGrant, bool) {
	g, ok := s.Grants[installation]
	enrolled, present := s.Enrollments[installation]
	return g, ok && present && g.Body.AuthorityDigest == s.AuthorityDigest && g.Body.BootstrapGeneration == enrolled.BootstrapGeneration && g.Body.Snapshot == s.Snapshot
}
func (s CurrentState) ActiveGrant(installation string) (SignedFenceGrant, bool) {
	g, ok := s.CurrentGrant(installation)
	a, active := s.Activations[installation]
	hash, err := FenceGrantHash(g.Body)
	return g, ok && active && err == nil && a.Body.GrantHash == hash && a.Body.AuthorityDigest == s.AuthorityDigest && a.Body.Term == g.Body.Term && a.Body.OwnerPodUID == g.Body.OwnerPodUID && a.Body.LeaseHolderIdentity == g.Body.LeaseHolderIdentity
}

// Storage is a bounded full online version inventory, never a mutable head cache.
// ReadAll must reject extra versions, markers, gaps and invalid retention receipts.
// The sole commit decision is PutIfAbsent at the fixed canonical sequence slot.
type Storage interface {
	ReadAll(context.Context, string) ([]StoredSlot, error)
	PutIfAbsent(context.Context, string, uint64, []byte) (RetentionReceipt, error)
}
type Ledger struct {
	Storage       Storage
	Registrations map[string]Registration
	Now           func() time.Time
}

func (Ledger) String() string   { return "canonical journal [redacted]" }
func (Ledger) GoString() string { return "canonical journal [redacted]" }
