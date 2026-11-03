// Package recovery verifies explicit independently signed checkpoint recovery.
// It never learns keys from a manifest or treats missing state as a new install.
package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
)

const Domain = "sekvyr-e2e2/checkpoint-recovery/v1"
const Limit = 64 << 10

type Error struct{ Reason string }

func (e *Error) Error() string   { return "checkpoint recovery: " + e.Reason }
func reject(reason string) error { return &Error{Reason: reason} }

type Binding struct {
	StoreName       string `json:"store_name"`
	StoreUID        string `json:"store_uid"`
	CRName          string `json:"cr_name"`
	CRUID           string `json:"cr_uid"`
	BindingID       string `json:"binding_id"`
	ViewID          string `json:"view_id"`
	TargetName      string `json:"target_name"`
	TargetUID       string `json:"target_uid"`
	CRGeneration    int64  `json:"cr_generation"`
	StoreGeneration int64  `json:"store_generation"`
	Identity        string `json:"identity"`
}
type Body struct {
	Format                      string           `json:"format"`
	Operation                   string           `json:"operation"`
	RecoveryID                  string           `json:"recovery_id"`
	InstallationID              string           `json:"installation_id"`
	PreviousBootstrapGeneration int64            `json:"previous_bootstrap_generation"`
	PreviousStateSecretUID      string           `json:"previous_state_secret_uid"`
	BootstrapGeneration         int64            `json:"bootstrap_generation"`
	StateSecretName             string           `json:"state_secret_name"`
	StateSecretUID              string           `json:"state_secret_uid"`
	IdentityKeySecretUID        string           `json:"identity_key_secret_uid"`
	TrustBundleSecretUID        string           `json:"trust_bundle_secret_uid"`
	NodeFingerprint             string           `json:"node_fingerprint"`
	Scope                       e2e2.Scope       `json:"scope"`
	GenesisHash                 string           `json:"genesis_hash"`
	Cursor                      journal.Cursor   `json:"cursor"`
	Snapshot                    journal.Snapshot `json:"snapshot"`
	Binding                     Binding          `json:"binding"`
	ExpiresAt                   string           `json:"expires_at"`
	ExpectedStateSHA256         string           `json:"expected_state_sha256"`
	AllowRollout                bool             `json:"allow_rollout"`
}
type Plan struct {
	Body      Body   `json:"body"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// Sign is for an offline administrative tool. The private key is never learned
// from the panel, witness, target or recovery manifest.
func Sign(body Body, private ed25519.PrivateKey) (Plan, error) {
	if len(private) != ed25519.PrivateKeySize || !ed25519.NewKeyFromSeed(private[:32]).Equal(private) {
		return Plan{}, reject("RecoverySigningKeyInvalid")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return Plan{}, reject("PlanInvalid")
	}
	canonical, err := e2e2.Canonical(raw, Limit)
	if err != nil {
		return Plan{}, reject("PlanInvalid")
	}
	return Plan{Body: body, KeyID: e2e2.KeyID(private.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append(e2e2.Domain(Domain), canonical...)))}, nil
}

type Accepted struct {
	body Body
	head witness.Head
	hash string
}

func (Accepted) String() string        { return "verified checkpoint recovery [redacted]" }
func (Accepted) GoString() string      { return "verified checkpoint recovery [redacted]" }
func (a *Accepted) Body() Body         { return a.body }
func (a *Accepted) Head() witness.Head { return a.head }
func (a *Accepted) Hash() string       { return a.hash }

// Verify requires an already replay-verified ONLINE journal state. The manifest
// deliberately binds the exact cursor: concurrent commits require a new reviewed
// plan rather than silently rebasing recovery onto another authority/snapshot.
func Verify(ctx context.Context, raw []byte, cfg installation.Config, current journal.CurrentState, now time.Time) (*Accepted, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, reject("Cancelled")
	}
	if cfg.Validate() != nil || cfg.HA == nil {
		return nil, reject("RecoveryProfileInvalid")
	}
	var plan Plan
	if e2e2.DecodeStrict(raw, &plan, Limit) != nil {
		return nil, reject("PlanInvalid")
	}
	b := plan.Body
	if b.Format != "sekvyr-checkpoint-recovery-v1" || !installation.ValidUUID(b.RecoveryID) || b.InstallationID != cfg.InstallationID || b.PreviousBootstrapGeneration < 0 || b.BootstrapGeneration <= b.PreviousBootstrapGeneration || b.BootstrapGeneration != cfg.BootstrapGeneration {
		return nil, reject("RecoveryIdentityMismatch")
	}
	if b.StateSecretName != cfg.StateSecret.Name || b.StateSecretUID != cfg.StateSecret.UID || b.IdentityKeySecretUID != cfg.IdentityKeySecret.UID || b.TrustBundleSecretUID != cfg.TrustBundleSecret.UID || !installation.ValidUUID(b.StateSecretUID) || !installation.ValidUUID(b.IdentityKeySecretUID) || !installation.ValidUUID(b.TrustBundleSecretUID) {
		return nil, reject("RecoveryIdentityMismatch")
	}
	if !digest(b.ExpectedStateSHA256) || !digest(b.Binding.Identity) || b.Binding.CRGeneration < 1 || b.Binding.StoreGeneration < 1 || b.NodeFingerprint == "" {
		return nil, reject("RecoveryIdentityMismatch")
	}
	switch b.Operation {
	case "initialize":
		empty := sha256.Sum256(nil)
		if b.PreviousBootstrapGeneration != 0 || b.BootstrapGeneration != 1 || b.PreviousStateSecretUID != "" || b.ExpectedStateSHA256 != hex.EncodeToString(empty[:]) {
			return nil, reject("RecoveryIdentityMismatch")
		}
	case "recover":
		if b.PreviousBootstrapGeneration < 1 || !installation.ValidUUID(b.PreviousStateSecretUID) || b.PreviousStateSecretUID == b.StateSecretUID {
			return nil, reject("RecoveryIdentityMismatch")
		}
	default:
		return nil, reject("RecoveryIdentityMismatch")
	}
	if b.Scope != current.Scope || current.Scope.LogID != cfg.HA.Journal.LogID || current.GenesisHash != cfg.HA.Journal.GenesisHash || b.GenesisHash != current.GenesisHash || b.Cursor != current.Cursor || b.Snapshot != current.Snapshot || b.Binding.ViewID != current.Scope.ViewID || current.Snapshot.Sequence == "0" || current.Snapshot.EnvelopeHash == e2e2.ZeroHash {
		return nil, reject("RecoveryCheckpointMismatch")
	}
	expires, err := time.Parse(time.RFC3339, b.ExpiresAt)
	if err != nil || !now.Before(expires) || expires.Sub(now) > 24*time.Hour {
		return nil, reject("RecoveryExpired")
	}
	enrollment, ok := current.Enrollments[cfg.InstallationID]
	if !ok || enrollment.BootstrapGeneration != b.BootstrapGeneration || enrollment.Namespace != cfg.Namespace || enrollment.OperatorServiceAccount != cfg.ServiceAccount || enrollment.NodeFingerprint != b.NodeFingerprint || enrollment.IdentityKeySecretUID != b.IdentityKeySecretUID || enrollment.TrustBundleSecretUID != b.TrustBundleSecretUID {
		return nil, reject("RecoveryEnrollmentMismatch")
	}
	if !hasSecret(enrollment.AllowedObjects, cfg.Namespace, b.StateSecretName, b.StateSecretUID) || !hasSecret(enrollment.AllowedObjects, cfg.Namespace, b.Binding.TargetName, b.Binding.TargetUID) || b.Binding.TargetName == b.StateSecretName {
		return nil, reject("RecoveryOwnershipMismatch")
	}
	for _, id := range []string{b.Binding.StoreUID, b.Binding.CRUID, b.Binding.BindingID, b.Binding.TargetUID} {
		if !installation.ValidUUID(id) {
			return nil, reject("RecoveryOwnershipMismatch")
		}
	}
	for _, name := range []string{b.Binding.StoreName, b.Binding.CRName, b.Binding.TargetName} {
		if !installation.ValidName(name) {
			return nil, reject("RecoveryOwnershipMismatch")
		}
	}
	public, err := e2e2.DecodeBase64(current.Authority.AdminKey.PublicKey, ed25519.PublicKeySize)
	if err != nil || !e2e2.ValidEd25519PublicKey(public) || plan.KeyID != current.Authority.AdminKey.KeyID || e2e2.KeyID(public) != plan.KeyID {
		return nil, reject("RecoveryAuthorityInvalid")
	}
	body, err := json.Marshal(b)
	if err != nil {
		return nil, reject("PlanInvalid")
	}
	canonical, err := e2e2.Canonical(body, Limit)
	if err != nil {
		return nil, reject("PlanInvalid")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(plan.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(public, append(e2e2.Domain(Domain), canonical...), signature) {
		return nil, reject("RecoverySignatureInvalid")
	}
	canonicalPlan, err := e2e2.Canonical(raw, Limit)
	if err != nil {
		return nil, reject("PlanInvalid")
	}
	hash := sha256.Sum256(canonicalPlan)
	return &Accepted{body: b, head: current.Head(), hash: hex.EncodeToString(hash[:])}, nil
}
func digest(raw string) bool {
	b, err := hex.DecodeString(raw)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == raw
}
func hasSecret(refs []journal.ObjectRef, namespace, name, uid string) bool {
	for _, ref := range refs {
		if ref.APIVersion == "v1" && ref.Kind == "Secret" && ref.Namespace == namespace && ref.Name == name && ref.UID == uid {
			return true
		}
	}
	return false
}
