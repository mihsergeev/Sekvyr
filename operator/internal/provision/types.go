// Package provision prepares reviewed offline artifacts. It has no network,
// Kubernetes, Helm, storage commit, fencing or trust-discovery operations.
package provision

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	"github.com/mihsergeev/Sekvyr/operator/internal/recovery"
)

const Version = "0.1.0-rc.2"
const MaxInputBytes = 64 << 20

var ErrInvalid = errors.New("ProvisionInputInvalid")
var ErrFiles = errors.New("ProvisionFileBoundaryDenied")
var ErrAuthority = errors.New("ProvisionAuthorityMismatch")
var ErrPlatform = errors.New("ProvisionSecureFilesystemUnsupported")

type Receipt struct {
	Format                     string `json:"format"`
	Operation                  string `json:"operation"`
	Artifacts                  int    `json:"artifacts"`
	OfflineOnly                bool   `json:"offline_only"`
	OnlineVerificationRequired bool   `json:"online_verification_required"`
	IdentityComputed           bool   `json:"identity_computed"`
}

type PublicKey struct {
	Format    string `json:"format"`
	Role      string `json:"role"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}
type KeygenRequest struct {
	Role string `json:"role"`
}
type PublicRequest struct {
	Role        string `json:"role"`
	PrivateFile string `json:"private_file"`
}
type GenesisRequest struct {
	BodyFile        string `json:"body_file"`
	AdminKeyFile    string `json:"admin_key_file"`
	AdminPublicFile string `json:"admin_public_file"`
}

// RegistrationFile is an independently reviewed original-admin/genesis/floor
// pin, not a CurrentState exported by a server. ExpectedCursor forbids rebase.
type ChainFiles struct {
	RegistrationFile string         `json:"registration_file"`
	RecordsFile      string         `json:"records_file"`
	ExpectedCursor   journal.Cursor `json:"expected_cursor"`
}
type SnapshotRequest struct {
	Pending             bool       `json:"pending"`
	Chain               ChainFiles `json:"chain"`
	HeaderFile          string     `json:"header_file"`
	PlaintextFile       string     `json:"plaintext_file"`
	ReadKeyFile         string     `json:"read_key_file"`
	PublisherKeyFile    string     `json:"publisher_key_file"`
	PublisherPublicFile string     `json:"publisher_public_file"`
	RecipientPublicFile string     `json:"recipient_public_file"`
}
type TransitionRequest struct {
	Chain        ChainFiles `json:"chain"`
	BodyFile     string     `json:"body_file"`
	AdminKeyFile string     `json:"admin_key_file"`
}

// UIDReceipts are independently collected administrative input. They are not
// automatically discovered or asserted to be fresh by this offline package.
type UIDReceipts struct {
	Enrollment journal.Enrollment `json:"enrollment"`
	Binding    recovery.Binding   `json:"binding"`
}
type BootstrapRequest struct {
	Chain          ChainFiles `json:"chain"`
	ConfigFile     string     `json:"config_file"`
	ReceiptsFile   string     `json:"receipts_file"`
	BindingFile    string     `json:"binding_file"`
	NodePublicFile string     `json:"node_public_file"`
	TrustKey       string     `json:"trust_key"`
	PublisherKeyID string     `json:"publisher_key_id"`
}
type RecoveryRequest struct {
	Chain        ChainFiles `json:"chain"`
	ConfigFile   string     `json:"config_file"`
	ReceiptsFile string     `json:"receipts_file"`
	BindingFile  string     `json:"binding_file"`
	BodyFile     string     `json:"body_file"`
	StateFile    string     `json:"state_file"`
	AdminKeyFile string     `json:"admin_key_file"`
}

type files interface {
	ReadFile(string, int) ([]byte, error)
}
type artifacts map[string][]byte

type preparationInfo struct{ identityComputed bool }

func (artifacts) String() string   { return "provision artifacts [redacted]" }
func (artifacts) GoString() string { return "provision artifacts [redacted]" }

func encode(v any, limit int) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, ErrInvalid
	}
	b, err = e2e2.Canonical(b, limit)
	if err != nil {
		return nil, ErrInvalid
	}
	return b, nil
}
func decodeFile(f files, path string, out any, max int) error {
	b, err := f.ReadFile(path, max)
	if err != nil {
		return ErrFiles
	}
	defer clear(b)
	if journal.DecodeStrict(b, out, max) != nil {
		return ErrInvalid
	}
	return nil
}

// Run validates and prepares everything before exclusively creating output.
// A partial filesystem failure is preserved for explicit review, never adopted
// or overwritten on retry. Receipt contains no key, plaintext or input path.
func Run(ctx context.Context, command, workDir, input, output string, now time.Time) (Receipt, error) {
	if ctx == nil || ctx.Err() != nil {
		return Receipt{}, ErrInvalid
	}
	store, err := openFiles(workDir)
	if err != nil {
		return Receipt{}, err
	}
	defer store.Close()
	raw, err := store.ReadFile(input, MaxInputBytes)
	if err != nil {
		return Receipt{}, ErrFiles
	}
	defer clear(raw)
	info := &preparationInfo{}
	a, err := executePrepared(command, raw, store, now, info)
	if err != nil {
		return Receipt{}, err
	}
	defer func() {
		for _, b := range a {
			clear(b)
		}
	}()
	if ctx.Err() != nil {
		return Receipt{}, ErrInvalid
	}
	if err = store.WriteNew(output, a); err != nil {
		return Receipt{}, ErrFiles
	}
	return Receipt{Format: "sekvyr-offline-provision-receipt-v1", Operation: command, Artifacts: len(a), OfflineOnly: true, OnlineVerificationRequired: true, IdentityComputed: info.identityComputed}, nil
}
