// Package fencing implements the explicitly opted-in HA trial fencing boundary.
// Lease election is not fencing: current signed grants, activation receipts and
// per-object barriers authorize writes. It makes no Byzantine operator claim.
package fencing

import (
	"encoding/json"
	"errors"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
)

const FenceAnnotation = "secrets.sekvyr.ru/fence"
const WriteSessionAnnotation = "secrets.sekvyr.ru/write-session"
const maxWireBytes = 256 << 10
const maxAdmissionBytes = 4 << 20
const maxCASAttempts = 3

type Error struct{ Reason string }

func (e *Error) Error() string { return "fencing: " + e.Reason }
func fail(reason string) error { return &Error{Reason: reason} }
func Reason(err error) string {
	var value *Error
	if errors.As(err, &value) {
		return value.Reason
	}
	return "FencingUnavailable"
}

// Fence is public metadata. No key material or raw grant is copied into objects.
type Fence struct {
	InstallationID      string `json:"installation_id"`
	BootstrapGeneration int64  `json:"bootstrap_generation"`
	Term                string `json:"term"`
	OwnerPodUID         string `json:"owner_pod_uid"`
	GrantHash           string `json:"grant_hash"`
}

func EncodeFence(value Fence) (string, error) {
	if !validUUID(value.InstallationID) || value.BootstrapGeneration < 1 || value.BootstrapGeneration > 9007199254740991 || !validUUID(value.OwnerPodUID) || len(value.GrantHash) != 64 {
		return "", fail("FenceInvalid")
	}
	if _, err := e2e2.Counter(value.Term, false); err != nil {
		return "", fail("FenceInvalid")
	}
	for _, digit := range value.GrantHash {
		if !(digit >= '0' && digit <= '9' || digit >= 'a' && digit <= 'f') {
			return "", fail("FenceInvalid")
		}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fail("FenceInvalid")
	}
	canonical, err := e2e2.Canonical(raw, 4096)
	if err != nil {
		return "", fail("FenceInvalid")
	}
	return string(canonical), nil
}

func DecodeFence(raw string) (Fence, error) {
	var value Fence
	if journal.DecodeStrict([]byte(raw), &value, 4096) != nil {
		return value, fail("FenceInvalid")
	}
	encoded, err := EncodeFence(value)
	if err != nil || encoded != raw {
		return Fence{}, fail("FenceInvalid")
	}
	return value, nil
}

type Subject struct {
	Username string `json:"username"`
	UID      string `json:"uid"`
}
type MaterialPin struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
	Key  string `json:"key"`
}

type Config struct {
	Trial                     bool                `json:"trial"`
	InstallationID            string              `json:"installation_id"`
	LogID                     string              `json:"log_id"`
	MinimumCursor             journal.Cursor      `json:"minimum_cursor"`
	Namespace                 string              `json:"namespace"`
	NamespaceUID              string              `json:"namespace_uid"`
	OperatorServiceAccountUID string              `json:"operator_service_account_uid"`
	LeaseUID                  string              `json:"lease_uid"`
	FencerServiceAccount      string              `json:"fencer_service_account"`
	FencerServiceAccountUID   string              `json:"fencer_service_account_uid"`
	BootstrapSubjects         []Subject           `json:"bootstrap_subjects"`
	ManagedObjects            []journal.ObjectRef `json:"managed_objects"`
	MaterialPins              []MaterialPin       `json:"material_pins"`
}
