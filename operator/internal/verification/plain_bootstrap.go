package verification

import (
	"encoding/json"
	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/panelauth"
)

// Plain trust is independently delivered and UID-pinned like E2E2 trust, but
// contains no publisher, witness or checkpoint assertions. It cannot substitute
// for schemaVersion 2 E2E2 trust, or authorize canonical HA.
func ValidatePlainTrustBundle(raw []byte, expected InstallationIdentity) error {
	var version struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if len(raw) > 64<<10 || json.Unmarshal(raw, &version) != nil {
		return reject("TrustInvalid")
	}
	if version.SchemaVersion == 2 {
		// An existing independently pinned E2E2 bundle can also identify a Plain
		// binding in a non-HA installation. Every E2E2 view/pin is still decoded
		// and validated; this does not turn Plain data into verified ciphertext.
		_, err := DecodeTrustBundle(raw, expected)
		return err
	}
	var wire struct {
		SchemaVersion            int    `json:"schemaVersion"`
		Protocol                 string `json:"protocol"`
		InstallationID           string `json:"installationID"`
		BootstrapGeneration      int64  `json:"bootstrapGeneration"`
		Namespace                string `json:"namespace"`
		ServiceAccount           string `json:"serviceAccount"`
		PanelOrigin              string `json:"panelOrigin"`
		NodePublicKeyFingerprint string `json:"nodePublicKeyFingerprint"`
	}
	if e2e2.DecodeStrict(raw, &wire, 64<<10) != nil || wire.SchemaVersion != 1 || wire.Protocol != "plain-v1" {
		return reject("TrustInvalid")
	}
	if !uuid(expected.InstallationID) || !dns(expected.Namespace, false) || !dns(expected.ServiceAccount, true) || expected.BootstrapGeneration < 1 || !fingerprint(expected.NodeFingerprint, "p256-sha256:") {
		return reject("TrustInvalid")
	}
	actualOrigin, actualErr := panelauth.CanonicalOrigin(wire.PanelOrigin)
	expectedOrigin, expectedErr := panelauth.CanonicalOrigin(expected.PanelOrigin)
	if actualErr != nil || expectedErr != nil || actualOrigin != expectedOrigin || wire.InstallationID != expected.InstallationID || wire.BootstrapGeneration != expected.BootstrapGeneration || wire.Namespace != expected.Namespace || wire.ServiceAccount != expected.ServiceAccount || wire.NodePublicKeyFingerprint != expected.NodeFingerprint {
		return reject("TrustMismatch")
	}
	return nil
}
