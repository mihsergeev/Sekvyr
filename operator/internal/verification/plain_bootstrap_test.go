package verification

import (
	"encoding/json"
	"testing"
)

func TestPlainBootstrapCannotSubstituteE2E2Trust(t *testing.T) {
	wire, expected, _ := bundleFixture(t)
	plain := map[string]any{"schemaVersion": 1, "protocol": "plain-v1", "installationID": expected.InstallationID, "bootstrapGeneration": expected.BootstrapGeneration, "namespace": expected.Namespace, "serviceAccount": expected.ServiceAccount, "panelOrigin": expected.PanelOrigin, "nodePublicKeyFingerprint": expected.NodeFingerprint}
	raw, _ := json.Marshal(plain)
	if err := ValidatePlainTrustBundle(raw, expected); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeTrustBundle(raw, expected); err == nil {
		t.Fatal("Plain trust authorized E2E2")
	}
	for _, field := range []string{"installationID", "bootstrapGeneration", "namespace", "serviceAccount", "panelOrigin", "nodePublicKeyFingerprint", "protocol", "unexpected"} {
		t.Run(field, func(t *testing.T) {
			copy := map[string]any{}
			for k, v := range plain {
				copy[k] = v
			}
			copy[field] = "substitute"
			raw, _ := json.Marshal(copy)
			if ValidatePlainTrustBundle(raw, expected) == nil {
				t.Fatal("substituted Plain trust accepted")
			}
		})
	}
	raw, _ = json.Marshal(wire)
	if err := ValidatePlainTrustBundle(raw, expected); err != nil {
		t.Fatal("fully pinned mixed-mode trust rejected", err)
	}
	wire.ViewTrust[0].PublisherKeyFingerprint = "ed25519-sha256:invalid"
	raw, _ = json.Marshal(wire)
	if ValidatePlainTrustBundle(raw, expected) == nil {
		t.Fatal("Plain skipped invalid schema2 cryptographic pins")
	}
}
