package verification

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/panelauth"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
)

// InstallationIdentity is fixed independently of incoming bundle bytes. The
// installation adapter must first authorize the immutable Secret name/UID and
// retained state generation. This parser is not a signature authority or TOFU.
type InstallationIdentity struct {
	InstallationID        string
	Namespace             string
	ServiceAccount        string
	PanelOrigin           string
	BootstrapGeneration   int64
	NodeFingerprint       string
	AllowedWitnessOrigins []string
}

type bundleWire struct {
	SchemaVersion            int        `json:"schemaVersion"`
	InstallationID           string     `json:"installationID"`
	BootstrapGeneration      int64      `json:"bootstrapGeneration"`
	Namespace                string     `json:"namespace"`
	ServiceAccount           string     `json:"serviceAccount"`
	PanelOrigin              string     `json:"panelOrigin"`
	NodePublicKeyFingerprint string     `json:"nodePublicKeyFingerprint"`
	ViewTrust                []viewWire `json:"viewTrust"`
}
type viewWire struct {
	TrustKey                string         `json:"trustKey"`
	StoreUID                string         `json:"storeUID"`
	BindingID               string         `json:"bindingID"`
	RealmID                 string         `json:"realmID"`
	ProjectID               string         `json:"projectID"`
	EnvironmentID           string         `json:"environmentID"`
	ViewID                  string         `json:"viewID"`
	LogID                   string         `json:"logID"`
	PublisherPolicyEpoch    string         `json:"publisherPolicyEpoch"`
	PublisherPublicKey      string         `json:"publisherPublicKey"`
	PublisherKeyFingerprint string         `json:"publisherKeyFingerprint"`
	Witness                 witnessWire    `json:"witness"`
	MinimumCheckpoint       checkpointWire `json:"minimumCheckpoint"`
}
type witnessWire struct {
	Origin         string `json:"origin"`
	Epoch          string `json:"epoch"`
	PublicKey      string `json:"publicKey"`
	KeyFingerprint string `json:"keyFingerprint"`
}
type checkpointWire struct {
	Sequence     string `json:"sequence"`
	EnvelopeHash string `json:"envelopeHash"`
}
type authorizedView struct {
	wire  viewWire
	trust Trust
}
type TrustBundle struct{ views map[string]authorizedView }

func (b *TrustBundle) ViewCount() int {
	if b == nil {
		return 0
	}
	return len(b.views)
}

func (TrustBundle) String() string   { return "independent trust bundle [redacted]" }
func (TrustBundle) GoString() string { return "independent trust bundle [redacted]" }

// DecodeTrustBundle accepts exactly the independently delivered bundle format.
// Design examples marked exampleOnly/description are deliberately not accepted.
// Positive minimum seq/hash is mandatory; a fresh reader never adopts genesis.
func DecodeTrustBundle(raw []byte, expected InstallationIdentity) (*TrustBundle, error) {
	if !uuid(expected.InstallationID) || !dns(expected.Namespace, false) || !dns(expected.ServiceAccount, true) || expected.BootstrapGeneration < 1 || !fingerprint(expected.NodeFingerprint, "p256-sha256:") {
		return nil, reject("TrustInvalid")
	}
	var wire bundleWire
	if e2e2.DecodeStrict(raw, &wire, 64<<10) != nil {
		return nil, reject("TrustInvalid")
	}
	if wire.SchemaVersion != 2 || wire.InstallationID != expected.InstallationID || wire.Namespace != expected.Namespace || wire.ServiceAccount != expected.ServiceAccount || wire.BootstrapGeneration != expected.BootstrapGeneration || wire.NodePublicKeyFingerprint != expected.NodeFingerprint {
		return nil, reject("TrustMismatch")
	}
	origin, err := panelauth.CanonicalOrigin(wire.PanelOrigin)
	want, e := panelauth.CanonicalOrigin(expected.PanelOrigin)
	if err != nil || e != nil || origin != want {
		return nil, reject("TrustMismatch")
	}
	if len(wire.ViewTrust) == 0 || len(wire.ViewTrust) > 64 {
		return nil, reject("TrustInvalid")
	}
	views := make(map[string]authorizedView, len(wire.ViewTrust))
	bindings := map[string]bool{}
	logs := map[string]bool{}
	for _, view := range wire.ViewTrust {
		if !dns(view.TrustKey, false) || !uuid(view.StoreUID) || !uuid(view.BindingID) || views[view.TrustKey].wire.TrustKey != "" || bindings[view.StoreUID+"/"+view.BindingID] {
			return nil, reject("TrustInvalid")
		}
		scope := witness.Scope{RealmID: view.RealmID, ProjectID: view.ProjectID, EnvironmentID: view.EnvironmentID, ViewID: view.ViewID, LogID: view.LogID}
		if !e2e2.ValidScope(codecScope(scope)) || logs[scope.LogID] {
			return nil, reject("TrustInvalid")
		}
		publisher, err := e2e2.DecodeBase64(view.PublisherPublicKey, ed25519.PublicKeySize)
		if err != nil || !e2e2.ValidEd25519PublicKey(publisher) || e2e2.KeyID(publisher) != view.PublisherKeyFingerprint {
			return nil, reject("TrustInvalid")
		}
		public, err := e2e2.DecodeBase64(view.Witness.PublicKey, ed25519.PublicKeySize)
		if err != nil || !e2e2.ValidEd25519PublicKey(public) || e2e2.KeyID(public) != view.Witness.KeyFingerprint {
			return nil, reject("TrustInvalid")
		}
		witnessOrigin, originErr := panelauth.CanonicalOrigin(view.Witness.Origin)
		if originErr != nil || witnessOrigin == origin || !allowedOrigin(view.Witness.Origin, expected.AllowedWitnessOrigins) {
			return nil, reject("WitnessOriginDenied")
		}
		trust := Trust{Scope: scope, PublisherPolicyEpoch: view.PublisherPolicyEpoch, PublisherKeys: map[string]ed25519.PublicKey{view.PublisherKeyFingerprint: bytes.Clone(publisher)}, WitnessOrigin: witnessOrigin,
			WitnessEpoch: view.Witness.Epoch, WitnessKeyID: view.Witness.KeyFingerprint, WitnessPublicKey: bytes.Clone(public),
			MinimumCheckpoint: witness.Floor{Sequence: view.MinimumCheckpoint.Sequence, EnvelopeHash: view.MinimumCheckpoint.EnvelopeHash}, NodeFingerprint: expected.NodeFingerprint}
		if _, err := e2e2.Counter(trust.MinimumCheckpoint.Sequence, false); err != nil {
			return nil, reject("TrustInvalid")
		}
		if _, err := witness.NewPinnedVerifier(witness.Trust{Scope: scope, WitnessEpoch: trust.WitnessEpoch, KeyID: trust.WitnessKeyID, PublicKey: trust.WitnessPublicKey, PublisherPolicyEpoch: trust.PublisherPolicyEpoch, Checkpoint: trust.MinimumCheckpoint}); err != nil {
			return nil, reject("TrustInvalid")
		}
		views[view.TrustKey] = authorizedView{wire: view, trust: trust}
		bindings[view.StoreUID+"/"+view.BindingID] = true
		logs[scope.LogID] = true
	}
	return &TrustBundle{views: views}, nil
}

// Authorize binds a view to the exact administrator Store UID, binding UUID and
// stable view UUID. Human routing labels are never substituted for this check.
func (b *TrustBundle) Authorize(trustKey, storeUID, bindingID, viewID string) (Trust, error) {
	if b == nil {
		return Trust{}, reject("TrustInvalid")
	}
	view, ok := b.views[trustKey]
	if !ok || view.wire.StoreUID != storeUID || view.wire.BindingID != bindingID || view.wire.ViewID != viewID {
		return Trust{}, reject("BindingDenied")
	}
	trust := view.trust
	trust.WitnessPublicKey = bytes.Clone(trust.WitnessPublicKey)
	trust.PublisherKeys = make(map[string]ed25519.PublicKey, len(view.trust.PublisherKeys))
	for id, key := range view.trust.PublisherKeys {
		trust.PublisherKeys[id] = bytes.Clone(key)
	}
	return trust, nil
}

// ParseNodeKey accepts one unencrypted PKCS8 PEM P-256 private key only. It never
// generates a key, writes a key file or tries a legacy key format on failure.
func ParseNodeKey(raw []byte, expectedFingerprint string) (*ecdh.PrivateKey, error) {
	if len(raw) == 0 || len(raw) > 16<<10 || !fingerprint(expectedFingerprint, "p256-sha256:") {
		return nil, reject("NodeKeyInvalid")
	}
	trimmed := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, reject("NodeKeyInvalid")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, reject("NodeKeyInvalid")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, reject("NodeKeyInvalid")
	}
	var node *ecdh.PrivateKey
	switch k := key.(type) {
	case *ecdh.PrivateKey:
		node = k
	case *ecdsa.PrivateKey:
		node, err = k.ECDH()
	default:
		return nil, reject("NodeKeyInvalid")
	}
	if err != nil || node == nil || node.Curve() != ecdh.P256() {
		return nil, reject("NodeKeyInvalid")
	}
	actual, err := e2e2.NodeKeyFingerprint(node.PublicKey())
	if err != nil || actual != expectedFingerprint {
		return nil, reject("NodeKeyMismatch")
	}
	return node, nil
}

func allowedOrigin(value string, allowed []string) bool {
	origin, err := panelauth.CanonicalOrigin(value)
	if err != nil {
		return false
	}
	for _, raw := range allowed {
		pin, e := panelauth.CanonicalOrigin(raw)
		if e == nil && origin == pin {
			return true
		}
	}
	return false
}
func uuid(value string) bool {
	return e2e2.ValidScope(e2e2.Scope{RealmID: value, ProjectID: value, EnvironmentID: value, ViewID: value, LogID: value})
}
func fingerprint(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, c := range []byte(strings.TrimPrefix(value, prefix)) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func dns(value string, subdomain bool) bool {
	if value == "" || len(value) > 253 || !subdomain && len(value) > 63 {
		return false
	}
	labels := strings.Split(value, ".")
	if !subdomain && len(labels) != 1 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
