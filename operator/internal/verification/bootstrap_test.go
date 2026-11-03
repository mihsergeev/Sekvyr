package verification

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

func bundleFixture(t *testing.T) (bundleWire, InstallationIdentity, *readerFixture) {
	t.Helper()
	f := newFixture(t, 1)
	var id string
	var key []byte
	for candidate, public := range f.trust.PublisherKeys {
		id = candidate
		key = public
	}
	expected := InstallationIdentity{InstallationID: "55555555-5555-4555-8555-555555555555", Namespace: "apps", ServiceAccount: "sekvyr-operator", PanelOrigin: "https://sekvyr.example.com", BootstrapGeneration: 1, NodeFingerprint: f.trust.NodeFingerprint, AllowedWitnessOrigins: []string{"https://witness.example.com"}}
	scope := f.trust.Scope
	wire := bundleWire{SchemaVersion: 2, InstallationID: expected.InstallationID, BootstrapGeneration: 1, Namespace: expected.Namespace, ServiceAccount: expected.ServiceAccount, PanelOrigin: expected.PanelOrigin, NodePublicKeyFingerprint: expected.NodeFingerprint, ViewTrust: []viewWire{{TrustKey: "app-view", StoreUID: "11111111-1111-4111-8111-111111111111", BindingID: "22222222-2222-4222-8222-222222222222", RealmID: scope.RealmID, ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID, ViewID: scope.ViewID, LogID: scope.LogID, PublisherPolicyEpoch: "1", PublisherPublicKey: base64.RawURLEncoding.EncodeToString(key), PublisherKeyFingerprint: id, Witness: witnessWire{Origin: "https://witness.example.com", Epoch: "1", PublicKey: base64.RawURLEncoding.EncodeToString(f.trust.WitnessPublicKey), KeyFingerprint: f.trust.WitnessKeyID}, MinimumCheckpoint: checkpointWire{Sequence: "1", EnvelopeHash: f.heads[0].EnvelopeHash}}}}
	return wire, expected, f
}

func TestIndependentBundleBindsInstallationAndAuthorizedView(t *testing.T) {
	wire, expected, _ := bundleFixture(t)
	raw, _ := json.Marshal(wire)
	bundle, err := DecodeTrustBundle(raw, expected)
	if err != nil {
		t.Fatal(err)
	}
	v := wire.ViewTrust[0]
	trust, err := bundle.Authorize(v.TrustKey, v.StoreUID, v.BindingID, v.ViewID)
	if err != nil {
		t.Fatal(err)
	}
	if trust.Scope.ViewID != v.ViewID || trust.MinimumCheckpoint.EnvelopeHash != v.MinimumCheckpoint.EnvelopeHash {
		t.Fatal("independent identity lost")
	}
	for _, key := range trust.PublisherKeys {
		clear(key)
	}
	second, err := bundle.Authorize(v.TrustKey, v.StoreUID, v.BindingID, v.ViewID)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range second.PublisherKeys {
		if bytes.Equal(key, make([]byte, 32)) {
			t.Fatal("caller mutated stored trust")
		}
	}
	for _, args := range [][4]string{{"other", v.StoreUID, v.BindingID, v.ViewID}, {v.TrustKey, "33333333-3333-4333-8333-333333333333", v.BindingID, v.ViewID}, {v.TrustKey, v.StoreUID, "33333333-3333-4333-8333-333333333333", v.ViewID}, {v.TrustKey, v.StoreUID, v.BindingID, "33333333-3333-4333-8333-333333333333"}} {
		if _, err := bundle.Authorize(args[0], args[1], args[2], args[3]); err == nil {
			t.Fatal("binding substitute accepted")
		}
	}
}

func TestBootstrapSubstitutionsAndRollbackRejected(t *testing.T) {
	changes := map[string]func(*bundleWire){
		"generation rollback":                       func(b *bundleWire) { b.BootstrapGeneration = 0 },
		"generation advance requires authorization": func(b *bundleWire) { b.BootstrapGeneration = 2 },
		"other installation":                        func(b *bundleWire) { b.InstallationID = "33333333-3333-4333-8333-333333333333" },
		"namespace":                                 func(b *bundleWire) { b.Namespace = "foreign" },
		"service account":                           func(b *bundleWire) { b.ServiceAccount = "application" },
		"panel origin":                              func(b *bundleWire) { b.PanelOrigin = "https://other.example.com" },
		"node fingerprint":                          func(b *bundleWire) { b.NodePublicKeyFingerprint = "p256-sha256:" + strings.Repeat("0", 64) },
		"publisher key": func(b *bundleWire) {
			b.ViewTrust[0].PublisherPublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		},
		"publisher fingerprint": func(b *bundleWire) {
			b.ViewTrust[0].PublisherKeyFingerprint = "ed25519-sha256:" + strings.Repeat("0", 64)
		},
		"witness origin": func(b *bundleWire) { b.ViewTrust[0].Witness.Origin = "https://panel.example.com" },
		"witness key": func(b *bundleWire) {
			b.ViewTrust[0].Witness.PublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		},
		"witness fingerprint": func(b *bundleWire) {
			b.ViewTrust[0].Witness.KeyFingerprint = "ed25519-sha256:" + strings.Repeat("0", 64)
		},
		"genesis TOFU": func(b *bundleWire) {
			b.ViewTrust[0].MinimumCheckpoint = checkpointWire{Sequence: "0", EnvelopeHash: e2e2.ZeroHash}
		},
		"zero head hash":       func(b *bundleWire) { b.ViewTrust[0].MinimumCheckpoint.EnvelopeHash = e2e2.ZeroHash },
		"duplicate views":      func(b *bundleWire) { b.ViewTrust = append(b.ViewTrust, b.ViewTrust[0]) },
		"unknown mode version": func(b *bundleWire) { b.SchemaVersion = 1 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			wire, expected, _ := bundleFixture(t)
			change(&wire)
			raw, _ := json.Marshal(wire)
			if _, err := DecodeTrustBundle(raw, expected); err == nil {
				t.Fatal("bootstrap substitution accepted")
			}
		})
	}
	wire, expected, _ := bundleFixture(t)
	raw, _ := json.Marshal(wire)
	for _, bad := range [][]byte{append([]byte(`{"schemaVersion":2,`), raw[1:]...), bytes.Replace(raw, []byte(`"schemaVersion":2`), []byte(`"schemaVersion":null`), 1), append(raw, []byte(` {}`)...), bytes.Replace(raw, []byte(`"schemaVersion":2`), []byte(`"schemaVersion":2,"exampleOnly":true`), 1)} {
		if _, err := DecodeTrustBundle(bad, expected); err == nil {
			t.Fatal("ambiguous/bootstrap example accepted")
		}
	}
}

func TestNodeKeyOnlyPKCS8P256AndExactFingerprint(t *testing.T) {
	f := newFixture(t, 1)
	der, err := x509.MarshalPKCS8PrivateKey(f.node)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	node, err := ParseNodeKey(raw, f.trust.NodeFingerprint)
	if err != nil || !bytes.Equal(node.Bytes(), f.node.Bytes()) {
		t.Fatal("valid existing node key rejected")
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), raw...), append(bytes.Clone(raw), []byte("untrusted tail")...), append([]byte("untrusted prefix\n"), raw...), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), bytes.Repeat([]byte{'x'}, (16<<10)+1)} {
		if _, err := ParseNodeKey(bad, f.trust.NodeFingerprint); err == nil {
			t.Fatal("bad key encoding accepted")
		}
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, _ := x509.MarshalPKCS8PrivateKey(x25519)
	if _, err := ParseNodeKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}), f.trust.NodeFingerprint); err == nil {
		t.Fatal("node curve downgrade accepted")
	}
	if _, err := ParseNodeKey(raw, "p256-sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("node replacement accepted")
	}
}

func TestWitnessCannotReusePanelOriginEvenIfAllowlisted(t *testing.T) {
	wire, expected, _ := bundleFixture(t)
	wire.ViewTrust[0].Witness.Origin = expected.PanelOrigin
	expected.AllowedWitnessOrigins = append(expected.AllowedWitnessOrigins, expected.PanelOrigin)
	raw, _ := json.Marshal(wire)
	if _, err := DecodeTrustBundle(raw, expected); err == nil {
		t.Fatal("panel and witness shared origin accepted")
	}
}
