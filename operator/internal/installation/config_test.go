package installation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func fixture() Config {
	return Config{InstallationID: "11111111-1111-4111-8111-111111111111", Namespace: "test-system", ServiceAccount: "operator", BootstrapGeneration: 7,
		AllowedPanelOrigins: []string{"https://panel.example.test"}, AllowedWitnessOrigins: []string{"https://witness.example.test"},
		IdentityKeySecret: SecretPin{Name: "identity", UID: "22222222-2222-4222-8222-222222222222", Key: "identity.pem"},
		TrustBundleSecret: SecretPin{Name: "trust", UID: "33333333-3333-4333-8333-333333333333", Key: "trust.json"},
		StateSecret:       SecretPin{Name: "state", UID: "44444444-4444-4444-8444-444444444444", Key: "installation.json"}}
}
func TestStrictConfig(t *testing.T) {
	c := fixture()
	raw, _ := json.Marshal(c)
	if _, err := Decode(strings.NewReader(string(raw))); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.TrimSuffix(string(raw), "}") + `,"unexpected":"sensitive-value"}`,
		strings.TrimSuffix(string(raw), "}") + `,"namespace":"other"}`,
		strings.Replace(string(raw), `"key":"identity.pem"`, `"key":"identity.pem","key":"other"`, 1),
		string(raw) + `{}`, strings.Repeat(" ", 65537),
	} {
		if _, err := Decode(strings.NewReader(bad)); err == nil {
			t.Fatal("ambiguous/unknown/oversized JSON accepted")
		}
	}
}
func TestOriginIsolation(t *testing.T) {
	c := fixture()
	if !c.AllowsPanelOrigin("https://PANEL.example.test:443/") {
		t.Fatal("equivalent origin rejected")
	}
	for _, bad := range []string{"http://panel.example.test", "https://panel.example.test.attacker.test", "https://user@panel.example.test", "https://panel.example.test/?q=x", "https://panel.example.test/#", "https://panel.example.test:", "https://panel.example.test:0443", "https://panel.example.test/a", "https://panel.example.test//", "https://panel.example.test:0"} {
		if c.AllowsPanelOrigin(bad) {
			t.Fatal("unsafe origin accepted")
		}
	}
}
func protectedObjects(c Config) []client.Object {
	immutable := true
	marker, _ := json.Marshal(StateMarker{InstallationID: c.InstallationID, BootstrapGeneration: c.BootstrapGeneration})
	var objects []client.Object
	for i, p := range []SecretPin{c.IdentityKeySecret, c.TrustBundleSecret, c.StateSecret} {
		data := []byte("test-only-bootstrap-placeholder")
		if i == 2 {
			data = marker
		}
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: p.Name, Namespace: c.Namespace, UID: types.UID(p.UID)}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{p.Key: data}}
		if i < 2 {
			s.Immutable = &immutable
		}
		objects = append(objects, s)
	}
	return objects
}
func reader(objects ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

type countReader struct {
	client.Reader
	calls int
}

func (r *countReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	r.calls++
	return r.Reader.Get(ctx, key, object, options...)
}
func TestBootstrapScopePinsAndGeneration(t *testing.T) {
	c := fixture()
	ctx := context.Background()
	if err := c.ValidateRuntime(ctx, reader(protectedObjects(c)...), c.Namespace, c.ServiceAccount); err != nil {
		t.Fatal(err)
	}
	for _, tuple := range [][2]string{{"other", c.ServiceAccount}, {c.Namespace, "other"}} {
		r := &countReader{Reader: reader()}
		if Reason(c.ValidateRuntime(ctx, r, tuple[0], tuple[1])) != "ScopeDenied" || r.calls != 0 {
			t.Fatal("bootstrap read outside installation scope")
		}
	}
	tests := []struct {
		name   string
		alter  func([]client.Object)
		reason string
	}{
		{"replaced", func(o []client.Object) { o[0].SetUID("55555555-5555-4555-8555-555555555555") }, "BootstrapMismatch"},
		{"mutable-trust", func(o []client.Object) { o[1].(*corev1.Secret).Immutable = nil }, "BootstrapMismatch"},
		{"wrong-type", func(o []client.Object) { o[0].(*corev1.Secret).Type = corev1.SecretTypeServiceAccountToken }, "BootstrapMismatch"},
		{"oversized-key", func(o []client.Object) { o[0].(*corev1.Secret).Data[c.IdentityKeySecret.Key] = make([]byte, 16385) }, "BootstrapMismatch"},
		{"rolled-back-state", func(o []client.Object) {
			o[2].(*corev1.Secret).Data[c.StateSecret.Key] = []byte(`{"installationID":"` + c.InstallationID + `","bootstrapGeneration":6}`)
		}, "BootstrapMismatch"},
		{"duplicate-state", func(o []client.Object) {
			o[2].(*corev1.Secret).Data[c.StateSecret.Key] = []byte(`{"installationID":"` + c.InstallationID + `","bootstrapGeneration":6,"bootstrapGeneration":7}`)
		}, "BootstrapMismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects := protectedObjects(c)
			tt.alter(objects)
			if Reason(c.ValidateRuntime(ctx, reader(objects...), c.Namespace, c.ServiceAccount)) != tt.reason {
				t.Fatal("invalid bootstrap accepted")
			}
		})
	}
	if Reason(c.ValidateRuntime(ctx, reader(protectedObjects(c)[:2]...), c.Namespace, c.ServiceAccount)) != "StateMissing" {
		t.Fatal("missing state accepted")
	}
}
func TestProtectedNamesAndUIDs(t *testing.T) {
	c := fixture()
	c.ProtectedSecretUIDs = []string{"55555555-5555-4555-8555-555555555555"}
	for _, pair := range [][2]string{{c.IdentityKeySecret.Name, ""}, {"another-name", c.IdentityKeySecret.UID}, {"other", c.ProtectedSecretUIDs[0]}, {"sh.helm.release.v1.demo.v1", ""}} {
		if !c.Protected(pair[0], types.UID(pair[1])) {
			t.Fatal("protected target accepted")
		}
	}
}
func testCertificate(t *testing.T, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(2000000000, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func TestCAContentPins(t *testing.T) {
	a, b := testCertificate(t, 1), testCertificate(t, 2)
	h1, err := CertificateSetSHA256(append(append([]byte{}, a...), b...))
	if err != nil {
		t.Fatal(err)
	}
	h2, err := CertificateSetSHA256(append(append(append([]byte{}, b...), a...), a...))
	if err != nil || h1 != h2 {
		t.Fatal("certificate set order/duplicates changed pin")
	}
	c := fixture()
	c.CAConfigMaps = []CAPin{{Name: "ca", UID: "55555555-5555-4555-8555-555555555555", Key: "ca.crt", DERSetSHA256: h1}}
	immutable := true
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: c.Namespace, UID: types.UID(c.CAConfigMaps[0].UID)}, Immutable: &immutable, Data: map[string]string{"ca.crt": string(a) + string(b)}}
	if err := c.ValidateCA(context.Background(), reader(config), "ca", "ca.crt"); err != nil {
		t.Fatal(err)
	}
	config.Data["ca.crt"] = string(a)
	if c.ValidateCA(context.Background(), reader(config), "ca", "ca.crt") == nil {
		t.Fatal("CA content replacement accepted")
	}
	if _, err := CertificateSetSHA256(append([]byte("junk"), a...)); err == nil {
		t.Fatal("unparsed CA data accepted")
	}
}
