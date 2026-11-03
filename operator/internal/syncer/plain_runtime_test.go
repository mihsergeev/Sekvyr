package syncer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// This is a real pinned TLS transport peer around Runtime.Sync and fake Kube
// storage. It does not claim that the peer authenticates Kubernetes signatures;
// those checks belong to the actual backend and isolated live acceptance.
type plainRuntimeFixture struct {
	runtime *Runtime
	engine  Engine
	cr      *api.SekvyrSecret
	store   *api.SekvyrStore
	binding api.Binding
	writer  *reviewWriter
	mode    atomic.Int32
	logins  atomic.Int32
	reads   atomic.Int32
}

func newPlainRuntimeFixture(t *testing.T) *plainRuntimeFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("test node generation failed")
	}
	public, _ := key.PublicKey.ECDH()
	fingerprint, err := e2e2.NodeKeyFingerprint(public)
	if err != nil {
		t.Fatal("test node fingerprint failed")
	}
	engine, cr, store, binding, writer := reviewEngine(t, fingerprint)
	binding.Encryption = api.Encryption{Mode: "Plain"}
	binding.Source.ViewID, binding.Source.Environment, binding.Source.Group = "", "test", "public-group"
	f := &plainRuntimeFixture{engine: engine, cr: cr, store: store, binding: binding, writer: writer}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/machine/token":
			f.logins.Add(1)
			var body map[string]string
			if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["kubernetes_token"] == "" {
				t.Error("wrong runtime authentication shape")
				w.WriteHeader(400)
				return
			}
			if f.mode.Load() == 2 {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"access_token":"public-runtime-machine-session","token_type":"Bearer","expires_in":300,"name":"public-runtime-reader"}`)
		case "/api/v1/machine/secrets":
			f.reads.Add(1)
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer public-runtime-machine-session" || r.URL.Query().Get("project") != "app" || r.URL.Query().Get("env") != "test" || r.URL.Query().Get("group") != "public-group" || len(r.URL.Query()) != 3 {
				t.Error("runtime crossed its fixed authenticated source")
				w.WriteHeader(403)
				return
			}
			switch f.mode.Load() {
			case 1:
				w.WriteHeader(503) // sealed/unavailable response: no cached read
			case 3:
				w.WriteHeader(403)
			case 4:
				fmt.Fprint(w, `{"project":"app","environment":"test","values":[],"e2e":true,"project_key":null}`)
			case 5:
				fmt.Fprint(w, `{"project":"other","environment":"test","values":[],"e2e":false,"project_key":null}`)
			case 6:
				fmt.Fprint(w, `{"project":"app","environment":"test","values":[{"name":"TOKEN","path":"/","value":"public-first-row"},{"name":"BAD\u0000","path":"/","value":"public-bad-row"}],"e2e":false,"project_key":null}`)
			case 7:
				if f.reads.Load() == 1 {
					w.WriteHeader(401)
				} else {
					fmt.Fprint(w, `{"project":"app","environment":"test","values":[{"name":"TOKEN","path":"/","value":"public-runtime-value"}],"e2e":false,"project_key":null}`)
				}
			default:
				fmt.Fprint(w, `{"project":"app","environment":"test","values":[{"name":"TOKEN","path":"/","value":"public-runtime-value"}],"e2e":false,"project_key":null}`)
			}
		default:
			t.Error("Plain runtime attempted another protocol endpoint")
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caHash, err := installation.CertificateSetSHA256(ca)
	if err != nil {
		t.Fatal("test CA invalid")
	}
	engine.Config.AllowedPanelOrigins = []string{server.URL}
	engine.Config.CAConfigMaps = []installation.CAPin{{Name: "plain-ca", UID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Key: "ca.crt", DERSetSHA256: caHash}}
	store.Spec.Endpoint = api.Endpoint{URL: server.URL, CAConfigMapRef: &api.ConfigMapKeyRef{Name: "plain-ca", Key: "ca.crt"}}
	writer.config = engine.Config
	immutable := true
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("test key encoding failed")
	}
	trust, _ := json.Marshal(map[string]any{"schemaVersion": 1, "protocol": "plain-v1", "installationID": engine.Config.InstallationID,
		"bootstrapGeneration": 1, "namespace": engine.Config.Namespace, "serviceAccount": engine.Config.ServiceAccount,
		"panelOrigin": server.URL, "nodePublicKeyFingerprint": fingerprint})
	objects := []client.Object{
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: engine.Config.IdentityKeySecret.Name, Namespace: engine.Config.Namespace, UID: types.UID(engine.Config.IdentityKeySecret.UID)}, Type: corev1.SecretTypeOpaque, Immutable: &immutable, Data: map[string][]byte{engine.Config.IdentityKeySecret.Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: engine.Config.TrustBundleSecret.Name, Namespace: engine.Config.Namespace, UID: types.UID(engine.Config.TrustBundleSecret.UID)}, Type: corev1.SecretTypeOpaque, Immutable: &immutable, Data: map[string][]byte{engine.Config.TrustBundleSecret.Key: trust}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "plain-ca", Namespace: engine.Config.Namespace, UID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc"}, Immutable: &immutable, Data: map[string]string{"ca.crt": string(ca)}},
	}
	for _, object := range objects {
		if writer.Client.Create(context.Background(), object) != nil {
			t.Fatal("runtime bootstrap fixture failed")
		}
	}
	var state corev1.Secret
	if writer.Client.Get(context.Background(), client.ObjectKey{Namespace: engine.Config.Namespace, Name: engine.Config.StateSecret.Name}, &state) != nil {
		t.Fatal("runtime state unavailable")
	}
	state.Data[engine.Config.StateSecret.Key], _ = json.Marshal(map[string]any{"installationID": engine.Config.InstallationID, "bootstrapGeneration": 1})
	if writer.Client.Update(context.Background(), &state) != nil {
		t.Fatal("runtime marker setup failed")
	}
	claims, _ := json.Marshal(map[string]any{"sub": "system:serviceaccount:" + engine.Config.Namespace + ":" + engine.Config.ServiceAccount,
		"aud": []string{"sekvyr"}, "exp": time.Now().Add(time.Hour).Unix(), "kubernetes.io": map[string]any{
			"namespace": engine.Config.Namespace, "serviceaccount": map[string]any{"name": engine.Config.ServiceAccount, "uid": "public-test-account"}, "pod": map[string]any{"uid": "public-test-pod"}}})
	tokenFile := filepath.Join(t.TempDir(), "projected-token")
	if os.WriteFile(tokenFile, []byte("public-header."+base64.RawURLEncoding.EncodeToString(claims)+".public-test-signature"), 0600) != nil {
		t.Fatal("runtime projected token fixture failed")
	}
	f.engine, f.runtime = engine, &Runtime{Config: engine.Config, Reader: engine.Reader, Writer: writer, TokenFile: tokenFile}
	return f
}

func (f *plainRuntimeFixture) sync() (Result, error) {
	return f.runtime.Sync(context.Background(), f.cr, f.store, f.binding, func(context.Context) error { return nil })
}

func TestPlainRuntimePinnedTLSFailuresNeverPartiallyCreateTarget(t *testing.T) {
	for _, mode := range []int32{1, 2, 3, 4, 5, 6} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			f := newPlainRuntimeFixture(t)
			f.mode.Store(mode)
			if _, err := f.sync(); err == nil || len(f.writer.events) != 0 {
				t.Fatal("failed authenticated Plain read reached a target/state mutation")
			}
			var target corev1.Secret
			if f.engine.Reader.Get(context.Background(), client.ObjectKey{Namespace: f.engine.Config.Namespace, Name: f.binding.Target.Name}, &target) == nil {
				t.Fatal("failed read created a target")
			}
		})
	}
}

func TestPlainRuntimeFreshTLSReadAndOutageRetainCurrentTarget(t *testing.T) {
	f := newPlainRuntimeFixture(t)
	first, err := f.sync()
	if err != nil || !first.Plain || !first.Changed || first.Rollout == nil || !first.Rollout.Ready {
		t.Fatal("real TLS Plain runtime failed", err)
	}
	before := targetFor(t, f.engine).DeepCopy()
	for _, mode := range []int32{1, 2, 3, 4, 5, 6} {
		f.mode.Store(mode)
		f.writer.events = nil
		if _, err := f.sync(); err == nil || len(f.writer.events) != 0 {
			t.Fatal("failed fresh source reused cached values or wrote a target")
		}
		after := targetFor(t, f.engine)
		if !equalData(before.Data, after.Data) || before.Annotations[revisionAnnotation] != after.Annotations[revisionAnnotation] || after.Annotations[checkpointAnnotation] != "" {
			t.Fatal("failed read changed target bytes/revision or manufactured a checkpoint")
		}
	}
	f.mode.Store(0)
	if result, err := f.sync(); err != nil || result.Changed || result.Revision != first.Revision {
		t.Fatal("fresh source recovery caused an equal-value data change", err)
	}
}

func TestPlainRuntimeRetriesOnlyFreshAuthenticationAndPreflightsBeforeHTTP(t *testing.T) {
	f := newPlainRuntimeFixture(t)
	f.mode.Store(7)
	if _, err := f.sync(); err != nil || f.logins.Load() != 2 || f.reads.Load() != 2 {
		t.Fatal("Plain runtime did not perform the bounded reauthentication retry", err)
	}
	g := newPlainRuntimeFixture(t)
	g.binding.Target.Name = g.engine.Config.StateSecret.Name
	if _, err := g.sync(); err == nil || g.logins.Load() != 0 || g.reads.Load() != 0 || len(g.writer.events) != 0 {
		t.Fatal("protected target was not rejected before HTTP")
	}
}
