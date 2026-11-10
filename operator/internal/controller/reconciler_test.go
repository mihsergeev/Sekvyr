package controller

import (
	"context"
	"encoding/json"
	"testing"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func configFixture() installation.Config {
	return installation.Config{InstallationID: "11111111-1111-4111-8111-111111111111", Namespace: "test-system", ServiceAccount: "operator", BootstrapGeneration: 1,
		AllowedPanelOrigins: []string{"https://panel.example.test"}, AllowedWitnessOrigins: []string{"https://witness.example.test"},
		IdentityKeySecret: installation.SecretPin{Name: "identity", UID: "22222222-2222-4222-8222-222222222222", Key: "identity.pem"},
		TrustBundleSecret: installation.SecretPin{Name: "trust", UID: "33333333-3333-4333-8333-333333333333", Key: "trust.json"},
		StateSecret:       installation.SecretPin{Name: "state", UID: "44444444-4444-4444-8444-444444444444", Key: "installation.json"}}
}
func storeFixture() *api.SekvyrStore {
	return &api.SekvyrStore{ObjectMeta: metav1.ObjectMeta{Name: "store", Namespace: "test-system", UID: "55555555-5555-4555-8555-555555555555", Generation: 1}, Spec: api.SekvyrStoreSpec{
		Endpoint: api.Endpoint{URL: "https://panel.example.test"}, Bindings: []api.Binding{{ID: "66666666-6666-4666-8666-666666666666", Name: "app", ResourceName: "app", Source: api.Source{Project: "app", Environment: "prod", PathPrefix: "/"}, Selection: api.Selection{Mode: "All"}, Encryption: api.Encryption{Mode: "Plain"}, Target: api.Target{Name: "app-values"}, Rollout: api.BindingRollout{AllowedDeployments: []string{"app"}}}}}}
}
func secretFixture() *api.SekvyrSecret {
	s := storeFixture()
	return &api.SekvyrSecret{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: s.Namespace, UID: "77777777-7777-4777-8777-777777777777", Generation: 1}, Spec: api.SekvyrSecretSpec{StoreRef: api.StoreReference{Name: s.Name, UID: string(s.UID)}, Binding: "app"}}
}
func TestBindingAuthorization(t *testing.T) {
	c := configFixture()
	store := storeFixture()
	secret := secretFixture()
	if err := ValidateStore(c, store); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSecret(c, secret, store); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, reason string
		change       func(*api.SekvyrStore, *api.SekvyrSecret)
	}{
		{"recreated-store", "BootstrapMismatch", func(s *api.SekvyrStore, _ *api.SekvyrSecret) { s.UID = "88888888-8888-4888-8888-888888888888" }},
		{"other-resource", "ScopeDenied", func(_ *api.SekvyrStore, s *api.SekvyrSecret) { s.Name = "other" }},
		{"other-namespace", "ScopeDenied", func(_ *api.SekvyrStore, s *api.SekvyrSecret) { s.Namespace = "other" }},
		{"protected-target", "ProtectedTarget", func(s *api.SekvyrStore, _ *api.SekvyrSecret) { s.Spec.Bindings[0].Target.Name = "state" }},
		{"unapproved-rollout", "ScopeDenied", func(_ *api.SekvyrStore, s *api.SekvyrSecret) {
			s.Spec.Rollout = api.RequestedRollout{Enabled: true, Deployments: []string{"unapproved"}}
		}},
		{"disabled-rollout-names", "InvalidSpec", func(_ *api.SekvyrStore, s *api.SekvyrSecret) { s.Spec.Rollout.Deployments = []string{"app"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, q := store.DeepCopy(), secret.DeepCopy()
			tt.change(s, q)
			var err error
			if err = ValidateStore(c, s); err == nil {
				_, err = ValidateSecret(c, q, s)
			}
			if err == nil || installation.Reason(err) != tt.reason {
				t.Fatal("authorization failure was not preserved", err)
			}
		})
	}
}
func TestStoreUniquenessAndModes(t *testing.T) {
	c := configFixture()
	s := storeFixture()
	s.Spec.Bindings = append(s.Spec.Bindings, s.Spec.Bindings[0])
	if installation.Reason(ValidateStore(c, s)) != "BindingConflict" {
		t.Fatal("duplicate bindings accepted")
	}
	s = storeFixture()
	other := s.DeepCopy()
	other.Name = "other"
	other.UID = "88888888-8888-4888-8888-888888888888"
	if installation.Reason(ValidateBindings(c, []api.SekvyrStore{*s, *other})) != "BindingConflict" {
		t.Fatal("cross-store target/resource collision accepted")
	}
	s = storeFixture()
	b := &s.Spec.Bindings[0]
	b.Encryption = api.Encryption{Mode: "E2E", Protocol: "e2e2", TrustKey: "app", Freshness: &api.Freshness{Mode: "WitnessCurrent"}}
	b.Source.ViewID = "99999999-9999-4999-8999-999999999999"
	if err := ValidateStore(c, s); err != nil {
		t.Fatal(err)
	}
	b.Encryption.Protocol = "e2e1"
	if ValidateStore(c, s) == nil {
		t.Fatal("e2e1 downgrade accepted")
	}
	s = storeFixture()
	s.Spec.Bindings[0].Selection = api.Selection{Mode: "Keys", Keys: []api.SelectedKey{{Path: "/db", Name: "A", TargetKey: "A"}, {Path: "/db", Name: "B", TargetKey: "A"}}}
	if installation.Reason(ValidateStore(c, s)) != "BindingConflict" {
		t.Fatal("duplicate target keys accepted")
	}
}
func TestCanonicalMetadata(t *testing.T) {
	for _, good := range []string{"/", "/db", "/db/replica", "/caf\u00e9"} {
		if !canonicalPath(good) {
			t.Fatal("canonical path refused")
		}
	}
	for _, bad := range []string{"", "db", "//", "/db/", "/db//x", "/db/../x", "/./x", "/db\\x", "/x\x7f", "/x\u0085", "/x\u202e", "/x\u200b", "/cafe\u0301", "/x" + string([]byte{255})} {
		if canonicalPath(bad) {
			t.Fatal("noncanonical path accepted")
		}
	}
	for _, bad := range []string{"A\x7f", "A\u0085", "A\u202e", "A\u200b", "cafe\u0301"} {
		s := storeFixture()
		s.Spec.Bindings[0].Selection = api.Selection{Mode: "Keys", Keys: []api.SelectedKey{{Path: "/", Name: bad, TargetKey: "A"}}}
		if ValidateStore(configFixture(), s) == nil {
			t.Fatal("noncanonical source name accepted")
		}
	}
	if within("/database", "/db") {
		t.Fatal("prefix was not segment aware")
	}
}

type scopeReader struct {
	client.Reader
	namespace string
	calls     int
}

func (r *scopeReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	r.calls++
	if key.Namespace != r.namespace {
		panic("forbidden namespace read")
	}
	return r.Reader.Get(ctx, key, object, options...)
}
func (r *scopeReader) List(ctx context.Context, objects client.ObjectList, options ...client.ListOption) error {
	r.calls++
	opts := &client.ListOptions{}
	opts.ApplyOptions(options)
	if opts.Namespace != r.namespace {
		panic("cluster-wide list")
	}
	return r.Reader.List(ctx, objects, options...)
}
func fakeRuntime(t *testing.T) (*Reconciler, client.Client, *scopeReader) {
	t.Helper()
	c := configFixture()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	objects := []client.Object{storeFixture(), secretFixture()}
	immutable := true
	for i, pin := range []installation.SecretPin{c.IdentityKeySecret, c.TrustBundleSecret, c.StateSecret} {
		data := []byte("test-only-bootstrap-placeholder")
		if i == 2 {
			data, _ = json.Marshal(installation.StateMarker{InstallationID: c.InstallationID, BootstrapGeneration: c.BootstrapGeneration})
		}
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: pin.Name, Namespace: c.Namespace, UID: types.UID(pin.UID)}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{pin.Key: data}}
		if i < 2 {
			s.Immutable = &immutable
		}
		objects = append(objects, s)
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&api.SekvyrStore{}, &api.SekvyrSecret{}).WithObjects(objects...).Build()
	reader := &scopeReader{Reader: fakeClient, namespace: c.Namespace}
	return &Reconciler{Client: fakeClient, APIReader: reader, Installation: c, Namespace: c.Namespace, ServiceAccount: c.ServiceAccount}, fakeClient, reader
}
func TestReconcileScaffoldNeverReadyOrCreatesTarget(t *testing.T) {
	r, c, _ := fakeRuntime(t)
	ctx := context.Background()
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: r.Namespace, Name: "app"}})
	if err != nil {
		t.Fatal(err)
	}
	var secret api.SekvyrSecret
	if err := c.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: "app"}, &secret); err != nil {
		t.Fatal(err)
	}
	ready := meta.FindStatusCondition(secret.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "VerificationNotImplemented" {
		t.Fatal("false readiness assertion")
	}
	bootstrap := meta.FindStatusCondition(secret.Status.Conditions, "BootstrapReady")
	if bootstrap == nil || bootstrap.Status != metav1.ConditionTrue || bootstrap.Reason != "BootstrapMetadataValid" {
		t.Fatal("metadata result missing")
	}
	witness := meta.FindStatusCondition(secret.Status.Conditions, "WitnessReady")
	if witness == nil || witness.Status != metav1.ConditionUnknown || witness.Reason != "NotImplemented" {
		t.Fatal("unimplemented witness trusted")
	}
	var objects corev1.SecretList
	if err := c.List(ctx, &objects, client.InNamespace(r.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(objects.Items) != 3 {
		t.Fatal("scaffold wrote a target Secret")
	}
	if secret.Status.LastSuccessfulSyncTime != nil || secret.Status.LastVerifiedCheckpoint != nil || secret.Status.LastAppliedRevision != "" {
		t.Fatal("scaffold claimed data verification")
	}
}
func TestForbiddenNamespaceRejectedBeforeAPIAccess(t *testing.T) {
	r, _, reader := fakeRuntime(t)
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "other", Name: "app"}})
	if err != nil || reader.calls != 0 {
		t.Fatal("out-of-scope reconcile reached API")
	}
}

type replaceAfterRead struct {
	client.Client
	key client.ObjectKey
}

func (r *replaceAfterRead) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := r.Client.Get(ctx, key, obj, opts...); err != nil || key != r.key {
		return err
	}
	replacement := obj.DeepCopyObject().(client.Object)
	if err := r.Client.Delete(ctx, replacement); err != nil {
		return err
	}
	replacement.SetUID("88888888-8888-4888-8888-888888888888")
	replacement.SetResourceVersion("")
	return r.Client.Create(ctx, replacement)
}

func TestReconcileDoesNotWriteStatusToReplacement(t *testing.T) {
	for _, obj := range []client.Object{secretFixture(), storeFixture()} {
		t.Run(obj.GetName(), func(t *testing.T) {
			r, c, _ := fakeRuntime(t)
			ctx := context.Background()
			key := client.ObjectKeyFromObject(obj)
			r.APIReader = &replaceAfterRead{Client: c, key: key}
			var reconciler interface {
				Reconcile(context.Context, ctrl.Request) (ctrl.Result, error)
			} = r
			if _, ok := obj.(*api.SekvyrStore); ok {
				reconciler = &StoreReconciler{Reconciler: r}
			}
			if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, key, obj); err != nil {
				t.Fatal(err)
			}
			if obj.GetUID() != "88888888-8888-4888-8888-888888888888" {
				t.Fatal("fixture did not replace the object")
			}
			var status api.ResourceStatus
			switch typed := obj.(type) {
			case *api.SekvyrSecret:
				status = typed.Status
			case *api.SekvyrStore:
				status = typed.Status
			}
			if status.ObservedGeneration != 0 || len(status.Conditions) != 0 {
				t.Fatal("reconciliation published the old object's status on its replacement")
			}
		})
	}
}
func TestSuspendedAndMissingStateStayClosed(t *testing.T) {
	for _, suspended := range []bool{false, true} {
		r, c, reader := fakeRuntime(t)
		ctx := context.Background()
		q := secretFixture()
		if suspended {
			var current api.SekvyrSecret
			_ = c.Get(ctx, client.ObjectKeyFromObject(q), &current)
			current.Spec.Suspend = true
			_ = c.Update(ctx, &current)
		} else {
			_ = c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "state", Namespace: r.Namespace}})
		}
		_, _ = r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(q)})
		var result api.SekvyrSecret
		_ = c.Get(ctx, client.ObjectKeyFromObject(q), &result)
		condition := meta.FindStatusCondition(result.Status.Conditions, "Ready")
		expected := "StateMissing"
		if suspended {
			expected = "Suspended"
			if reader.calls != 1 {
				t.Fatal("suspended reconcile read bootstrap/source")
			}
		}
		if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != expected {
			t.Fatal("failure state not reflected")
		}
	}
}
