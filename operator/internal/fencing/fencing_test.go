package fencing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// These deterministic keys and opaque IDs are PUBLIC UNIT FIXTURES. They never
// represent a real installation. This double does not simulate or claim WORM.
func uid(n int) string { return fmt.Sprintf("10000000-0000-4000-8000-%012d", n) }
func publicKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}

type memoryLedger struct {
	state                      journal.CurrentState
	failure                    error
	conflicts                  int
	onConflict                 func()
	grants, activations, reads int
}

func (l *memoryLedger) ReadCurrent(context.Context, string, journal.Cursor) (journal.CurrentState, error) {
	l.reads++
	if l.failure != nil {
		return journal.CurrentState{}, l.failure
	}
	raw, _ := json.Marshal(l.state)
	var copy journal.CurrentState
	_ = json.Unmarshal(raw, &copy)
	return copy, nil
}
func (l *memoryLedger) AppendFenceGrantCAS(ctx context.Context, _ string, expected journal.Cursor, raw []byte) (journal.CurrentState, error) {
	l.grants++
	if l.conflicts > 0 {
		l.conflicts--
		if l.onConflict != nil {
			l.onConflict()
		}
		return journal.CurrentState{}, journal.Failure("CASConflict")
	}
	if expected != l.state.Cursor {
		return journal.CurrentState{}, journal.Failure("CASConflict")
	}
	var grant journal.SignedFenceGrant
	if journal.DecodeStrict(raw, &grant, maxWireBytes) != nil || journal.VerifyFenceGrant(grant, l.state.Authority) != nil {
		return journal.CurrentState{}, journal.Failure("GrantInvalid")
	}
	l.state.Grants[grant.Body.InstallationID] = grant
	l.advance()
	return l.ReadCurrent(ctx, "", journal.Cursor{})
}
func (l *memoryLedger) AppendFenceActivationCAS(ctx context.Context, _ string, expected journal.Cursor, raw []byte) (journal.CurrentState, error) {
	l.activations++
	if expected != l.state.Cursor {
		return journal.CurrentState{}, journal.Failure("CASConflict")
	}
	var activation journal.SignedFenceActivation
	if journal.DecodeStrict(raw, &activation, maxWireBytes) != nil || journal.VerifyFenceActivation(activation, l.state.Authority) != nil {
		return journal.CurrentState{}, journal.Failure("ActivationInvalid")
	}
	l.state.Activations[activation.Body.InstallationID] = activation
	l.advance()
	return l.ReadCurrent(ctx, "", journal.Cursor{})
}
func (l *memoryLedger) advance() {
	l.state.Cursor = journal.Cursor{JournalSequence: fmt.Sprint(l.grants + l.activations), RecordHash: strings.Repeat("a", 64)}
}

type fixedAuth struct{ identity Identity }

func (a fixedAuth) Authenticate(context.Context, string, journal.Enrollment) (Identity, error) {
	return a.identity, nil
}

type fixture struct {
	service   *Service
	ledger    *memoryLedger
	kube      client.Client
	identity  Identity
	holder    string
	refs      []journal.ObjectRef
	namespace string
	now       time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ns := "trial-apps"
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	identity := Identity{Namespace: ns, ServiceAccount: "operator", ServiceAccountUID: uid(2), PodName: "operator-a", PodUID: uid(10)}
	holder := identity.PodName + "_" + uid(11)
	refs, err := journal.CanonicalObjectRefs([]journal.ObjectRef{{APIVersion: "v1", Kind: "Secret", Namespace: ns, Name: "state", UID: uid(7)},
		{APIVersion: "v1", Kind: "Secret", Namespace: ns, Name: "target", UID: uid(8)},
		{APIVersion: "apps/v1", Kind: "Deployment", Namespace: ns, Name: "app", UID: uid(9)}})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := journal.Enrollment{InstallationID: uid(20), BootstrapGeneration: 1, Namespace: ns, NamespaceUID: uid(1), OperatorServiceAccount: "operator", OperatorServiceAccountUID: uid(2),
		FencerServiceAccount: "fencer", FencerServiceAccountUID: uid(3), Lease: journal.ObjectRef{APIVersion: "coordination.k8s.io/v1", Kind: "Lease", Namespace: ns, Name: "leader", UID: uid(4)},
		IdentityKeySecretUID: uid(5), TrustBundleSecretUID: uid(6), NodeFingerprint: "p256-sha256:" + strings.Repeat("b", 64), AllowedObjects: refs}
	key, _ := journal.KeyFromPublic(publicKey(1).Public().(ed25519.PublicKey))
	state := journal.CurrentState{Scope: e2e2.Scope{RealmID: uid(21), ProjectID: uid(22), EnvironmentID: uid(23), ViewID: uid(24), LogID: uid(25)},
		GenesisHash: strings.Repeat("c", 64), Cursor: journal.Cursor{JournalSequence: "0", RecordHash: strings.Repeat("c", 64)}, AuthorityDigest: strings.Repeat("d", 64),
		Snapshot:  journal.Snapshot{Sequence: "1", EnvelopeHash: strings.Repeat("e", 64), ReadKeyEpoch: "1", PublisherPolicyEpoch: "1"},
		Authority: journal.Authority{FencerKeys: []journal.Key{key}}, Enrollments: map[string]journal.Enrollment{uid(20): enrollment}, Grants: map[string]journal.SignedFenceGrant{}, Activations: map[string]journal.SignedFenceActivation{}}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = coordinationv1.AddToScheme(scheme)
	duration := int32(15)
	objects := []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, UID: types.UID(uid(1))}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "operator", Namespace: ns, UID: types.UID(uid(2))}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: identity.PodName, Namespace: ns, UID: types.UID(identity.PodUID)}, Spec: corev1.PodSpec{ServiceAccountName: "operator"}},
		&coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "leader", Namespace: ns, UID: types.UID(uid(4))}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, RenewTime: &metav1.MicroTime{Time: now.Add(-time.Second)}}}}
	for _, ref := range refs {
		object, _ := objectFor(ref)
		object.GetObjectKind().SetGroupVersionKind(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind))
		object.SetName(ref.Name)
		object.SetNamespace(ns)
		object.SetUID(types.UID(ref.UID))
		object.SetResourceVersion("1")
		if secret, ok := object.(*corev1.Secret); ok {
			secret.Data = map[string][]byte{"value": []byte("PUBLIC_UNIT_FIXTURE")}
		}
		objects = append(objects, object)
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	ledger := &memoryLedger{state: state}
	service := &Service{Config: Config{Trial: true, InstallationID: uid(20), LogID: uid(25), MinimumCursor: state.Cursor, Namespace: ns, NamespaceUID: uid(1), OperatorServiceAccountUID: uid(2), LeaseUID: uid(4), FencerServiceAccount: "fencer", FencerServiceAccountUID: uid(3),
		BootstrapSubjects: []Subject{{Username: "trial-bootstrap", UID: ""}}, ManagedObjects: refs}, Journal: ledger, Reader: kube, Writer: kube, Auth: fixedAuth{identity}, SigningKey: publicKey(1), Now: func() time.Time { return now }}
	return &fixture{service: service, ledger: ledger, kube: kube, identity: identity, holder: holder, refs: refs, namespace: ns, now: now}
}

func (f *fixture) acquire(t *testing.T) *Session {
	t.Helper()
	session, err := f.service.Acquire(context.Background(), "public-fixture-token", 1, f.holder)
	if err != nil {
		t.Fatal(err)
	}
	return session
}
func (f *fixture) active(t *testing.T) *Session {
	t.Helper()
	session := f.acquire(t)
	ready, err := f.service.Barriers(context.Background(), "public-fixture-token", session.hash)
	if err != nil {
		t.Fatal(err)
	}
	return ready
}
func (f *fixture) secret(t *testing.T) *corev1.Secret {
	t.Helper()
	var target corev1.Secret
	if err := f.kube.Get(context.Background(), types.NamespacedName{Namespace: f.namespace, Name: "target"}, &target); err != nil {
		t.Fatal(err)
	}
	target.APIVersion = "v1"
	target.Kind = "Secret"
	return &target
}

func requestFor(old, next client.Object, user authenticationv1.UserInfo) *admissionv1.AdmissionRequest {
	before, _ := json.Marshal(old)
	after, _ := json.Marshal(next)
	return &admissionv1.AdmissionRequest{UID: types.UID(uid(99)), Name: old.GetName(), Namespace: old.GetNamespace(), Operation: admissionv1.Update,
		Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Secret"}, Resource: metav1.GroupVersionResource{Version: "v1", Resource: "secrets"},
		OldObject: runtime.RawExtension{Raw: before}, Object: runtime.RawExtension{Raw: after}, UserInfo: user}
}
func (f *fixture) operator() authenticationv1.UserInfo {
	return authenticationv1.UserInfo{Username: serviceAccountUser(f.namespace, "operator"), UID: uid(2), Extra: map[string]authenticationv1.ExtraValue{podUIDExtra: {f.identity.PodUID}, podNameExtra: {f.identity.PodName}}}
}

func TestActivationRequiresEveryBarrier(t *testing.T) {
	f := newFixture(t)
	session := f.acquire(t)
	if _, _, err := currentGrant(f.ledger.state, uid(20), true); Reason(err) != "BarriersIncomplete" {
		t.Fatal("pending grant became active")
	}
	before := f.secret(t)
	before.Annotations = map[string]string{FenceAnnotation: session.fence}
	if err := Writer(f.kube, session).Update(context.Background(), before); Reason(err) != "BarriersIncomplete" {
		t.Fatal("pending client wrote data")
	}
	f.service.Writer = &failureWriter{Client: f.kube, name: "target"}
	if _, err := f.service.Barriers(context.Background(), "public-fixture-token", session.hash); err == nil {
		t.Fatal("partial barriers activated")
	}
	if f.ledger.activations != 0 {
		t.Fatal("activation attempted after failed barrier")
	}
	f.service.Writer = f.kube
	ready, err := f.service.Barriers(context.Background(), "public-fixture-token", session.hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ready.ready || f.ledger.activations != 1 {
		t.Fatal("complete barriers did not activate once")
	}
	if _, err = f.service.Barriers(context.Background(), "public-fixture-token", session.hash); err != nil || f.ledger.activations != 1 {
		t.Fatal("idempotent barriers reactivated")
	}
}

type failureWriter struct {
	client.Client
	name string
}

func (w *failureWriter) Patch(ctx context.Context, obj client.Object, p client.Patch, options ...client.PatchOption) error {
	if obj.GetName() == w.name {
		return errors.New("public test failure")
	}
	return w.Client.Patch(ctx, obj, p, options...)
}

func TestAcquireFreshLeaseOnCASConflictAndFixedProcessIdentity(t *testing.T) {
	f := newFixture(t)
	f.ledger.conflicts = 1
	f.ledger.onConflict = func() {
		var lease coordinationv1.Lease
		_ = f.kube.Get(context.Background(), types.NamespacedName{Namespace: f.namespace, Name: "leader"}, &lease)
		next := f.identity.PodName + "_" + uid(12)
		lease.Spec.HolderIdentity = &next
		_ = f.kube.Update(context.Background(), &lease)
	}
	if _, err := f.service.Acquire(context.Background(), "public-fixture-token", 1, f.holder); Reason(err) != "LeaseMismatch" {
		t.Fatalf("stale process reacquired: %v", err)
	}
	if f.ledger.grants != 1 {
		t.Fatal("CAS retry ignored new holder")
	}
}

func TestSamePodNewHolderAdvancesTermAndOldWriterNeverAdoptsNewFence(t *testing.T) {
	f := newFixture(t)
	old := f.active(t)
	var lease coordinationv1.Lease
	_ = f.kube.Get(context.Background(), types.NamespacedName{Namespace: f.namespace, Name: "leader"}, &lease)
	f.holder = f.identity.PodName + "_" + uid(12)
	lease.Spec.HolderIdentity = &f.holder
	_ = f.kube.Update(context.Background(), &lease)
	newSession := f.active(t)
	if old.hash == newSession.hash || newSession.grant.Body.Term != "2" {
		t.Fatal("same-pod new process reused old term")
	}
	target := f.secret(t)
	if err := Writer(f.kube, old).Update(context.Background(), target); Reason(err) != "FenceMismatch" {
		t.Fatal("old writer adopted GET fence")
	}
	if err := Writer(f.kube, newSession).Update(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if target.Annotations[WriteSessionAnnotation] != newSession.hash {
		t.Fatal("writer copied stale request session")
	}
}

func TestSnapshotAdvanceRequiresNewGrantAndBarriersWithoutDataOrPodTemplateChange(t *testing.T) {
	f := newFixture(t)
	old := f.active(t)
	before := f.secret(t)
	next := before.DeepCopy()
	next.Annotations[WriteSessionAnnotation] = old.hash
	f.ledger.state.Snapshot = journal.Snapshot{Sequence: "2", EnvelopeHash: strings.Repeat("f", 64), ReadKeyEpoch: "1", PublisherPolicyEpoch: "1"}
	if f.service.Admit(context.Background(), requestFor(before, next, f.operator())).Allowed {
		t.Fatal("old snapshot grant admitted")
	}
	var deployment appsv1.Deployment
	_ = f.kube.Get(context.Background(), types.NamespacedName{Namespace: f.namespace, Name: "app"}, &deployment)
	template := deployment.Spec.Template.DeepCopy()
	fresh := f.active(t)
	if fresh.grant.Body.Term != "2" || fresh.hash == old.hash || fresh.grant.Body.Snapshot != f.ledger.state.Snapshot {
		t.Fatal("canonical advance reused grant")
	}
	if !reflect.DeepEqual(before.Data, f.secret(t).Data) {
		t.Fatal("fencing changed data")
	}
	_ = f.kube.Get(context.Background(), types.NamespacedName{Namespace: f.namespace, Name: "app"}, &deployment)
	if !reflect.DeepEqual(template, &deployment.Spec.Template) {
		t.Fatal("fencing changed pod template")
	}
	if err := Writer(f.kube, old).Update(context.Background(), f.secret(t)); Reason(err) != "FenceMismatch" {
		t.Fatal("old session adopted current fence")
	}
}

func TestAdmissionRejectsStaleOrUnboundActorAndJournalOutage(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	old := f.secret(t)
	next := old.DeepCopy()
	next.Data["value"] = []byte("PUBLIC_CHANGED")
	next.Annotations[WriteSessionAnnotation] = session.hash
	request := requestFor(old, next, f.operator())
	if response := f.service.Admit(context.Background(), request); !response.Allowed {
		t.Fatal(response.Result.Message)
	}
	for _, mutation := range []func(*admissionv1.AdmissionRequest){
		func(r *admissionv1.AdmissionRequest) { r.UserInfo.Extra = nil },
		func(r *admissionv1.AdmissionRequest) {
			r.UserInfo.Extra[podUIDExtra] = authenticationv1.ExtraValue{uid(33)}
		},
		func(r *admissionv1.AdmissionRequest) { r.UserInfo.UID = uid(34) },
		func(r *admissionv1.AdmissionRequest) { r.Operation = admissionv1.Create },
		func(r *admissionv1.AdmissionRequest) { r.SubResource = "status" },
	} {
		copy := request.DeepCopy()
		mutation(copy)
		if f.service.Admit(context.Background(), copy).Allowed {
			t.Fatal("forged actor admitted")
		}
	}
	f.ledger.failure = errors.New("PRIVATE UPSTREAM BODY MUST NOT LEAK")
	response := f.service.Admit(context.Background(), request)
	if response.Allowed || strings.Contains(response.Result.Message, "PRIVATE") {
		t.Fatal("journal outage did not fail closed safely")
	}
}

func TestAdmissionOrdinaryCannotChangeFenceAndFencerCannotChangeData(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	old := f.secret(t)
	next := old.DeepCopy()
	next.Annotations[WriteSessionAnnotation] = session.hash
	next.Annotations[FenceAnnotation] = "forged"
	if f.service.Admit(context.Background(), requestFor(old, next, f.operator())).Allowed {
		t.Fatal("operator changed fence")
	}
	without := old.DeepCopy()
	delete(without.Annotations, FenceAnnotation)
	fencer := authenticationv1.UserInfo{Username: serviceAccountUser(f.namespace, "fencer"), UID: uid(3)}
	if !f.service.Admit(context.Background(), requestFor(without, old, fencer)).Allowed {
		t.Fatal("valid fence-only barrier denied")
	}
	changed := old.DeepCopy()
	changed.Data["value"] = []byte("FORBIDDEN_PUBLIC_FIXTURE")
	if f.service.Admit(context.Background(), requestFor(without, changed, fencer)).Allowed {
		t.Fatal("fencer changed Secret data")
	}
	changed = old.DeepCopy()
	changed.ResourceVersion = "different"
	if f.service.Admit(context.Background(), requestFor(without, changed, fencer)).Allowed {
		t.Fatal("barrier omitted exact resourceVersion")
	}
}

func TestBarrierDoesNotTouchPlaintextOrDeploymentTemplate(t *testing.T) {
	f := newFixture(t)
	before := f.secret(t).Data
	var deployment appsv1.Deployment
	_ = f.kube.Get(context.Background(), types.NamespacedName{Namespace: f.namespace, Name: "app"}, &deployment)
	template := deployment.Spec.Template.DeepCopy()
	f.active(t)
	if !reflect.DeepEqual(before, f.secret(t).Data) {
		t.Fatal("barrier changed Secret bytes")
	}
	_ = f.kube.Get(context.Background(), types.NamespacedName{Namespace: f.namespace, Name: "app"}, &deployment)
	if !reflect.DeepEqual(template, &deployment.Spec.Template) {
		t.Fatal("barrier restarted workload")
	}
}

func TestWriteAPIsWithoutSafeCASAreExplicitlyDenied(t *testing.T) {
	f := newFixture(t)
	writer := Writer(f.kube, f.active(t))
	ctx := context.Background()
	target := f.secret(t)
	for _, err := range []error{writer.Create(ctx, target), writer.Delete(ctx, target), writer.DeleteAllOf(ctx, target), writer.Apply(ctx, nil),
		writer.Status().Update(ctx, target), writer.Status().Apply(ctx, nil), writer.SubResource("scale").Patch(ctx, target, nil)} {
		if err == nil {
			t.Fatal("mutating API bypassed fixed session")
		}
	}
}

func TestCodecAndRedaction(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	for _, value := range []any{f.service, session, Writer(f.kube, session)} {
		printed := fmt.Sprintf("%v %#v", value, value)
		if strings.Contains(printed, string(f.service.SigningKey)) || strings.Contains(printed, session.hash) || !strings.Contains(printed, "redacted") {
			t.Fatal("sensitive object formatting")
		}
	}
	if _, err := DecodeFence(session.fence); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{strings.Replace(session.fence, `"term":"1"`, `"term":"01"`, 1), session.fence + " ", `{"term":null}`} {
		if _, err := DecodeFence(raw); err == nil {
			t.Fatal("noncanonical fence accepted")
		}
	}
}
