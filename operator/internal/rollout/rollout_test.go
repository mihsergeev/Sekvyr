package rollout

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type memoryGuard struct {
	auth     *Authorization
	data     map[string][]byte
	confirms int
}

func (g *memoryGuard) Confirm(_ context.Context, s *corev1.Secret, i Intent) error {
	g.confirms++
	hash, _ := Hash(i)
	if g.auth.Cancelled || hash != g.auth.IntentHash || s.Annotations[RevisionAnnotation] != i.Revision || string(s.Data["DEMO"]) != string(g.data["DEMO"]) {
		return failure("RolloutStateAmbiguous")
	}
	return nil
}
func (g *memoryGuard) Applied(_ context.Context, d DeploymentRef) (bool, error) {
	return containsRef(g.auth.Applied, d), nil
}
func (g *memoryGuard) MarkApplied(_ context.Context, d DeploymentRef) error {
	g.auth.Applied = append(g.auth.Applied, d)
	return nil
}
func (g *memoryGuard) Cancel(context.Context) error { g.auth.Cancelled = true; return nil }

type patchWriter struct {
	client.Client
	patches  int
	conflict bool
	raw      []byte
}

func (w *patchWriter) Patch(ctx context.Context, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
	w.patches++
	w.raw, _ = p.Data(obj)
	if w.conflict {
		return apierrors.NewConflict(schema.GroupResource{Resource: "deployments"}, obj.GetName(), errors.New("public-CAS-conflict"))
	}
	return w.Client.Patch(ctx, obj, p, opts...)
}

func fixture(t *testing.T) (Runner, Request, *patchWriter, *memoryGuard, time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	cr := &api.SekvyrSecret{ObjectMeta: metav1.ObjectMeta{Name: "request", Namespace: "test", UID: "request-uid", Generation: 1}, Spec: api.SekvyrSecretSpec{StoreRef: api.StoreReference{Name: "store", UID: "store-uid"}, Binding: "binding", Rollout: api.RequestedRollout{Enabled: true, Deployments: []string{"app"}}}}
	store := &api.SekvyrStore{ObjectMeta: metav1.ObjectMeta{Name: "store", Namespace: "test", UID: "store-uid", Generation: 1}}
	b := api.Binding{ID: "binding-uid", Name: "binding", Target: api.Target{Name: "target"}, Rollout: api.BindingRollout{AllowedDeployments: []string{"app"}}}
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "test", UID: "deployment-uid", Generation: 1, ResourceVersion: "1"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"unrelated": "preserve"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "public.example/test:v1", EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "target"}}}}}}}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}}
	target := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "test", UID: "target-uid"}, Data: map[string][]byte{"DEMO": []byte("public-canary")}}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(d).Build()
	policy := Policy{Enabled: true, AllowedDeployments: []string{"app"}}
	i, reason := Prepare(context.Background(), c, policy, cr, store, b, target, "11111111111111111111111111111111", 1, now.Add(-10*time.Second), nil)
	if reason != "" {
		t.Fatal(reason)
	}
	raw, _ := Encode(i)
	target.Annotations = map[string]string{IntentAnnotation: string(raw), RevisionAnnotation: i.Revision}
	if c.Create(context.Background(), target) != nil {
		t.Fatal("target fixture")
	}
	a, err := Authorize(i)
	if err != nil {
		t.Fatal(err)
	}
	guard := &memoryGuard{auth: a, data: target.Data}
	writer := &patchWriter{Client: c}
	runner := Runner{Reader: c, Writer: writer, Now: func() time.Time { return now }}
	return runner, Request{Policy: policy, CR: cr, Store: store, Binding: b, BootstrapGeneration: 1, TargetUID: string(target.UID), StrictCurrent: true, Guard: guard}, writer, guard, now
}
func authorize(context.Context) error { return nil }
func deployment(t *testing.T, r Runner) *appsv1.Deployment {
	t.Helper()
	var d appsv1.Deployment
	if err := r.Reader.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "app"}, &d); err != nil {
		t.Fatal(err)
	}
	return &d
}

func TestPrepareInitialDisabledAndDeferredUID(t *testing.T) {
	r, q, _, _, now := fixture(t)
	ctx := context.Background()
	i, why := Prepare(ctx, r.Reader, q.Policy, q.CR, q.Store, q.Binding, nil, "22222222222222222222222222222222", 1, now, nil)
	if i.Eligible || why != "InitialCreate" {
		t.Fatal("initial armed")
	}
	var target corev1.Secret
	_ = r.Reader.Get(ctx, types.NamespacedName{Namespace: "test", Name: "target"}, &target)
	q.CR.Spec.Rollout.Enabled = false
	i, why = Prepare(ctx, r.Reader, q.Policy, q.CR, q.Store, q.Binding, &target, "22222222222222222222222222222222", 1, now, nil)
	if i.Eligible || why != "Disabled" {
		t.Fatal("disabled armed")
	}
	q.CR.Spec.Rollout.Enabled = true
	q.Policy.Enabled = false
	i, _ = Prepare(ctx, r.Reader, q.Policy, q.CR, q.Store, q.Binding, &target, "22222222222222222222222222222222", 1, now, nil)
	if i.Eligible {
		t.Fatal("installation opt-in bypass")
	}
	q.Policy.Enabled = true
	q.Binding.Rollout.AllowedDeployments = nil
	i, _ = Prepare(ctx, r.Reader, q.Policy, q.CR, q.Store, q.Binding, &target, "22222222222222222222222222222222", 1, now, nil)
	if i.Eligible {
		t.Fatal("store allowlist bypass")
	}
	q.Binding.Rollout.AllowedDeployments = []string{"app"}
	d := deployment(t, r)
	_ = r.Writer.Delete(ctx, d)
	i, why = Prepare(ctx, r.Reader, q.Policy, q.CR, q.Store, q.Binding, &target, "22222222222222222222222222222222", 1, now, nil)
	if !i.Eligible || why != "DeploymentUnavailable" || i.Deployments[0].UID != "" {
		t.Fatal("candidate lost")
	}
	d.ResourceVersion = ""
	d.UID = "later-uid"
	_ = r.Writer.Create(ctx, d)
	resolved, why := Resolve(ctx, r.Reader, i)
	if why != "" || resolved.Deployments[0].UID != "later-uid" {
		t.Fatal("candidate not resolved")
	}
	resolved.Deployments[0].UID = "original-pinned-uid"
	_, why = Resolve(ctx, r.Reader, resolved)
	if why != "DeploymentReplaced" {
		t.Fatal("repinned deployment")
	}
}
func TestRunnerAnnotationOnlyCASAndDurableIdempotency(t *testing.T) {
	r, q, w, g, _ := fixture(t)
	ctx := context.Background()
	result := r.Reconcile(ctx, q, authorize)
	if w.patches != 1 || result.Reason != "RolloutProgressing" || len(g.auth.Applied) != 1 {
		t.Fatal(result, w.patches)
	}
	var operations []struct{ Op, Path string }
	if json.Unmarshal(w.raw, &operations) != nil || len(operations) != 3 || operations[0].Path != "/metadata/uid" || operations[1].Path != "/metadata/resourceVersion" || operations[2].Path != "/spec/template/metadata/annotations/secrets.sekvyr.ru~1restart-target-uid" {
		t.Fatal("patch escaped scope")
	}
	d := deployment(t, r)
	if d.Spec.Template.Annotations["unrelated"] != "preserve" || d.Spec.Template.Spec.Containers[0].Image != "public.example/test:v1" {
		t.Fatal("unrelated template changed")
	}
	// New executor process uses the durable state receipt and template marker.
	r = Runner{Reader: r.Reader, Writer: w, Now: r.Now}
	result = r.Reconcile(ctx, q, authorize)
	if !result.Ready || w.patches != 1 {
		t.Fatal("repeat restart", result)
	}
	delete(d.Spec.Template.Annotations, Annotation(q.TargetUID))
	_ = r.Writer.Update(ctx, d)
	result = r.Reconcile(ctx, q, authorize)
	if result.Reason != "RolloutMarkerChanged" || w.patches != 1 {
		t.Fatal("missing marker rearmed", result)
	}
}
func TestRunnerOutageSuspendAndChangedGenerationNeverPatch(t *testing.T) {
	for _, which := range []string{"outage", "suspend", "generation", "no-guard", "no-optin", "store-revoke"} {
		t.Run(which, func(t *testing.T) {
			r, q, w, g, _ := fixture(t)
			switch which {
			case "outage":
				q.StrictCurrent = false
			case "suspend":
				q.CR.Spec.Suspend = true
			case "generation":
				q.CR.Generation++
			case "no-guard":
				q.Guard = nil
			case "no-optin":
				q.CR.Spec.Rollout.Enabled = false
			case "store-revoke":
				q.Binding.Rollout.AllowedDeployments = nil
			}
			r.Reconcile(context.Background(), q, authorize)
			if w.patches != 0 || len(g.auth.Applied) != 0 {
				t.Fatal("unsafe restart")
			}
		})
	}
}
func TestRunnerPausedDeadlineUIDConsumptionAndRVFailures(t *testing.T) {
	for _, which := range []string{"paused", "uid", "not-consuming", "rv"} {
		t.Run(which, func(t *testing.T) {
			r, q, w, _, _ := fixture(t)
			ctx := context.Background()
			d := deployment(t, r)
			want := ""
			switch which {
			case "paused":
				d.Spec.Paused = true
				want = "DeploymentPaused"
			case "uid":
				_ = r.Writer.Delete(ctx, d)
				d.ResourceVersion = ""
				d.UID = "replacement"
				_ = r.Writer.Create(ctx, d)
				want = "DeploymentReplaced"
			case "not-consuming":
				d.Spec.Template.Spec.Containers[0].EnvFrom = nil
				want = "SecretNotConsumed"
			case "rv":
				w.conflict = true
				want = "DeploymentConflict"
			}
			if which != "uid" {
				_ = r.Writer.Update(ctx, d)
			}
			result := r.Reconcile(ctx, q, authorize)
			if result.Reason != want {
				t.Fatal(which, result)
			}
			if which != "rv" && w.patches != 0 {
				t.Fatal("blocked workload patched")
			}
		})
	}
}

func TestRunnerFailureStatusIsScopedToAppliedRevisionAndObservedGeneration(t *testing.T) {
	r, q, w, g, _ := fixture(t)
	ctx := context.Background()
	d := deployment(t, r)
	d.Spec.Template.Annotations[Annotation(q.TargetUID)] = "00000000000000000000000000000000"
	if err := r.Writer.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	d = deployment(t, r)
	d.Status.Conditions = []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded"}}
	if err := r.Writer.Status().Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	// The failed old configuration must get one attempt with the new revision.
	result := r.Reconcile(ctx, q, authorize)
	if result.Reason != "RolloutProgressing" || w.patches != 1 || len(g.auth.Applied) != 1 {
		t.Fatal("old failure blocked repair", result, w.patches)
	}
	// Fake clients do not increment Deployment generation on template mutation;
	// model that API behavior explicitly while retaining the older failed status.
	d = deployment(t, r)
	d.Generation++
	if err := r.Writer.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	result = r.Reconcile(ctx, q, authorize)
	if result.Reason != "RolloutProgressing" || w.patches != 1 {
		t.Fatal("stale status failed new revision", result, w.patches)
	}
	// Once Kubernetes observes the new generation, its failure is authoritative
	// for readiness, and does not authorize a second patch of that same revision.
	d = deployment(t, r)
	d.Status.ObservedGeneration = d.Generation
	if err := r.Writer.Status().Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	result = r.Reconcile(ctx, q, authorize)
	if result.Reason != "ProgressDeadlineExceeded" || w.patches != 1 {
		t.Fatal("current failed revision patched twice", result, w.patches)
	}
	// Even a current failure cannot make a changed marker grant another restart.
	d = deployment(t, r)
	delete(d.Spec.Template.Annotations, Annotation(q.TargetUID))
	if err := r.Writer.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	result = r.Reconcile(ctx, q, authorize)
	if result.Reason != "RolloutMarkerChanged" || w.patches != 1 {
		t.Fatal("failure bypassed receipt", result, w.patches)
	}
}
func TestDebounceMaximumAndCurrentRequiredAfterRestart(t *testing.T) {
	r, q, w, g, now := fixture(t)
	ctx := context.Background()
	var target corev1.Secret
	_ = r.Reader.Get(ctx, types.NamespacedName{Namespace: "test", Name: "target"}, &target)
	previous := g.auth
	i, _ := Prepare(ctx, r.Reader, q.Policy, q.CR, q.Store, q.Binding, &target, "22222222222222222222222222222222", 1, now, previous)
	if i.FirstChangeAt != previous.Intent.FirstChangeAt {
		t.Fatal("first deadline reset")
	}
	a, _ := Authorize(i)
	g.auth = a
	raw, _ := Encode(i)
	target.Annotations[IntentAnnotation] = string(raw)
	target.Annotations[RevisionAnnotation] = i.Revision
	_ = r.Writer.Update(ctx, &target)
	result := r.Reconcile(ctx, q, authorize)
	if result.Reason != "Debouncing" || result.RequeueAfter != 5*time.Second || w.patches != 0 {
		t.Fatal(result)
	}
	r.Now = func() time.Time { return now.Add(31 * time.Second) }
	q.StrictCurrent = false
	r.Reconcile(ctx, q, authorize)
	if w.patches != 0 {
		t.Fatal("outage retry")
	}
	q.StrictCurrent = true
	r.Reconcile(ctx, q, authorize)
	if w.patches != 1 {
		t.Fatal("pending not resumed")
	}
}
func TestConsumesOnlyActualPodSecretReferences(t *testing.T) {
	r, _, _, _, _ := fixture(t)
	d := deployment(t, r)
	if !Consumes(d, "target") {
		t.Fatal("envFrom")
	}
	d.Spec.Template.Spec.Containers = nil
	d.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "target"}}
	if Consumes(d, "target") {
		t.Fatal("pull credential counted")
	}
	d.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "config", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "target"}}}}}}}}
	if Consumes(d, "target") {
		t.Fatal("unused volume counted as consumption")
	}
	d.Spec.Template.Spec.InitContainers = []corev1.Container{{Name: "initialize", VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/config"}}}}
	if !Consumes(d, "target") {
		t.Fatal("projected secret")
	}
}

func TestMaximumDebounceCannotBeExtendedByContinuousUpdates(t *testing.T) {
	r, q, w, g, now := fixture(t)
	ctx := context.Background()
	i := g.auth.Intent
	i.FirstChangeAt = now.Add(-31 * time.Second).Format(time.RFC3339Nano)
	i.LastChangeAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	g.auth, _ = Authorize(i)
	var target corev1.Secret
	_ = r.Reader.Get(ctx, types.NamespacedName{Namespace: "test", Name: "target"}, &target)
	raw, _ := Encode(i)
	target.Annotations[IntentAnnotation] = string(raw)
	_ = r.Writer.Update(ctx, &target)
	result := r.Reconcile(ctx, q, authorize)
	if w.patches != 1 || result.Reason != "RolloutProgressing" {
		t.Fatal("maximum debounce exceeded", result)
	}
}

func TestFirstObservedNonConsumerUIDCannotBeRepinned(t *testing.T) {
	r, q, _, _, now := fixture(t)
	ctx := context.Background()
	d := deployment(t, r)
	d.Spec.Template.Spec.Containers[0].EnvFrom = nil
	if err := r.Writer.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	var target corev1.Secret
	_ = r.Reader.Get(ctx, types.NamespacedName{Namespace: "test", Name: "target"}, &target)
	i, reason := Prepare(ctx, r.Reader, q.Policy, q.CR, q.Store, q.Binding, &target, "22222222222222222222222222222222", 1, now, nil)
	if reason != "SecretNotConsumed" || i.Deployments[0].UID != "deployment-uid" {
		t.Fatal("first observed UID not pinned", reason)
	}
	_ = r.Writer.Delete(ctx, d)
	d.ResourceVersion = ""
	d.UID = "replacement"
	_ = r.Writer.Create(ctx, d)
	if _, reason = Resolve(ctx, r.Reader, i); reason != "DeploymentReplaced" {
		t.Fatal("nonconsumer replaced", reason)
	}
}

func TestDeploymentUIDPinSurvivesCompletedAndCancelledIntents(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "completed", true: "cancelled"}[cancelled], func(t *testing.T) {
			r, q, _, g, now := fixture(t)
			ctx := context.Background()
			previous := g.auth
			previous.Applied = append(previous.Applied, previous.Intent.Deployments[0])
			previous.Cancelled = cancelled
			d := deployment(t, r)
			_ = r.Writer.Delete(ctx, d)
			d.ResourceVersion = ""
			d.UID = "replacement"
			_ = r.Writer.Create(ctx, d)
			var target corev1.Secret
			_ = r.Reader.Get(ctx, types.NamespacedName{Namespace: "test", Name: "target"}, &target)
			// Even tampering with the public marker cannot discard protected UID pins.
			target.Annotations[IntentAnnotation] = "{}"
			i, reason := Prepare(ctx, r.Reader, q.Policy, q.CR, q.Store, q.Binding, &target, "22222222222222222222222222222222", 1, now, previous)
			if reason != "DeploymentReplaced" || i.Deployments[0].UID != "deployment-uid" {
				t.Fatal("completed UID repinned", reason)
			}
			if i.FirstChangeAt != now.Format(time.RFC3339Nano) {
				t.Fatal("completed debounce deadline carried")
			}
			q.CR.Generation++
			i, reason = Prepare(ctx, r.Reader, q.Policy, q.CR, q.Store, q.Binding, &target, "22222222222222222222222222222222", 1, now, previous)
			if reason != "" || i.Deployments[0].UID != "replacement" {
				t.Fatal("explicit new context did not authorize", reason)
			}
		})
	}
}
