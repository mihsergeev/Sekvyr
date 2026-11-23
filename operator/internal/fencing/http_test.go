package fencing

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestTokenReviewBindsAudiencePodServiceAccountAndNamespace(t *testing.T) {
	for _, name := range []string{"valid", "wrong-audience", "unbound", "wrong-pod", "wrong-sa-uid", "denied"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			enrollment := f.ledger.state.Enrollments[uid(20)]
			api := kubefake.NewClientset()
			api.PrependReactor("create", "tokenreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
				input := action.(ktesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
				if len(input.Spec.Audiences) != 1 || input.Spec.Audiences[0] != TokenAudience {
					t.Fatal("wrong TokenReview audience")
				}
				status := authenticationv1.TokenReviewStatus{Authenticated: true, Audiences: []string{TokenAudience}, User: f.operator()}
				switch name {
				case "wrong-audience":
					status.Audiences = []string{"api"}
				case "unbound":
					status.User.Extra = nil
				case "wrong-pod":
					status.User.Extra[podUIDExtra] = authenticationv1.ExtraValue{uid(45)}
				case "wrong-sa-uid":
					status.User.UID = uid(46)
				case "denied":
					status.Authenticated = false
					status.Error = "PRIVATE_UPSTREAM_BODY"
				}
				return true, &authenticationv1.TokenReview{Status: status}, nil
			})
			auth := TokenAuthenticator{Client: api, Reader: f.kube}
			identity, err := auth.Authenticate(context.Background(), "public-unit-token", enrollment)
			if name == "valid" {
				if err != nil || identity != f.identity {
					t.Fatal("valid bound token rejected", err)
				}
			} else if err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("bad identity admitted or leaked detail")
			}
		})
	}
}

type forbiddenReader struct{ calls int }

func (r *forbiddenReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	r.calls++
	return errors.New("forbidden cross-object get")
}
func (r *forbiddenReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	r.calls++
	return errors.New("forbidden cross-object list")
}

func TestAdmissionUsesOnlineJournalAndNoOtherObjectOrLeaseGET(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	old := f.secret(t)
	next := old.DeepCopy()
	next.Annotations[WriteSessionAnnotation] = session.hash
	reader := &forbiddenReader{}
	f.service.Reader = reader
	if !f.service.Admit(context.Background(), requestFor(old, next, f.operator())).Allowed {
		t.Fatal("valid write rejected")
	}
	if reader.calls != 0 {
		t.Fatal("admission read another Kubernetes object")
	}
	f.ledger.failure = errors.New("offline")
	if f.service.Admit(context.Background(), requestFor(old, next, f.operator())).Allowed {
		t.Fatal("admission reused cached journal decision")
	}
}

func TestRealTLSClientAcquireBarrierReadyAndTokenFileRotation(t *testing.T) {
	f := newFixture(t)
	server := httptest.NewTLSServer(f.service)
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	file := filepath.Join(t.TempDir(), "projected-token")
	if err := os.WriteFile(file, []byte("public-unit-token"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientConfig{Origin: server.URL, AllowedOrigins: []string{server.URL}, CustomCAPEM: ca, TokenFile: file,
		PodUID: f.identity.PodUID, InstallationID: uid(20), LogID: uid(25), MinimumCursor: f.ledger.state.Cursor, ExpectedLeaseHolderIdentity: f.holder, Journal: f.ledger})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	pending, err := client.Acquire(context.Background(), uid(20), 1)
	if err != nil {
		t.Fatal(err)
	}
	if pending.ready {
		t.Fatal("acquire activated before barriers")
	}
	ready, err := client.Barriers(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Ready(context.Background(), ready); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, []byte("invalid token with whitespace"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = client.Ready(context.Background(), ready); Reason(err) != "ProjectedTokenInvalid" {
		t.Fatal("client cached projected bearer")
	}
}

func TestAdmissionReviewV1WireAndMalformedRequestsFailClosed(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	old := f.secret(t)
	next := old.DeepCopy()
	next.Annotations[WriteSessionAnnotation] = session.hash
	review := admissionv1.AdmissionReview{TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}, Request: requestFor(old, next, f.operator())}
	raw, _ := json.Marshal(review)
	request := httptest.NewRequest(http.MethodPost, "https://fencer.example.test/admit", bytes.NewReader(raw))
	result := httptest.NewRecorder()
	f.service.ServeHTTP(result, request)
	if result.Code != http.StatusOK {
		t.Fatalf("v1 request rejected: %d %s", result.Code, result.Body.String())
	}
	var response admissionv1.AdmissionReview
	if journal.DecodeStrict(result.Body.Bytes(), &response, maxAdmissionBytes) != nil || response.Response == nil || !response.Response.Allowed || response.Response.UID != review.Request.UID {
		t.Fatal("invalid admission response")
	}
	for _, payload := range [][]byte{[]byte(`{"request":null}`), append(raw, raw...), []byte(`{"kind":"AdmissionReview","kind":"AdmissionReview"}`)} {
		result = httptest.NewRecorder()
		f.service.ServeHTTP(result, httptest.NewRequest(http.MethodPost, "https://fencer.example.test/admit", bytes.NewReader(payload)))
		if result.Code == http.StatusOK {
			t.Fatal("malformed admission allowed")
		}
	}
}

func TestAdmissionAcceptsKubernetesObjectsOutsideE2E2JSONProfile(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	old := f.secret(t)
	for i := 0; i < 65; i++ {
		old.Data[fmt.Sprintf("fixture-%d", i)] = []byte("value")
	}
	next := old.DeepCopy()
	next.Annotations[WriteSessionAnnotation] = session.hash
	next.Data["fixture-0"] = []byte("updated")
	secret := requestFor(old, next, f.operator())

	var deployment appsv1.Deployment
	if err := f.kube.Get(context.Background(), client.ObjectKey{Namespace: f.namespace, Name: "app"}, &deployment); err != nil {
		t.Fatal(err)
	}
	deployment.APIVersion, deployment.Kind = "apps/v1", "Deployment"
	tolerationSeconds := int64(-1)
	deployment.Spec.Template.Spec.Tolerations = []corev1.Toleration{{Key: "fixture", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &tolerationSeconds}}
	updated := deployment.DeepCopy()
	updated.Annotations[WriteSessionAnnotation] = session.hash
	workload := requestFor(&deployment, updated, f.operator())
	workload.Kind = metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	workload.Resource = metav1.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	server := httptest.NewTLSServer(f.service)
	defer server.Close()
	check := func(t *testing.T, request *admissionv1.AdmissionRequest, allowed bool) {
		t.Helper()
		review := admissionv1.AdmissionReview{TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}, Request: request}
		raw, err := json.Marshal(review)
		if err != nil {
			t.Fatal(err)
		}
		response, err := server.Client().Post(server.URL+"/admit?timeout=10s", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var answer admissionv1.AdmissionReview
		if err := json.NewDecoder(response.Body).Decode(&answer); err != nil || response.StatusCode != http.StatusOK || answer.Response == nil || answer.Response.UID != request.UID || answer.Response.Allowed != allowed {
			t.Fatalf("admission status %d, allowed wanted %t", response.StatusCode, allowed)
		}
	}
	t.Run("wide Secret data", func(t *testing.T) { check(t, secret, true) })
	t.Run("negative Deployment toleration", func(t *testing.T) { check(t, workload, true) })
	t.Run("barrier can only change its annotation", func(t *testing.T) {
		fencer := authenticationv1.UserInfo{Username: serviceAccountUser(f.namespace, "fencer"), UID: uid(3)}
		withoutFence := old.DeepCopy()
		delete(withoutFence.Annotations, FenceAnnotation)
		check(t, requestFor(withoutFence, old, fencer), true)
		changed := old.DeepCopy()
		changed.Data["fixture-0"] = []byte("unauthorized change")
		check(t, requestFor(withoutFence, changed, fencer), false)
	})
	t.Run("barrier compares Kubernetes int64 exactly", func(t *testing.T) {
		fencer := authenticationv1.UserInfo{Username: serviceAccountUser(f.namespace, "fencer"), UID: uid(3)}
		withoutFence := deployment.DeepCopy()
		delete(withoutFence.Annotations, FenceAnnotation)
		seconds := int64(1 << 53)
		withoutFence.Spec.Template.Spec.TerminationGracePeriodSeconds = &seconds
		barrier := withoutFence.DeepCopy()
		barrier.Annotations[FenceAnnotation] = session.fence
		request := requestFor(withoutFence, barrier, fencer)
		request.Kind, request.Resource = workload.Kind, workload.Resource
		check(t, request, true)
		*barrier.Spec.Template.Spec.TerminationGracePeriodSeconds = seconds + 1
		request = requestFor(withoutFence, barrier, fencer)
		request.Kind, request.Resource = workload.Kind, workload.Resource
		check(t, request, false)
	})
	t.Run("duplicate field in object", func(t *testing.T) {
		ambiguous := secret.DeepCopy()
		ambiguous.Object.Raw = bytes.Replace(ambiguous.Object.Raw, []byte(`"data":{`), []byte(`"data":{"fixture-0":"YW1iaWd1b3Vz",`), 1)
		check(t, ambiguous, false)
	})
}

func TestClientRejectsRedirectWithoutForwardingBearer(t *testing.T) {
	f := newFixture(t)
	seen := false
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = true; _, _ = io.WriteString(w, "forbidden") }))
	defer other.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(file, []byte("public-unit-token"), 0600)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewClient(ClientConfig{Origin: server.URL, AllowedOrigins: []string{server.URL}, CustomCAPEM: ca, TokenFile: file, PodUID: uid(10),
		InstallationID: uid(20), LogID: uid(25), ExpectedLeaseHolderIdentity: f.holder, Journal: f.ledger})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.Acquire(context.Background(), uid(20), 1); Reason(err) != "RedirectDenied" || seen {
		t.Fatal("client followed redirect")
	}
}

func TestSessionWriterPatchInjectsFixedHashAndEnforcesUIDRVCAS(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	target := f.secret(t)
	target.Annotations[WriteSessionAnnotation] = "old-marker"
	writer := Writer(f.kube, session)
	patch := client.RawPatch(types.JSONPatchType, []byte(`[{"op":"replace","path":"/data/value","value":"UFVCTElDX1RFTlQ="}]`))
	if err := writer.Patch(context.Background(), target, patch); err != nil {
		t.Fatal(err)
	}
	if target.Annotations[WriteSessionAnnotation] != session.hash {
		t.Fatal("copied request marker from GET")
	}
	bad := client.RawPatch(types.JSONPatchType, []byte(`[{"op":"remove","path":"/metadata/annotations"}]`))
	if err := writer.Patch(context.Background(), target, bad); Reason(err) != "FenceMismatch" {
		t.Fatal("patch removed fixed fence")
	}
}
