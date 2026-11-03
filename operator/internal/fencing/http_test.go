package fencing

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
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
