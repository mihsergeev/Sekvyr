package fencing

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRealTLSAdmissionAcceptsKubernetesDeadlineWithoutBypassingFence(t *testing.T) {
	f := newFixture(t)
	session := f.active(t)
	old := f.secret(t)
	next := old.DeepCopy()
	next.Annotations[WriteSessionAnnotation] = session.hash
	review := admissionv1.AdmissionReview{TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}, Request: requestFor(old, next, f.operator())}
	raw, _ := json.Marshal(review)
	server := httptest.NewTLSServer(f.service)
	defer server.Close()
	for _, query := range []string{"", "?timeout=1s", "?timeout=30s"} {
		request, _ := http.NewRequest(http.MethodPost, server.URL+"/admit"+query, bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		before := f.ledger.reads
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var answer admissionv1.AdmissionReview
		err = json.NewDecoder(response.Body).Decode(&answer)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || answer.Response == nil || !answer.Response.Allowed || answer.Response.UID != review.Request.UID || f.ledger.reads <= before {
			t.Fatal("normal Kubernetes admission rejected or skipped online authority", query)
		}
	}
	// A valid deadline parameter never authorizes stale write-session metadata.
	next.Annotations[WriteSessionAnnotation] = "stale"
	review.Request = requestFor(old, next, f.operator())
	raw, _ = json.Marshal(review)
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/admit?timeout=30s", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var answer admissionv1.AdmissionReview
	err = json.NewDecoder(response.Body).Decode(&answer)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || answer.Response == nil || answer.Response.Allowed {
		t.Fatal("deadline bypassed fencing")
	}
}

func TestAdmissionDeadlineRejectsUnknownAmbiguousOrUnboundedQueries(t *testing.T) {
	f := newFixture(t)
	server := httptest.NewTLSServer(f.service)
	defer server.Close()
	for _, path := range []string{"/admit?", "/admit?timeout=0s", "/admit?timeout=31s", "/admit?timeout=030s", "/admit?timeout=-1s", "/admit?timeout=1ms", "/admit?timeout=1.5s", "/admit?timeout=30s&timeout=1s", "/admit?timeout=30s&extra=1", "/admit?timeout=30s&", "/admit?extra=30s", "/admit?timeout=%33%30s", "/healthz?timeout=30s", "/v1/installations/" + uid(20) + "/acquire?timeout=30s"} {
		request, _ := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader([]byte("{}")))
		request.Header.Set("Content-Type", "application/json")
		before := f.ledger.reads
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 400 || f.ledger.reads != before {
			t.Fatal("ambiguous deadline reached authority handling", path)
		}
	}
}
