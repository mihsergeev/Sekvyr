package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/fencing"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestBootstrapFailureReportsSafeReasonAndRedactsUpstream(t *testing.T) {
	if got := bootstrapFailure(&fencing.Error{Reason: "MaterialReplaced"}).Error(); got != "fencer: MaterialReplaced" {
		t.Fatal("public reason lost")
	}
	upstream := strings.Repeat("sensitive-upstream-", 4)
	if got := bootstrapFailure(errors.New(upstream)).Error(); got != "fencer: FencingUnavailable" || strings.Contains(got, upstream) {
		t.Fatal("raw upstream details leaked")
	}
}

func TestGatewayCARequiresPinnedImmutableConfigMap(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	digest, err := installation.CertificateSetSHA256(ca)
	if err != nil {
		t.Fatal(err)
	}
	config := fencing.Config{Namespace: "apps", GatewayCAPin: installation.CAPin{
		Name: "gateway-ca", UID: "55555555-5555-4555-8555-555555555555", Key: "ca.crt", DERSetSHA256: digest,
	}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	immutable := true
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.ConfigMap)
	}{
		{name: "pinned"},
		{name: "recreated", mutate: func(cm *corev1.ConfigMap) { cm.UID = "66666666-6666-4666-8666-666666666666" }},
		{name: "mutable", mutate: func(cm *corev1.ConfigMap) { cm.Immutable = nil }},
		{name: "terminating", mutate: func(cm *corev1.ConfigMap) {
			deleted := metav1.Now()
			cm.DeletionTimestamp = &deleted
			cm.Finalizers = []string{"example.test/finalizer"}
		}},
		{name: "wrong CA", mutate: func(cm *corev1.ConfigMap) { cm.Data["ca.crt"] = "unexpected CA" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "gateway-ca", UID: "55555555-5555-4555-8555-555555555555"},
				Immutable: &immutable, Data: map[string]string{"ca.crt": string(ca)}}
			if tc.mutate != nil {
				tc.mutate(cm)
			}
			reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()
			got, err := gatewayCABytes(context.Background(), reader, config)
			if tc.mutate == nil {
				if err != nil || !bytes.Equal(got, ca) {
					t.Fatalf("expected the pinned bytes, error=%v", err)
				}
			} else if err == nil || err.Error() != "fencer: GatewayCAPinMismatch" || got != nil {
				t.Fatal("unexpected ConfigMap accepted as the gateway CA", err)
			}
		})
	}
}
