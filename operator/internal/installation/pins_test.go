package installation

import (
	"context"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"testing"
)

func TestExternalAccountAndLeasePinsAreExactAndFailClosed(t *testing.T) {
	for _, scenario := range []string{"valid", "account-replaced", "lease-replaced", "lease-name", "missing-account", "missing-lease"} {
		t.Run(scenario, func(t *testing.T) {
			c := fixture()
			c.ServiceAccountUID = "55555555-5555-4555-8555-555555555555"
			c.LeaderElectionLeaseUID = "66666666-6666-4666-8666-666666666666"
			c.LeaderElectionLeaseName = "custom-leader"
			account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: c.ServiceAccount, Namespace: c.Namespace, UID: types.UID(c.ServiceAccountUID)}}
			lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: c.LeaderElectionLeaseName, Namespace: c.Namespace, UID: types.UID(c.LeaderElectionLeaseUID)}}
			switch scenario {
			case "account-replaced":
				account.UID = "77777777-7777-4777-8777-777777777777"
			case "lease-replaced":
				lease.UID = "77777777-7777-4777-8777-777777777777"
			case "lease-name":
				lease.Name = "sekvyr-operator-leader"
			}
			objects := protectedObjects(c)
			if scenario != "missing-account" {
				objects = append(objects, account)
			}
			if scenario != "missing-lease" {
				objects = append(objects, lease)
			}
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = coordinationv1.AddToScheme(scheme)
			reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
			err := c.ValidateRuntime(context.Background(), reader, c.Namespace, c.ServiceAccount)
			if scenario == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if Reason(err) != "BootstrapMismatch" {
				t.Fatal("external identity substitution accepted", err)
			}
		})
	}
	for _, scenario := range []string{"bad-account", "bad-lease", "name-only", "uid-only"} {
		c := fixture()
		switch scenario {
		case "bad-account":
			c.ServiceAccountUID = "not-a-uid"
		case "bad-lease":
			c.LeaderElectionLeaseName = "leader"
			c.LeaderElectionLeaseUID = "not-a-uid"
		case "name-only":
			c.LeaderElectionLeaseName = "leader"
		case "uid-only":
			c.LeaderElectionLeaseUID = "66666666-6666-4666-8666-666666666666"
		}
		if c.Validate() == nil {
			t.Fatal("ambiguous pin accepted", scenario)
		}
	}
}
