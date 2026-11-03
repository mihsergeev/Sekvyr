package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"testing"
)

func TestSchemeAndDeepCopyDoNotAliasMutableFields(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	object, err := scheme.New(GroupVersion.WithKind("SekvyrStore"))
	if err != nil {
		t.Fatal(err)
	}
	store := object.(*SekvyrStore)
	required := true
	store.Spec.Endpoint.CAConfigMapRef = &ConfigMapKeyRef{Name: "ca", Key: "ca.crt"}
	store.Spec.Bindings = []Binding{{Selection: Selection{Mode: "Keys", Keys: []SelectedKey{{Name: "A", Required: &required}}}, Encryption: Encryption{Freshness: &Freshness{Mode: "WitnessCurrent"}}, Rollout: BindingRollout{AllowedDeployments: []string{"app"}}}}
	store.Status.Conditions = []metav1.Condition{{Type: "Ready", Reason: "ScaffoldOnly"}}
	copy := store.DeepCopy()
	copy.Spec.Endpoint.CAConfigMapRef.Name = "other"
	*copy.Spec.Bindings[0].Selection.Keys[0].Required = false
	copy.Spec.Bindings[0].Encryption.Freshness.Mode = "other"
	copy.Spec.Bindings[0].Rollout.AllowedDeployments[0] = "other"
	copy.Status.Conditions[0].Reason = "other"
	if store.Spec.Endpoint.CAConfigMapRef.Name != "ca" || !*store.Spec.Bindings[0].Selection.Keys[0].Required || store.Spec.Bindings[0].Encryption.Freshness.Mode != "WitnessCurrent" || store.Spec.Bindings[0].Rollout.AllowedDeployments[0] != "app" || store.Status.Conditions[0].Reason != "ScaffoldOnly" {
		t.Fatal("deep copy aliases API state")
	}
}
