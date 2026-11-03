package controller

import (
	"context"
	"testing"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func aggregateChild(store *api.SekvyrStore) *api.SekvyrSecret {
	child := secretFixture()
	child.Status.ObservedGeneration = child.Generation
	child.Status.ObservedStoreUID = string(store.UID)
	child.Status.ObservedStoreGeneration = store.Generation
	for _, name := range []string{"Ready", "DataCurrent", "WitnessReady", "RolloutReady"} {
		child.Status.Conditions = append(child.Status.Conditions, metav1.Condition{Type: name, Status: metav1.ConditionTrue, Reason: "Synchronized", ObservedGeneration: child.Generation})
	}
	return child
}

func aggregateResult(t *testing.T, store *api.SekvyrStore, child *api.SekvyrSecret) api.ResourceStatus {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(child).Build()
	r := &Reconciler{APIReader: reader, Namespace: store.Namespace}
	return r.aggregateStore(context.Background(), store, api.ResourceStatus{})
}

func aggregateE2EStore() *api.SekvyrStore {
	store := storeFixture()
	store.Spec.Bindings[0].Encryption = api.Encryption{Mode: "E2E", Protocol: "e2e2"}
	return store
}

func expectAggregate(t *testing.T, status api.ResourceStatus, kind string, expected metav1.ConditionStatus) {
	t.Helper()
	condition := meta.FindStatusCondition(status.Conditions, kind)
	if condition == nil || condition.Status != expected {
		t.Fatalf("aggregate %s must be %s", kind, expected)
	}
}

func TestAggregateDataFreshnessIsIndependentOfPendingRollout(t *testing.T) {
	store := aggregateE2EStore()
	child := aggregateChild(store)
	status := aggregateResult(t, store, child)
	for _, kind := range []string{"Ready", "DataCurrent", "WitnessReady", "RolloutReady"} {
		expectAggregate(t, status, kind, metav1.ConditionTrue)
	}
	child.Spec.Rollout.Enabled = true
	child.Spec.Rollout.Deployments = []string{"app"}
	for i := range child.Status.Conditions {
		if child.Status.Conditions[i].Type == "Ready" || child.Status.Conditions[i].Type == "RolloutReady" {
			child.Status.Conditions[i].Status = metav1.ConditionFalse
		}
	}
	status = aggregateResult(t, store, child)
	expectAggregate(t, status, "Ready", metav1.ConditionFalse)
	expectAggregate(t, status, "RolloutReady", metav1.ConditionFalse)
	expectAggregate(t, status, "DataCurrent", metav1.ConditionTrue)
	expectAggregate(t, status, "WitnessReady", metav1.ConditionTrue)
}

func TestAggregateRejectsAChildFromAnOlderStoreAuthorization(t *testing.T) {
	for _, name := range []string{"store-generation", "store-uid"} {
		t.Run(name, func(t *testing.T) {
			store := aggregateE2EStore()
			child := aggregateChild(store)
			if name == "store-generation" {
				store.Generation++
				store.Spec.Bindings[0].Source.PathPrefix = "/changed-selection"
			} else {
				child.Status.ObservedStoreUID = "88888888-8888-4888-8888-888888888888"
			}
			status := aggregateResult(t, store, child)
			for _, kind := range []string{"Ready", "DataCurrent", "WitnessReady", "RolloutReady"} {
				expectAggregate(t, status, kind, metav1.ConditionFalse)
			}
		})
	}
}

func TestAggregateImmediatelyRejectsSuspendedOrDeletingChildren(t *testing.T) {
	for _, name := range []string{"suspended", "deleting"} {
		t.Run(name, func(t *testing.T) {
			store := aggregateE2EStore()
			child := aggregateChild(store)
			if name == "suspended" {
				child.Spec.Suspend = true
			} else {
				now := metav1.Now()
				child.DeletionTimestamp = &now
				child.Finalizers = []string{"secrets.sekvyr.ru/test-hold"}
			}
			status := aggregateResult(t, store, child)
			for _, kind := range []string{"Ready", "DataCurrent", "WitnessReady", "RolloutReady"} {
				expectAggregate(t, status, kind, metav1.ConditionFalse)
			}
		})
	}
}

func TestAggregateRequiresTheGenerationOfEveryCondition(t *testing.T) {
	for _, kind := range []string{"Ready", "DataCurrent", "WitnessReady", "RolloutReady"} {
		t.Run(kind, func(t *testing.T) {
			store := aggregateE2EStore()
			child := aggregateChild(store)
			for i := range child.Status.Conditions {
				if child.Status.Conditions[i].Type == kind {
					child.Status.Conditions[i].ObservedGeneration = 0
				}
			}
			status := aggregateResult(t, store, child)
			expectAggregate(t, status, kind, metav1.ConditionFalse)
		})
	}
}
