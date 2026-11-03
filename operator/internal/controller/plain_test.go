package controller

import (
	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/syncer"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestPlainStatusNeverClaimsWitnessVerification(t *testing.T) {
	previous := api.ResourceStatus{LastVerifiedCheckpoint: &api.Checkpoint{}}
	for _, success := range []bool{true, false} {
		var result *syncer.Result
		if success {
			result = &syncer.Result{Plain: true, Revision: "11111111111111111111111111111111"}
		}
		status := syncStatus(previous, 1, result, "PanelUnavailable", false, "Plain")
		condition := meta.FindStatusCondition(status.Conditions, "WitnessReady")
		if condition == nil || condition.Status != metav1.ConditionUnknown || condition.Reason != "NotApplicablePlain" || status.LastVerifiedCheckpoint != nil {
			t.Fatal("Plain fabricated a witness checkpoint", status)
		}
	}
	store := storeFixture()
	child := aggregateChild(store)
	for i := range child.Status.Conditions {
		if child.Status.Conditions[i].Type == "WitnessReady" {
			child.Status.Conditions[i].Status = metav1.ConditionUnknown
		}
	}
	status := aggregateResult(t, store, child)
	expectAggregate(t, status, "Ready", metav1.ConditionTrue)
	expectAggregate(t, status, "WitnessReady", metav1.ConditionUnknown)
	child.Spec.Suspend = true
	status = aggregateResult(t, store, child)
	expectAggregate(t, status, "Ready", metav1.ConditionFalse)
	expectAggregate(t, status, "WitnessReady", metav1.ConditionUnknown)
}
