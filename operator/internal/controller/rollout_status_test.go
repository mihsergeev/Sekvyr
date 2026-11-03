package controller

import (
	"testing"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/rollout"
	"github.com/mihsergeev/Sekvyr/operator/internal/syncer"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPendingRolloutDoesNotClaimStaleSecretData(t *testing.T) {
	result := &syncer.Result{Revision: "opaque-revision", Head: witness.Head{Sequence: "2", EnvelopeHash: "authenticated-hash"}, Rollout: &rollout.Result{Reason: "DeploymentPaused"}}
	status := syncStatus(api.ResourceStatus{}, 4, result, "", true)
	for _, name := range []string{"DataCurrent", "WitnessReady", "BootstrapReady"} {
		condition := meta.FindStatusCondition(status.Conditions, name)
		if condition == nil || condition.Status != metav1.ConditionTrue || condition.ObservedGeneration != 4 {
			t.Fatal("rollout blockage obscured successful current data verification")
		}
	}
	for _, name := range []string{"Ready", "RolloutReady"} {
		condition := meta.FindStatusCondition(status.Conditions, name)
		if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "DeploymentPaused" {
			t.Fatal("paused rollout was reported as ready")
		}
	}
	if status.LastAppliedRevision != result.Revision || status.LastSuccessfulSyncTime == nil || status.LastVerifiedCheckpoint.Sequence != "2" {
		t.Fatal("verified application metadata was lost while rollout was pending")
	}
	result.Rollout = &rollout.Result{Ready: true, Reason: "RolledOut"}
	complete := syncStatus(status, 4, result, "", true)
	if !meta.IsStatusConditionTrue(complete.Conditions, "Ready") || !meta.IsStatusConditionTrue(complete.Conditions, "RolloutReady") {
		t.Fatal("completed requested rollout was not ready")
	}
	failed := syncStatus(complete, 4, nil, "PanelUnavailable", true)
	if !meta.IsStatusConditionFalse(failed.Conditions, "DataCurrent") || !meta.IsStatusConditionFalse(failed.Conditions, "RolloutReady") || failed.LastAppliedRevision != complete.LastAppliedRevision {
		t.Fatal("panel outage created success or discarded the last accepted revision")
	}
}

func TestRequestedRolloutNeedsAnExplicitRuntimeResult(t *testing.T) {
	verified := &syncer.Result{Revision: "opaque-revision"}
	status := syncStatus(api.ResourceStatus{}, 1, verified, "", true)
	if !meta.IsStatusConditionTrue(status.Conditions, "DataCurrent") || !meta.IsStatusConditionFalse(status.Conditions, "Ready") || !meta.IsStatusConditionFalse(status.Conditions, "RolloutReady") {
		t.Fatal("missing rollout authorization was silently treated as success")
	}
	status = syncStatus(api.ResourceStatus{}, 1, verified, "", false)
	if !meta.IsStatusConditionTrue(status.Conditions, "Ready") || !meta.IsStatusConditionTrue(status.Conditions, "RolloutReady") {
		t.Fatal("disabled optional rollout blocked verified Secret synchronization")
	}
}
