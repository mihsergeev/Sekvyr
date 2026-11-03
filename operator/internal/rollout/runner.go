package rollout

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Annotation(targetUID string) string { return "secrets.sekvyr.ru/restart-" + targetUID }
func (r Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
func blocked(reason string, after time.Duration) Result {
	return Result{Reason: reason, RequeueAfter: after}
}

func (r Runner) Reconcile(ctx context.Context, q Request, revalidate func(context.Context) error) Result {
	if q.CR == nil || q.Store == nil {
		return blocked("RolloutAuthorizationChanged", 0)
	}
	if reason := Allowed(q.Policy, q.CR, q.Store, q.Binding); reason != "" {
		return Result{Ready: reason == "Disabled", Reason: reason}
	}
	current := q.StrictCurrent && !q.AuthenticatedPlain && q.Binding.Encryption.Mode != "Plain"
	plain := q.AuthenticatedPlain && !q.StrictCurrent && q.Binding.Encryption.Mode == "Plain" && q.Binding.Encryption.Protocol == "" && q.Binding.Encryption.TrustKey == "" && q.Binding.Encryption.Freshness == nil && q.Binding.Source.ViewID == ""
	if (!current && !plain) || q.Guard == nil {
		return blocked("CurrentVerificationRequired", 0)
	}
	if r.Reader == nil || r.Writer == nil || revalidate == nil {
		return blocked("RolloutUnavailable", 0)
	}
	var target corev1.Secret
	if r.Reader.Get(ctx, types.NamespacedName{Namespace: q.CR.Namespace, Name: q.Binding.Target.Name}, &target) != nil {
		return blocked("TargetUnavailable", 0)
	}
	if string(target.UID) != q.TargetUID || q.TargetUID == "" || !target.DeletionTimestamp.IsZero() {
		return blocked("TargetReplaced", 0)
	}
	i, err := Decode(target.Annotations[IntentAnnotation])
	if err != nil {
		return blocked("IntentInvalid", 0)
	}
	if i.Context != NewContext(q.CR, q.Store, q.Binding, q.BootstrapGeneration, q.TargetUID) {
		return blocked("RolloutAuthorizationChanged", 0)
	}
	if !i.Eligible {
		return Result{Ready: true, Reason: "Ineligible"}
	}
	if i.Revision != target.Annotations[RevisionAnnotation] || !sameNames(i.Deployments, sortedRefs(q.CR.Spec.Rollout.Deployments)) {
		return blocked("IntentInvalid", 0)
	}
	if err = q.Guard.Confirm(ctx, &target, i); err != nil {
		return blocked(Reason(err), 0)
	}
	first, _ := time.Parse(time.RFC3339Nano, i.FirstChangeAt)
	last, _ := time.Parse(time.RFC3339Nano, i.LastChangeAt)
	now := r.now()
	if now.Before(first) || now.Before(last) {
		return blocked("RolloutClockInvalid", 0)
	}
	due := last.Add(Debounce)
	if max := first.Add(MaximumDebounce); max.Before(due) {
		due = max
	}
	if now.Before(due) {
		return blocked("Debouncing", due.Sub(now))
	}
	anyProgress := false
	for _, ref := range i.Deployments {
		if ref.UID == "" {
			return blocked("DeploymentUnavailable", 2*time.Second)
		}
		var deployment appsv1.Deployment
		if err = r.Reader.Get(ctx, types.NamespacedName{Namespace: q.CR.Namespace, Name: ref.Name}, &deployment); err != nil {
			if apierrors.IsForbidden(err) {
				return blocked("DeploymentDenied", 0)
			}
			return blocked("DeploymentUnavailable", 2*time.Second)
		}
		if string(deployment.UID) != ref.UID || !deployment.DeletionTimestamp.IsZero() {
			return blocked("DeploymentReplaced", 0)
		}
		if !Consumes(&deployment, target.Name) {
			return blocked("SecretNotConsumed", 0)
		}
		if deployment.Spec.Paused {
			return blocked("DeploymentPaused", 2*time.Second)
		}
		applied, applyErr := q.Guard.Applied(ctx, ref)
		if applyErr != nil {
			return blocked(Reason(applyErr), 0)
		}
		key := Annotation(q.TargetUID)
		marker := deployment.Spec.Template.Annotations[key]
		if applied && marker != i.Revision {
			return blocked("RolloutMarkerChanged", 0)
		}
		patched := false
		if !applied {
			if err = revalidate(ctx); err != nil {
				return blocked("RolloutAuthorizationChanged", 0)
			}
			var fresh corev1.Secret
			if r.Reader.Get(ctx, client.ObjectKeyFromObject(&target), &fresh) != nil || q.Guard.Confirm(ctx, &fresh, i) != nil {
				return blocked("RolloutAuthorizationChanged", 0)
			}
			if marker != i.Revision {
				patch := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": string(deployment.UID)}, {"op": "test", "path": "/metadata/resourceVersion", "value": deployment.ResourceVersion}}
				if deployment.Spec.Template.Annotations == nil {
					patch = append(patch, map[string]any{"op": "add", "path": "/spec/template/metadata/annotations", "value": map[string]string{key: i.Revision}})
				} else {
					patch = append(patch, map[string]any{"op": "add", "path": "/spec/template/metadata/annotations/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1"), "value": i.Revision})
				}
				raw, _ := json.Marshal(patch)
				if err = r.Writer.Patch(ctx, &deployment, client.RawPatch(types.JSONPatchType, raw)); err != nil {
					if apierrors.IsConflict(err) || apierrors.IsInvalid(err) {
						return blocked("DeploymentConflict", 2*time.Second)
					}
					if apierrors.IsForbidden(err) {
						return blocked("DeploymentDenied", 0)
					}
					return blocked("DeploymentPatchFailed", 2*time.Second)
				}
				anyProgress = true
				patched = true
			}
			if err = q.Guard.MarkApplied(ctx, ref); err != nil {
				return blocked(Reason(err), 2*time.Second)
			}
		}
		// A failed older revision can be repaired by the newly authorized data.
		// Status describes this revision only after its generation was observed;
		// a patch made during this call must first be observed by Kubernetes.
		if !patched && deployment.Status.ObservedGeneration >= deployment.Generation {
			for _, condition := range deployment.Status.Conditions {
				if condition.Type == appsv1.DeploymentProgressing && condition.Status == corev1.ConditionFalse && condition.Reason == "ProgressDeadlineExceeded" {
					return blocked("ProgressDeadlineExceeded", 0)
				}
			}
		}
		replicas := int32(1)
		if deployment.Spec.Replicas != nil {
			replicas = *deployment.Spec.Replicas
		}
		if deployment.Status.ObservedGeneration < deployment.Generation || deployment.Status.UpdatedReplicas < replicas || deployment.Status.AvailableReplicas < replicas || deployment.Status.Replicas > replicas {
			anyProgress = true
		}
	}
	if anyProgress {
		return blocked("RolloutProgressing", 2*time.Second)
	}
	return Result{Ready: true, Reason: "RolledOut"}
}

// Cancel records terminal revocation in protected state. It does not mutate the
// target during suspend/delete and cannot authorize any Deployment operation.
func Cancel(ctx context.Context, guard Guard) error {
	if guard == nil {
		return failure("RolloutStateAmbiguous")
	}
	return guard.Cancel(ctx)
}
