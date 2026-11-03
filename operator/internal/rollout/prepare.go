package rollout

import (
	"context"
	"time"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Consumes checks actual Pod configuration. ImagePullSecrets do not count as
// application consumption. Init containers and projected Secret volumes do.
func Consumes(d *appsv1.Deployment, secret string) bool {
	mounted := map[string]bool{}
	containers := append([]corev1.Container(nil), d.Spec.Template.Spec.Containers...)
	containers = append(containers, d.Spec.Template.Spec.InitContainers...)
	for _, container := range containers {
		for _, mount := range container.VolumeMounts {
			mounted[mount.Name] = true
		}
	}
	for _, v := range d.Spec.Template.Spec.Volumes {
		if !mounted[v.Name] {
			continue
		}
		if v.Secret != nil && v.Secret.SecretName == secret {
			return true
		}
		if v.Projected != nil {
			for _, s := range v.Projected.Sources {
				if s.Secret != nil && s.Secret.Name == secret {
					return true
				}
			}
		}
	}
	for _, c := range containers {
		for _, e := range c.EnvFrom {
			if e.SecretRef != nil && e.SecretRef.Name == secret {
				return true
			}
		}
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil && e.ValueFrom.SecretKeyRef.Name == secret {
				return true
			}
		}
	}
	return false
}

// Prepare may create eligibility ONLY for an actual verified data update to an
// existing target. Caller atomically writes the result with that data/revision,
// after independently persisting Authorization in protected state.
func Prepare(ctx context.Context, reader client.Reader, p Policy, cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding, target *corev1.Secret, revision string, bootstrap int64, now time.Time, previous *Authorization) (Intent, string) {
	uid := ""
	if target != nil {
		uid = string(target.UID)
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	i := Intent{Version: 1, Context: NewContext(cr, store, b, bootstrap, uid), Revision: revision, FirstChangeAt: stamp, LastChangeAt: stamp, Deployments: []DeploymentRef{}}
	if target == nil {
		return i, "InitialCreate"
	}
	if reason := Allowed(p, cr, store, b); reason != "" {
		return i, reason
	}
	i.Eligible = true
	i.Deployments = sortedRefs(cr.Spec.Rollout.Deployments)
	// UID pins outlive completion and cancellation within this administrative
	// context. Public-marker edits never permit observing a replacement UID.
	if previous != nil && ValidAuthorization(previous) && previous.Intent.Eligible && previous.Intent.Context == i.Context && sameNames(previous.Intent.Deployments, i.Deployments) {
		for n := range i.Deployments {
			i.Deployments[n].UID = previous.Intent.Deployments[n].UID
		}
		old, decodeErr := Decode(target.Annotations[IntentAnnotation])
		oldHash, hashErr := Hash(old)
		if !previous.Cancelled && len(previous.Applied) < len(previous.Intent.Deployments) && decodeErr == nil && hashErr == nil && oldHash == previous.IntentHash && target.Annotations[RevisionAnnotation] == previous.Intent.Revision {
			i.FirstChangeAt = previous.Intent.FirstChangeAt
		}
	}
	return resolve(ctx, reader, i)
}
func sameNames(a, b []DeploymentRef) bool {
	if len(a) != len(b) {
		return false
	}
	for n := range a {
		if a[n].Name != b[n].Name {
			return false
		}
	}
	return true
}

// Resolve retries only a protected candidate after successful fresh sync.
// Known UIDs are immutable, including after Deployment deletion/recreation.
func Resolve(ctx context.Context, reader client.Reader, i Intent) (Intent, string) {
	if !i.Eligible {
		return i, "Disabled"
	}
	return resolve(ctx, reader, i)
}
func resolve(ctx context.Context, reader client.Reader, i Intent) (Intent, string) {
	i.Deployments = append([]DeploymentRef(nil), i.Deployments...)
	reason := ""
	for n, ref := range i.Deployments {
		var d appsv1.Deployment
		if reader == nil || reader.Get(ctx, types.NamespacedName{Namespace: i.Context.Namespace, Name: ref.Name}, &d) != nil {
			if reason == "" {
				reason = "DeploymentUnavailable"
			}
			continue
		}
		if !d.DeletionTimestamp.IsZero() || d.UID == "" {
			if reason == "" {
				reason = "DeploymentUnavailable"
			}
			continue
		}
		if ref.UID != "" && string(d.UID) != ref.UID {
			if reason == "" {
				reason = "DeploymentReplaced"
			}
			continue
		}
		if ref.UID == "" {
			i.Deployments[n].UID = string(d.UID)
		}
		if !Consumes(&d, i.Context.TargetName) {
			if reason == "" {
				reason = "SecretNotConsumed"
			}
			continue
		}
	}
	return i, reason
}
