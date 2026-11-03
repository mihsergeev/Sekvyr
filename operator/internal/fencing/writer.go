package fencing

import (
	"context"
	"encoding/json"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type sessionWriter struct {
	client.Client
	session *Session
}

// Writer binds one immutable, activated session to one reconciler invocation.
// It never adopts a fence or write-session hash learned from a later GET.
func Writer(base client.Client, session *Session) client.Client {
	var bound *Session
	if session != nil {
		copy := *session
		copy.grant = cloneGrant(session.grant)
		bound = &copy
	}
	return &sessionWriter{Client: base, session: bound}
}
func (*sessionWriter) String() string   { return "fenced writer [redacted]" }
func (*sessionWriter) GoString() string { return "fenced writer [redacted]" }

func (w *sessionWriter) check(object client.Object) error {
	if w.Client == nil || w.session == nil || !w.session.ready || object == nil {
		return fail("BarriersIncomplete")
	}
	version, kind := "", ""
	switch object.(type) {
	case *corev1.Secret:
		version, kind = "v1", "Secret"
	case *appsv1.Deployment:
		version, kind = "apps/v1", "Deployment"
	default:
		return fail("ObjectDenied")
	}
	matched := false
	for _, ref := range w.session.grant.Body.Objects {
		if ref == (journal.ObjectRef{APIVersion: version, Kind: kind, Namespace: object.GetNamespace(), Name: object.GetName(), UID: string(object.GetUID())}) {
			matched = true
		}
	}
	if !matched || object.GetResourceVersion() == "" || !object.GetDeletionTimestamp().IsZero() {
		return fail("ObjectReplaced")
	}
	if object.GetAnnotations()[FenceAnnotation] != w.session.fence {
		return fail("FenceMismatch")
	}
	return nil
}
func (w *sessionWriter) Create(context.Context, client.Object, ...client.CreateOption) error {
	return fail("PrecreatedObjectsRequired")
}
func (w *sessionWriter) Apply(context.Context, runtime.ApplyConfiguration, ...client.ApplyOption) error {
	return fail("ApplyDenied")
}
func (w *sessionWriter) Delete(context.Context, client.Object, ...client.DeleteOption) error {
	return fail("DeleteDenied")
}
func (w *sessionWriter) DeleteAllOf(context.Context, client.Object, ...client.DeleteAllOfOption) error {
	return fail("DeleteDenied")
}

func (w *sessionWriter) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	if err := w.check(object); err != nil {
		return err
	}
	annotations := map[string]string{}
	for key, value := range object.GetAnnotations() {
		annotations[key] = value
	}
	annotations[WriteSessionAnnotation] = w.session.hash
	object.SetAnnotations(annotations)
	return w.Client.Update(ctx, object, options...)
}

func (w *sessionWriter) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	if err := w.check(object); err != nil {
		return err
	}
	if patch == nil {
		return fail("PatchDenied")
	}
	original, err := json.Marshal(object)
	if err != nil {
		return fail("PatchDenied")
	}
	raw, err := patch.Data(object)
	if err != nil || len(raw) > maxAdmissionBytes {
		return fail("PatchDenied")
	}
	var updated []byte
	var operations []map[string]any
	switch patch.Type() {
	case types.JSONPatchType:
		decoded, decodeErr := jsonpatch.DecodePatch(raw)
		if decodeErr != nil {
			return fail("PatchDenied")
		}
		updated, err = decoded.Apply(original)
		if json.Unmarshal(raw, &operations) != nil {
			return fail("PatchDenied")
		}
	case types.MergePatchType:
		updated, err = jsonpatch.MergePatch(original, raw)
	default:
		return fail("PatchDenied")
	}
	if err != nil {
		return fail("PatchDenied")
	}
	post, err := decodeObject(updated)
	if err != nil {
		return fail("PatchDenied")
	}
	metadata, ok := post["metadata"].(map[string]any)
	if !ok || text(metadata, "uid") != string(object.GetUID()) || text(metadata, "resourceVersion") != object.GetResourceVersion() ||
		text(metadata, "namespace") != object.GetNamespace() || text(metadata, "name") != object.GetName() || annotation(metadata, FenceAnnotation) != w.session.fence {
		return fail("FenceMismatch")
	}
	checks := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": string(object.GetUID())},
		{"op": "test", "path": "/metadata/resourceVersion", "value": object.GetResourceVersion()}}
	if patch.Type() == types.MergePatchType {
		annotations, _ := metadata["annotations"].(map[string]any)
		annotations[WriteSessionAnnotation] = w.session.hash
		checks = append(checks, map[string]any{"op": "replace", "path": "", "value": post})
	} else {
		checks = append(checks, operations...)
		checks = append(checks, map[string]any{"op": "add", "path": "/metadata/annotations/" + strings.ReplaceAll(WriteSessionAnnotation, "/", "~1"), "value": w.session.hash})
	}
	encoded, err := json.Marshal(checks)
	if err != nil {
		return fail("PatchDenied")
	}
	return w.Client.Patch(ctx, object, client.RawPatch(types.JSONPatchType, encoded), options...)
}

func (w *sessionWriter) Status() client.SubResourceWriter { return deniedSubresource{} }
func (w *sessionWriter) SubResource(name string) client.SubResourceClient {
	return deniedSubresource{reader: w.Client.SubResource(name)}
}

type deniedSubresource struct{ reader client.SubResourceClient }

func (d deniedSubresource) Get(ctx context.Context, obj client.Object, sub client.Object, options ...client.SubResourceGetOption) error {
	if d.reader == nil {
		return fail("SubresourceDenied")
	}
	return d.reader.Get(ctx, obj, sub, options...)
}
func (deniedSubresource) Create(context.Context, client.Object, client.Object, ...client.SubResourceCreateOption) error {
	return fail("SubresourceDenied")
}
func (deniedSubresource) Update(context.Context, client.Object, ...client.SubResourceUpdateOption) error {
	return fail("SubresourceDenied")
}
func (deniedSubresource) Patch(context.Context, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
	return fail("SubresourceDenied")
}
func (deniedSubresource) Apply(context.Context, runtime.ApplyConfiguration, ...client.SubResourceApplyOption) error {
	return fail("SubresourceDenied")
}
