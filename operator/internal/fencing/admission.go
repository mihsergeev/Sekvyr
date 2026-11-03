package fencing

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Admit is side-effect free. In particular it never reads a Lease or mutates a
// barrier. Only the online canonical journal and this same object's old/new
// values may authorize the admission decision.
func (s *Service) Admit(ctx context.Context, request *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	response := &admissionv1.AdmissionResponse{Allowed: false, Result: &metav1.Status{Code: 403, Reason: metav1.StatusReasonForbidden, Message: "FencingDenied"}}
	deny := func(reason string) *admissionv1.AdmissionResponse { response.Result.Message = reason; return response }
	if request == nil {
		return deny("RequestInvalid")
	}
	response.UID = request.UID
	if request.Namespace != s.Config.Namespace || request.SubResource != "" || request.Name == "" || request.UID == "" {
		return deny("ScopeDenied")
	}
	version, kind := "v1", "Secret"
	if request.Resource.Group == "apps" && request.Resource.Resource == "deployments" && request.Resource.Version == "v1" {
		version, kind = "apps/v1", "Deployment"
	} else if request.Resource.Group != "" || request.Resource.Resource != "secrets" || request.Resource.Version != "v1" {
		return deny("ScopeDenied")
	}
	if request.Kind.Group != request.Resource.Group || request.Kind.Version != "v1" || request.Kind.Kind != kind {
		return deny("ScopeDenied")
	}
	configured := false
	for _, ref := range s.Config.ManagedObjects {
		if ref.APIVersion == version && ref.Kind == kind && ref.Namespace == request.Namespace && ref.Name == request.Name {
			configured = true
		}
	}
	if !configured {
		return deny("ObjectDenied")
	}
	for _, subject := range s.Config.BootstrapSubjects {
		if subject.Username != "" && request.UserInfo.Username == subject.Username && request.UserInfo.UID == subject.UID {
			if request.UserInfo.UID == s.Config.OperatorServiceAccountUID || request.UserInfo.UID == s.Config.FencerServiceAccountUID {
				return deny("IdentityRoleCollision")
			}
			response.Allowed = true
			response.Result = nil
			return response
		}
	}
	if request.Operation != admissionv1.Update {
		return deny("PrecreatedObjectsRequired")
	}
	old, err := decodeObject(request.OldObject.Raw)
	if err != nil {
		return deny("ObjectInvalid")
	}
	next, err := decodeObject(request.Object.Raw)
	if err != nil {
		return deny("ObjectInvalid")
	}
	oldMeta, oldOK := old["metadata"].(map[string]any)
	newMeta, newOK := next["metadata"].(map[string]any)
	if !oldOK || !newOK {
		return deny("ObjectInvalid")
	}
	uid, rv := text(oldMeta, "uid"), text(oldMeta, "resourceVersion")
	if uid == "" || rv == "" || text(newMeta, "uid") != uid || text(newMeta, "resourceVersion") != rv ||
		text(oldMeta, "namespace") != request.Namespace || text(newMeta, "namespace") != request.Namespace ||
		text(oldMeta, "name") != request.Name || text(newMeta, "name") != request.Name ||
		text(old, "apiVersion") != version || text(next, "apiVersion") != version || text(old, "kind") != kind || text(next, "kind") != kind ||
		oldMeta["deletionTimestamp"] != nil || newMeta["deletionTimestamp"] != nil {
		return deny("ObjectReplaced")
	}
	state, enrollment, err := s.read(ctx)
	if err != nil {
		return deny(Reason(err))
	}
	grant, hash, err := currentGrant(state, s.Config.InstallationID, false)
	if err != nil {
		return deny(Reason(err))
	}
	allowed := false
	for _, ref := range grant.Body.Objects {
		if ref.APIVersion == version && ref.Kind == kind && ref.Namespace == request.Namespace && ref.Name == request.Name && ref.UID == uid {
			allowed = true
		}
	}
	if !allowed {
		return deny("ObjectReplaced")
	}
	fence, err := EncodeFence(Fence{InstallationID: s.Config.InstallationID, BootstrapGeneration: grant.Body.BootstrapGeneration,
		Term: grant.Body.Term, OwnerPodUID: grant.Body.OwnerPodUID, GrantHash: hash})
	if err != nil {
		return deny("GrantInvalid")
	}
	oldFence, newFence := annotation(oldMeta, FenceAnnotation), annotation(newMeta, FenceAnnotation)
	if request.UserInfo.Username == serviceAccountUser(enrollment.Namespace, enrollment.FencerServiceAccount) && request.UserInfo.UID == enrollment.FencerServiceAccountUID {
		if newFence != fence || oldFence == newFence {
			return deny("BarrierInvalid")
		}
		if oldFence != "" {
			previous, parseErr := DecodeFence(oldFence)
			if parseErr != nil {
				return deny("FenceInvalid")
			}
			before, _ := e2e2.Counter(previous.Term, false)
			after, _ := e2e2.Counter(grant.Body.Term, false)
			if previous.InstallationID != grant.Body.InstallationID || previous.BootstrapGeneration > grant.Body.BootstrapGeneration || before >= after {
				return deny("FenceNotIncreasing")
			}
		}
		if !reflect.DeepEqual(withoutBarrier(old), withoutBarrier(next)) {
			return deny("BarrierOnlyRequired")
		}
		response.Allowed = true
		response.Result = nil
		return response
	}
	if request.UserInfo.Username != serviceAccountUser(enrollment.Namespace, enrollment.OperatorServiceAccount) || request.UserInfo.UID != enrollment.OperatorServiceAccountUID {
		return deny("IdentityMismatch")
	}
	podUID := request.UserInfo.Extra[podUIDExtra]
	podName := request.UserInfo.Extra[podNameExtra]
	if len(podUID) != 1 || podUID[0] != grant.Body.OwnerPodUID || len(podName) != 1 || !strings.HasPrefix(grant.Body.LeaseHolderIdentity, podName[0]+"_") {
		return deny("BoundPodRequired")
	}
	if _, _, err = currentGrant(state, s.Config.InstallationID, true); err != nil {
		return deny(Reason(err))
	}
	if oldFence != fence || newFence != fence || annotation(newMeta, WriteSessionAnnotation) != hash {
		return deny("FenceMismatch")
	}
	response.Allowed = true
	response.Result = nil
	return response
}

func decodeObject(raw []byte) (map[string]any, error) {
	canonical, err := e2e2.Canonical(raw, maxAdmissionBytes)
	if err != nil {
		return nil, fail("ObjectInvalid")
	}
	var result map[string]any
	if json.Unmarshal(canonical, &result) != nil || result == nil {
		return nil, fail("ObjectInvalid")
	}
	return result, nil
}
func text(value map[string]any, key string) string { result, _ := value[key].(string); return result }
func annotation(metadata map[string]any, key string) string {
	values, _ := metadata["annotations"].(map[string]any)
	return text(values, key)
}
func withoutBarrier(value map[string]any) map[string]any {
	raw, _ := json.Marshal(value)
	var copy map[string]any
	_ = json.Unmarshal(raw, &copy)
	metadata, _ := copy["metadata"].(map[string]any)
	delete(metadata, "managedFields")
	delete(metadata, "generation")
	delete(metadata, "resourceVersion")
	annotations, _ := metadata["annotations"].(map[string]any)
	delete(annotations, FenceAnnotation)
	if len(annotations) == 0 {
		delete(metadata, "annotations")
	}
	return copy
}
