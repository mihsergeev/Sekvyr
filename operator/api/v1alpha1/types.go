// Package v1alpha1 defines the namespace-scoped operator request API.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var GroupVersion = schema.GroupVersion{Group: "secrets.sekvyr.ru", Version: "v1alpha1"}
var SchemeBuilder = runtime.NewSchemeBuilder(func(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &SekvyrStore{}, &SekvyrStoreList{}, &SekvyrSecret{}, &SekvyrSecretList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
})
var AddToScheme = SchemeBuilder.AddToScheme

type ConfigMapKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}
type Endpoint struct {
	URL            string           `json:"url"`
	CAConfigMapRef *ConfigMapKeyRef `json:"caConfigMapRef,omitempty"`
}
type Source struct {
	Group       string `json:"group"`
	Project     string `json:"project"`
	Environment string `json:"environment"`
	PathPrefix  string `json:"pathPrefix"`
	ViewID      string `json:"viewId,omitempty"`
}
type SelectedKey struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	TargetKey string `json:"targetKey"`
	Required  *bool  `json:"required,omitempty"`
}
type Selection struct {
	Mode string        `json:"mode"`
	Keys []SelectedKey `json:"keys,omitempty"`
}
type Freshness struct {
	Mode string `json:"mode"`
}
type Encryption struct {
	Mode      string     `json:"mode"`
	Protocol  string     `json:"protocol,omitempty"`
	TrustKey  string     `json:"trustKey,omitempty"`
	Freshness *Freshness `json:"freshness,omitempty"`
}
type Target struct {
	Name           string `json:"name"`
	Type           string `json:"type,omitempty"`
	DeletionPolicy string `json:"deletionPolicy,omitempty"`
	AllowEmpty     bool   `json:"allowEmpty,omitempty"`
}
type BindingRollout struct {
	AllowedDeployments []string `json:"allowedDeployments"`
}
type Binding struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	ResourceName string         `json:"resourceName"`
	Source       Source         `json:"source"`
	Selection    Selection      `json:"selection"`
	Encryption   Encryption     `json:"encryption"`
	Target       Target         `json:"target"`
	Rollout      BindingRollout `json:"rollout"`
}
type SekvyrStoreSpec struct {
	Endpoint Endpoint  `json:"endpoint"`
	Bindings []Binding `json:"bindings"`
}
type StoreReference struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}
type RequestedRollout struct {
	Enabled     bool     `json:"enabled,omitempty"`
	Deployments []string `json:"deployments,omitempty"`
}
type SekvyrSecretSpec struct {
	StoreRef               StoreReference   `json:"storeRef"`
	Binding                string           `json:"binding"`
	RefreshIntervalSeconds int32            `json:"refreshIntervalSeconds,omitempty"`
	Suspend                bool             `json:"suspend,omitempty"`
	Rollout                RequestedRollout `json:"rollout,omitempty"`
}

// Checkpoint contains only an authenticated envelope hash and sequence, never values or trust pins.
type Checkpoint struct {
	Sequence     string `json:"sequence"`
	EnvelopeHash string `json:"envelopeHash"`
}
type ResourceStatus struct {
	ObservedGeneration      int64              `json:"observedGeneration,omitempty"`
	ObservedStoreUID        string             `json:"observedStoreUID,omitempty"`
	ObservedStoreGeneration int64              `json:"observedStoreGeneration,omitempty"`
	LastSuccessfulSyncTime  *metav1.Time       `json:"lastSuccessfulSyncTime,omitempty"`
	LastAttemptTime         *metav1.Time       `json:"lastAttemptTime,omitempty"`
	LastAppliedRevision     string             `json:"lastAppliedRevision,omitempty"`
	LastVerifiedCheckpoint  *Checkpoint        `json:"lastVerifiedCheckpoint,omitempty"`
	Conditions              []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
type SekvyrStore struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SekvyrStoreSpec `json:"spec"`
	Status            ResourceStatus  `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SekvyrStoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SekvyrStore `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
type SekvyrSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SekvyrSecretSpec `json:"spec"`
	Status            ResourceStatus   `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SekvyrSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SekvyrSecret `json:"items"`
}

func (s *ResourceStatus) deepCopy() ResourceStatus {
	out := *s
	if s.LastSuccessfulSyncTime != nil {
		out.LastSuccessfulSyncTime = s.LastSuccessfulSyncTime.DeepCopy()
	}
	if s.LastAttemptTime != nil {
		out.LastAttemptTime = s.LastAttemptTime.DeepCopy()
	}
	if s.LastVerifiedCheckpoint != nil {
		v := *s.LastVerifiedCheckpoint
		out.LastVerifiedCheckpoint = &v
	}
	out.Conditions = append([]metav1.Condition(nil), s.Conditions...)
	return out
}
func (s *SekvyrStore) DeepCopy() *SekvyrStore {
	if s == nil {
		return nil
	}
	out := *s
	out.ObjectMeta = *s.ObjectMeta.DeepCopy()
	out.Status = s.Status.deepCopy()
	if s.Spec.Endpoint.CAConfigMapRef != nil {
		v := *s.Spec.Endpoint.CAConfigMapRef
		out.Spec.Endpoint.CAConfigMapRef = &v
	}
	out.Spec.Bindings = make([]Binding, len(s.Spec.Bindings))
	for i, b := range s.Spec.Bindings {
		out.Spec.Bindings[i] = b
		out.Spec.Bindings[i].Selection.Keys = append([]SelectedKey(nil), b.Selection.Keys...)
		for j, k := range b.Selection.Keys {
			if k.Required != nil {
				v := *k.Required
				out.Spec.Bindings[i].Selection.Keys[j].Required = &v
			}
		}
		if b.Encryption.Freshness != nil {
			v := *b.Encryption.Freshness
			out.Spec.Bindings[i].Encryption.Freshness = &v
		}
		out.Spec.Bindings[i].Rollout.AllowedDeployments = append([]string(nil), b.Rollout.AllowedDeployments...)
	}
	return &out
}
func (s *SekvyrSecret) DeepCopy() *SekvyrSecret {
	if s == nil {
		return nil
	}
	out := *s
	out.ObjectMeta = *s.ObjectMeta.DeepCopy()
	out.Status = s.Status.deepCopy()
	out.Spec.Rollout.Deployments = append([]string(nil), s.Spec.Rollout.Deployments...)
	return &out
}
func (s *SekvyrStoreList) DeepCopy() *SekvyrStoreList {
	if s == nil {
		return nil
	}
	out := *s
	out.ListMeta = *s.ListMeta.DeepCopy()
	out.Items = make([]SekvyrStore, len(s.Items))
	for i := range s.Items {
		out.Items[i] = *s.Items[i].DeepCopy()
	}
	return &out
}
func (s *SekvyrSecretList) DeepCopy() *SekvyrSecretList {
	if s == nil {
		return nil
	}
	out := *s
	out.ListMeta = *s.ListMeta.DeepCopy()
	out.Items = make([]SekvyrSecret, len(s.Items))
	for i := range s.Items {
		out.Items[i] = *s.Items[i].DeepCopy()
	}
	return &out
}
func (s *SekvyrStore) DeepCopyObject() runtime.Object      { return s.DeepCopy() }
func (s *SekvyrSecret) DeepCopyObject() runtime.Object     { return s.DeepCopy() }
func (s *SekvyrStoreList) DeepCopyObject() runtime.Object  { return s.DeepCopy() }
func (s *SekvyrSecretList) DeepCopyObject() runtime.Object { return s.DeepCopy() }
