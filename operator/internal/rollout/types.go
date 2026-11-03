// Package rollout performs opt-in, namespace-scoped Deployment annotation CAS.
// Protected state, supplied through Guard, is authoritative; public annotations
// alone never authorize a restart. Cross-object exactly-once execution is not claimed.
package rollout

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const RevisionAnnotation = "secrets.sekvyr.ru/revision"
const IntentAnnotation = "secrets.sekvyr.ru/rollout-intent"
const Debounce = 5 * time.Second
const MaximumDebounce = 30 * time.Second
const intentLimit = 32 << 10

type Policy struct {
	Enabled            bool
	AllowedDeployments []string
}
type Context struct {
	Namespace           string `json:"namespace"`
	CRName              string `json:"crName"`
	CRUID               string `json:"crUID"`
	CRGeneration        int64  `json:"crGeneration"`
	StoreName           string `json:"storeName"`
	StoreUID            string `json:"storeUID"`
	StoreGeneration     int64  `json:"storeGeneration"`
	BindingID           string `json:"bindingID"`
	BootstrapGeneration int64  `json:"bootstrapGeneration"`
	TargetName          string `json:"targetName"`
	TargetUID           string `json:"targetUID"`
}
type DeploymentRef struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}
type Intent struct {
	Version       int             `json:"version"`
	Eligible      bool            `json:"eligible"`
	Context       Context         `json:"context"`
	Revision      string          `json:"revision"`
	FirstChangeAt string          `json:"firstChangeAt"`
	LastChangeAt  string          `json:"lastChangeAt"`
	Deployments   []DeploymentRef `json:"deployments"`
}

// Authorization is stored exclusively in the UID-pinned protected state Secret.
// Empty Deployment UIDs are durable preparation candidates from a real data update;
// fresh verified reconciliation may resolve each empty UID once, never repin one.
type Authorization struct {
	Intent     Intent          `json:"intent"`
	IntentHash string          `json:"intentHash"`
	Applied    []DeploymentRef `json:"applied"`
	Cancelled  bool            `json:"cancelled"`
}
type Result struct {
	Ready        bool
	Reason       string
	RequeueAfter time.Duration
}
type Error struct{ Reason string }

func (e *Error) Error() string    { return "rollout: " + e.Reason }
func failure(reason string) error { return &Error{Reason: reason} }
func Reason(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return "RolloutFailed"
}

// Guard is implemented by the successful synchronizer, not from a wire marker.
// Confirm must compare current verified bytes and exact protected authorization;
// Applied/MarkApplied/Cancel use the same protected-state identity and CAS.
type Guard interface {
	Confirm(context.Context, *corev1.Secret, Intent) error
	Applied(context.Context, DeploymentRef) (bool, error)
	MarkApplied(context.Context, DeploymentRef) error
	Cancel(context.Context) error
}
type Request struct {
	Policy              Policy
	CR                  *api.SekvyrSecret
	Store               *api.SekvyrStore
	Binding             api.Binding
	BootstrapGeneration int64
	TargetUID           string
	StrictCurrent       bool
	// AuthenticatedPlain is process-local authorization from a successful fresh
	// Plain read. It never satisfies the E2E2 current-head verification gate.
	AuthenticatedPlain bool
	Guard              Guard
}
type Runner struct {
	Reader client.Reader
	Writer client.Client
	Now    func() time.Time
}

func NewContext(cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding, bootstrap int64, uid string) Context {
	return Context{Namespace: cr.Namespace, CRName: cr.Name, CRUID: string(cr.UID), CRGeneration: cr.Generation, StoreName: store.Name, StoreUID: string(store.UID), StoreGeneration: store.Generation, BindingID: b.ID, BootstrapGeneration: bootstrap, TargetName: b.Target.Name, TargetUID: uid}
}
func ValidRevision(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == value
}
func Encode(i Intent) ([]byte, error) {
	raw, err := json.Marshal(i)
	if err != nil || len(raw) > intentLimit {
		return nil, failure("IntentInvalid")
	}
	return raw, nil
}
func Hash(i Intent) (string, error) {
	raw, err := Encode(i)
	if err != nil {
		return "", err
	}
	canonical, err := e2e2.Canonical(raw, intentLimit)
	if err != nil {
		return "", failure("IntentInvalid")
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
func Decode(raw string) (Intent, error) {
	var i Intent
	canonical, err := e2e2.Canonical([]byte(raw), intentLimit)
	if err != nil {
		return i, failure("IntentInvalid")
	}
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	if d.Decode(&i) != nil {
		return i, failure("IntentInvalid")
	}
	round, _ := Encode(i)
	canonicalRound, e := e2e2.Canonical(round, intentLimit)
	if e != nil || !bytes.Equal(canonicalRound, canonical) || !ValidIntent(i) {
		return i, failure("IntentInvalid")
	}
	return i, nil
}
func ValidIntent(i Intent) bool {
	if i.Version != 1 || !ValidRevision(i.Revision) || i.Deployments == nil || len(i.Deployments) > 32 {
		return false
	}
	first, err := time.Parse(time.RFC3339Nano, i.FirstChangeAt)
	if err != nil {
		return false
	}
	last, err := time.Parse(time.RFC3339Nano, i.LastChangeAt)
	if err != nil || last.Before(first) {
		return false
	}
	previous := ""
	for _, d := range i.Deployments {
		if d.Name == "" || d.Name <= previous {
			return false
		}
		previous = d.Name
	}
	if i.Eligible && (i.Context.TargetUID == "" || i.Context.CRUID == "" || i.Context.StoreUID == "" || len(i.Deployments) == 0) {
		return false
	}
	return true
}
func ValidAuthorization(a *Authorization) bool {
	if a == nil {
		return true
	}
	if !ValidIntent(a.Intent) || a.Applied == nil {
		return false
	}
	hash, err := Hash(a.Intent)
	if err != nil || hash != a.IntentHash {
		return false
	}
	previous := ""
	for _, d := range a.Applied {
		if d.UID == "" || d.Name <= previous || !containsRef(a.Intent.Deployments, d) {
			return false
		}
		previous = d.Name
	}
	return true
}
func Authorize(i Intent) (*Authorization, error) {
	h, err := Hash(i)
	if err != nil || !ValidIntent(i) {
		return nil, failure("IntentInvalid")
	}
	return &Authorization{Intent: i, IntentHash: h, Applied: []DeploymentRef{}}, nil
}
func containsRef(refs []DeploymentRef, want DeploymentRef) bool {
	for _, r := range refs {
		if r == want {
			return true
		}
	}
	return false
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
func Allowed(p Policy, cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding) string {
	if !cr.Spec.Rollout.Enabled {
		return "Disabled"
	}
	if !p.Enabled {
		return "InstallationDisabled"
	}
	if cr.Namespace != store.Namespace || cr.Spec.Suspend || !cr.DeletionTimestamp.IsZero() || !store.DeletionTimestamp.IsZero() || cr.Spec.StoreRef.Name != store.Name || cr.Spec.StoreRef.UID != string(store.UID) || cr.Spec.Binding != b.Name {
		return "RolloutAuthorizationChanged"
	}
	if len(cr.Spec.Rollout.Deployments) == 0 || len(cr.Spec.Rollout.Deployments) > 32 {
		return "DeploymentDenied"
	}
	seen := map[string]bool{}
	for _, name := range cr.Spec.Rollout.Deployments {
		if seen[name] || !contains(p.AllowedDeployments, name) || !contains(b.Rollout.AllowedDeployments, name) {
			return "DeploymentDenied"
		}
		seen[name] = true
	}
	return ""
}
func sortedRefs(names []string) []DeploymentRef {
	copy := append([]string(nil), names...)
	sort.Strings(copy)
	refs := make([]DeploymentRef, len(copy))
	for n, name := range copy {
		refs[n] = DeploymentRef{Name: name}
	}
	return refs
}
