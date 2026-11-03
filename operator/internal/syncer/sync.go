package syncer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/rollout"
	"github.com/mihsergeev/Sekvyr/operator/internal/verification"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
	"time"
)

const revisionAnnotation = "secrets.sekvyr.ru/revision"
const checkpointAnnotation = "secrets.sekvyr.ru/checkpoint"
const intentAnnotation = "secrets.sekvyr.ru/rollout-intent"

type CurrentReader interface {
	ReadCurrent(context.Context, *witness.Head) (*verification.Accepted, error)
}
type Result struct {
	Plain         bool
	Head          witness.Head
	Revision      string
	Changed       bool
	TargetUID     string
	RolloutGuard  rollout.Guard
	RolloutReason string
	Rollout       *rollout.Result
}
type Engine struct {
	Config          installation.Config
	Reader          client.Reader
	Writer          client.Client
	NodeFingerprint string
	RolloutPolicy   rollout.Policy
	Now             func() time.Time
	VerifyHead      func(context.Context, witness.Head) error
}

func bindingIdentity(b api.Binding) string {
	// Selection and human routing names are administratively mutable; stable
	// source identity, target policy and encryption identity are not.
	source := b.Source
	if b.Encryption.Mode == "E2E" {
		source.Group = ""
		source.Project = ""
		source.Environment = ""
		source.PathPrefix = ""
	}
	value := struct {
		ID, Name, ResourceName   string
		Source                   api.Source
		Encryption               api.Encryption
		TargetName, Type, Policy string
	}{b.ID, b.Name, b.ResourceName, source, b.Encryption, b.Target.Name, targetType(b), policy(b)}
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// BindingIdentity exposes the existing runtime identity calculation to offline
// administrative tooling. Its Go JSON field order is part of this identity;
// canonical JSON must not be substituted here.
func BindingIdentity(b api.Binding) string { return bindingIdentity(b) }

func targetType(b api.Binding) string {
	if b.Target.Type == "" {
		return "Opaque"
	}
	return b.Target.Type
}
func policy(b api.Binding) string {
	if b.Target.DeletionPolicy == "" {
		return "Retain"
	}
	return b.Target.DeletionPolicy
}
func (e Engine) expected(cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding) Record {
	mode := ""
	if b.Encryption.Mode == "Plain" {
		mode = "Plain"
	}
	return Record{Mode: mode, CRUID: string(cr.UID), CRName: cr.Name, StoreUID: string(store.UID), BindingID: b.ID, Identity: bindingIdentity(b), TargetName: b.Target.Name}
}
func (e Engine) state() stateStore {
	return stateStore{e.Config, e.Reader, e.Writer, e.NodeFingerprint}
}
func (e Engine) target(ctx context.Context, record Record) (*corev1.Secret, error) {
	if !e.Config.TargetAllowed(record.TargetName) || e.Config.Protected(record.TargetName, "") {
		return nil, fail("ProtectedTarget")
	}
	var secret corev1.Secret
	err := e.Reader.Get(ctx, types.NamespacedName{Namespace: e.Config.Namespace, Name: record.TargetName}, &secret)
	if apierrors.IsNotFound(err) {
		if record.TargetUID != "" {
			return nil, fail("TargetMissing")
		}
		return nil, nil
	}
	if err != nil {
		return nil, fail("TargetUnavailable")
	}
	if e.Config.Protected(secret.Name, secret.UID) || secret.Type != corev1.SecretTypeOpaque || secret.Immutable != nil && *secret.Immutable {
		return nil, fail("ProtectedTarget")
	}
	if record.TargetUID == "" {
		return nil, fail("StateAmbiguous")
	}
	if record.TargetUID != string(secret.UID) {
		return nil, fail("OwnershipConflict")
	}
	return &secret, nil
}

// Preflight reads ownership before any external fetch. No target is adopted by
// labels or checkpoint annotations. State is precreated and UID-pinned.
func (e Engine) Preflight(ctx context.Context, cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding) (*witness.Head, error) {
	if cr.Namespace != e.Config.Namespace || store.Namespace != e.Config.Namespace || !cr.DeletionTimestamp.IsZero() || cr.Spec.Suspend {
		return nil, fail("ScopeDenied")
	}
	if !e.Config.TargetAllowed(b.Target.Name) || e.Config.Protected(b.Target.Name, "") {
		return nil, fail("ProtectedTarget")
	}
	_, state, err := e.state().load(ctx)
	if err != nil {
		return nil, err
	}
	expected := e.expected(cr, store, b)
	record, exists := state.Bindings[expected.StoreUID+"/"+expected.BindingID]
	if exists && !sameIdentity(record, expected) {
		return nil, fail("OwnershipConflict")
	}
	if !exists {
		record = expected
	}
	if e.Config.HA != nil && (!exists || record.TargetUID == "") {
		return nil, fail("TargetReservationMissing")
	}
	if _, err := e.target(ctx, record); err != nil {
		if !exists && Reason(err) == "StateAmbiguous" {
			return nil, fail("OwnershipConflict")
		}
		return nil, err
	}
	if record.Head == nil {
		return nil, nil
	}
	copy := *record.Head
	return &copy, nil
}

func (e Engine) Sync(ctx context.Context, cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding, reader CurrentReader, revalidate func(context.Context) error) (Result, error) {
	var result Result
	local, err := e.Preflight(ctx, cr, store, b)
	if err != nil {
		return result, err
	}
	accepted, err := reader.ReadCurrent(ctx, local)
	if err != nil {
		return result, err
	}
	if accepted == nil || !validHead(accepted.Head()) {
		return result, fail("VerificationRequired")
	}
	head := accepted.Head()
	if e.VerifyHead != nil {
		if err = e.VerifyHead(ctx, head); err != nil {
			return result, err
		}
	}
	if head.Scope.ViewID != b.Source.ViewID {
		return result, fail("CheckpointMismatch")
	}
	if local != nil {
		if err = monotonic(*local, head); err != nil {
			return result, err
		}
	}
	data, err := selectData(accepted.Values(), b)
	if err != nil {
		return result, err
	}
	return e.applySnapshot(ctx, cr, store, b, head, data, revalidate)
}

// applySnapshot shares target ownership, CAS and rollout transactions. A Plain
// binding has an explicit protected mode and NEVER persists a witness head.
// It cannot enter the canonical HA profile or accept an E2E binding as Plain.
func (e Engine) applySnapshot(ctx context.Context, cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding, head witness.Head, data map[string][]byte, revalidate func(context.Context) error) (Result, error) {
	var result Result
	plain := b.Encryption.Mode == "Plain"
	if plain {
		if e.Config.HA != nil || b.Encryption.Protocol != "" || b.Source.ViewID != "" || head != (witness.Head{}) {
			return result, fail("ModeMismatch")
		}
	} else if b.Encryption.Mode != "E2E" || b.Encryption.Protocol != "e2e2" || !validHead(head) {
		return result, fail("VerificationRequired")
	}
	var err error
	if err = revalidate(ctx); err != nil {
		return result, err
	}
	expected := e.expected(cr, store, b)
	key := expected.StoreUID + "/" + expected.BindingID
	record, err := e.state().update(ctx, key, expected, func(r *Record) error {
		if !plain && r.Head != nil {
			if err := monotonic(*r.Head, head); err != nil {
				return err
			}
		}
		if plain {
			r.Head = nil
		} else {
			copy := head
			r.Head = &copy
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	// The high-watermark is durable before any target mutation. A crash here is
	// retried using the same or a newer verified head, never a lower one.
	if err = revalidate(ctx); err != nil {
		return result, err
	}
	target, err := e.target(ctx, record)
	if err != nil {
		return result, err
	}
	if target != nil {
		var old witness.Head
		if plain {
			if target.Annotations[checkpointAnnotation] != "" {
				return result, fail("ModeMismatch")
			}
		} else {
			if strict([]byte(target.Annotations[checkpointAnnotation]), &old, 16<<10) != nil || !validHead(old) {
				return result, fail("TargetCheckpointInvalid")
			}
			if err = monotonic(old, head); err != nil {
				return result, err
			}
		}
		if policy(b) == "Retain" && len(target.OwnerReferences) != 0 {
			return result, fail("OwnershipConflict")
		}
		if policy(b) == "Delete" && (len(target.OwnerReferences) != 1 || string(target.OwnerReferences[0].UID) != string(cr.UID) || target.OwnerReferences[0].Kind != "SekvyrSecret" || target.OwnerReferences[0].APIVersion != api.GroupVersion.String() || target.OwnerReferences[0].Name != cr.Name || target.OwnerReferences[0].Controller == nil || !*target.OwnerReferences[0].Controller) {
			return result, fail("OwnershipConflict")
		}
		if equalData(target.Data, data) {
			revision := target.Annotations[revisionAnnotation]
			decoded, decodeErr := hex.DecodeString(revision)
			if decodeErr != nil || len(decoded) != 16 || strings.ToLower(revision) != revision {
				return result, fail("TargetRevisionInvalid")
			}
			if err = e.state().confirm(ctx, key, expected, head, record.TargetUID); err != nil {
				return result, err
			}
			if old != head {
				checkpoint, _ := json.Marshal(head)
				target.Annotations[checkpointAnnotation] = string(checkpoint)
				if err = revalidate(ctx); err != nil {
					return result, err
				}
				if err = e.state().confirm(ctx, key, expected, head, record.TargetUID); err != nil {
					return result, err
				}
				if err = e.Writer.Update(ctx, target); err != nil {
					if apierrors.IsConflict(err) {
						return result, fail("TargetConflict")
					}
					return result, fail("TargetWriteFailed")
				}
			}
			guard, rolloutReason := e.resumeRollout(ctx, cr, store, b, head, target, data, revalidate)
			return Result{Plain: plain, Head: head, Revision: target.Annotations[revisionAnnotation], Changed: false, TargetUID: string(target.UID), RolloutGuard: guard, RolloutReason: rolloutReason}, nil
		}
	}
	revisionBytes := make([]byte, 16)
	if _, err = rand.Read(revisionBytes); err != nil {
		return result, fail("RandomUnavailable")
	}
	revision := hex.EncodeToString(revisionBytes)
	wasInitial := target == nil
	previousAuth := record.Rollout
	if target == nil {
		previousAuth = nil
	}
	intent, rolloutReason := rollout.Prepare(ctx, e.Reader, e.RolloutPolicy, cr, store, b, target, revision, e.Config.BootstrapGeneration, e.now(), previousAuth)
	authorization, authErr := rollout.Authorize(intent)
	if authErr != nil {
		return result, fail("RolloutStateInvalid")
	}
	// Authorization is independently durable BEFORE the target data/revision/intent
	// transaction. A crash with mismatched public metadata fails closed.
	record, err = e.state().update(ctx, key, expected, func(r *Record) error {
		if !recordHeadMatches(*r, head) || r.TargetUID != record.TargetUID {
			return fail("HeadChanged")
		}
		r.Rollout = authorization
		return nil
	})
	if err != nil {
		return result, err
	}
	if target == nil {
		target = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: b.Target.Name, Namespace: e.Config.Namespace}, Type: corev1.SecretTypeOpaque}
		if policy(b) == "Delete" {
			controller := true
			target.OwnerReferences = []metav1.OwnerReference{{APIVersion: api.GroupVersion.String(), Kind: "SekvyrSecret", Name: cr.Name, UID: cr.UID, Controller: &controller}}
		}
	}
	if target.Annotations == nil {
		target.Annotations = map[string]string{}
	}
	intentRaw, _ := rollout.Encode(intent)
	target.Data = data
	target.Annotations[revisionAnnotation] = revision
	if !plain {
		checkpoint, _ := json.Marshal(head)
		target.Annotations[checkpointAnnotation] = string(checkpoint)
	}
	target.Annotations[intentAnnotation] = string(intentRaw)
	if err = revalidate(ctx); err != nil {
		return result, err
	}
	if ctx.Err() != nil {
		return result, fail("Cancelled")
	}
	if err = e.confirmRolloutAuthorization(ctx, key, expected, head, record.TargetUID, authorization.IntentHash); err != nil {
		return result, err
	}
	if record.TargetUID == "" {
		if err = e.Writer.Create(ctx, target); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return result, fail("OwnershipConflict")
			}
			return result, fail("TargetWriteFailed")
		}
		uid := string(target.UID)
		if uid == "" {
			return result, fail("StateAmbiguous")
		}
		bound, bindErr := e.state().update(ctx, key, expected, func(r *Record) error {
			if r.TargetUID != "" && r.TargetUID != uid {
				return fail("StateAmbiguous")
			}
			r.TargetUID = uid
			return nil
		})
		if bindErr != nil {
			return result, fail("StateAmbiguous")
		}
		if !recordHeadMatches(bound, head) {
			return result, fail("HeadChanged")
		}
	} else {
		if err = e.Writer.Update(ctx, target); err != nil {
			if apierrors.IsConflict(err) {
				return result, fail("TargetConflict")
			}
			return result, fail("TargetWriteFailed")
		}
	}
	var guard rollout.Guard
	if !wasInitial {
		guard = e.rolloutGuard(cr, store, b, head, target, data, authorization)
	}
	return Result{Plain: plain, Head: head, Revision: revision, Changed: true, TargetUID: string(target.UID), RolloutGuard: guard, RolloutReason: rolloutReason}, nil
}

type selectableValue interface {
	Path() string
	Name() string
	Data() []byte
}

func selectData(values []verification.Value, b api.Binding) (map[string][]byte, error) {
	return selectValues(values, b)
}

func selectValues[V selectableValue](values []V, b api.Binding) (map[string][]byte, error) {
	data := map[string][]byte{}
	source := map[string]V{}
	for _, v := range values {
		if _, exists := source[v.Path()+"\x00"+v.Name()]; exists {
			return nil, fail("DuplicateSourceKey")
		}
		source[v.Path()+"\x00"+v.Name()] = v
	}
	total := 0
	add := func(key string, value V) error {
		if len(validation.IsConfigMapKey(key)) != 0 {
			return fail("InvalidTargetKey")
		}
		if _, exists := data[key]; exists {
			return fail("DuplicateTargetKey")
		}
		raw := value.Data()
		if len(raw) > (1<<20)-total {
			return fail("TargetTooLarge")
		}
		total += len(raw)
		data[key] = raw
		return nil
	}
	within := func(path string) bool {
		return b.Source.PathPrefix == "/" || path == b.Source.PathPrefix || strings.HasPrefix(path, b.Source.PathPrefix+"/")
	}
	switch b.Selection.Mode {
	case "All":
		for _, v := range values {
			if within(v.Path()) {
				if err := add(v.Name(), v); err != nil {
					return nil, err
				}
			}
		}
	case "Keys":
		for _, k := range b.Selection.Keys {
			v, exists := source[k.Path+"\x00"+k.Name]
			if !exists {
				if k.Required == nil || *k.Required {
					return nil, fail("RequiredValueMissing")
				}
				continue
			}
			if !within(k.Path) {
				return nil, fail("ScopeDenied")
			}
			if err := add(k.TargetKey, v); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fail("InvalidSelection")
	}
	if len(data) == 0 && !b.Target.AllowEmpty {
		return nil, fail("EmptyTargetDenied")
	}
	return data, nil
}

// Verify content directly; revision or label equality never authorizes adoption.
func equalData(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		other, exists := b[k]
		if !exists || !bytes.Equal(v, other) {
			return false
		}
	}
	return true
}
