// Package controller authorizes namespace-scoped bindings before invoking the
// opt-in E2E2 synchronizer and separately authorized Deployment rollout.
package controller

import (
	"context"
	"reflect"
	"time"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/syncer"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type Reconciler struct {
	Client         client.Client
	APIReader      client.Reader
	Installation   installation.Config
	Namespace      string
	ServiceAccount string
	Synchronizer   *syncer.Runtime
}

func syncStatus(previous api.ResourceStatus, generation int64, result *syncer.Result, reason string, rollout bool, modes ...string) api.ResourceStatus {
	status := previous
	status.Conditions = append([]metav1.Condition(nil), previous.Conditions...)
	status.ObservedGeneration = generation
	now := metav1.Now()
	status.LastAttemptTime = &now
	good := result != nil
	plain := good && result.Plain || len(modes) > 0 && modes[0] == "Plain"
	current := metav1.ConditionFalse
	ready := metav1.ConditionFalse
	bootstrap := metav1.ConditionTrue
	witness := metav1.ConditionUnknown
	if good {
		current = metav1.ConditionTrue
		witness = metav1.ConditionTrue
		reason = "Synchronized"
		status.LastSuccessfulSyncTime = &now
		status.LastAppliedRevision = result.Revision
		status.LastVerifiedCheckpoint = &api.Checkpoint{Sequence: result.Head.Sequence, EnvelopeHash: result.Head.EnvelopeHash}
	}
	witnessReason := reason
	witnessMessage := "E2E2 requires two fresh independently signed head proofs."
	if plain {
		witness = metav1.ConditionUnknown
		witnessReason = "NotApplicablePlain"
		witnessMessage = "Plain values are authenticated by the pinned panel origin; no witness or cryptographic checkpoint is claimed."
		status.LastVerifiedCheckpoint = nil
	}
	switch reason {
	case "Suspended", "Deleting":
		bootstrap = metav1.ConditionUnknown
	case "BootstrapMismatch", "BootstrapMissing", "StateMissing", "StateInvalid", "StateReplaced", "TrustInvalid", "TrustMismatch", "NodeKeyMismatch", "BindingDenied", "ScopeDenied", "OwnershipConflict", "ProtectedTarget", "StateAmbiguous", "TargetMissing", "RecoveryPending", "TargetReservationMissing", "HAProfileInvalid", "EnrollmentMismatch", "AuthorityUpgradeRequired":
		bootstrap = metav1.ConditionFalse
	}
	switch reason {
	case "WitnessUnavailable", "WitnessInvalid", "NonceMismatch", "FloorMismatch", "RollbackDetected", "ForkDetected", "EpochRollback":
		witness = metav1.ConditionFalse
	}
	rolloutState := metav1.ConditionTrue
	rolloutReason := "Disabled"
	if rollout {
		rolloutState = metav1.ConditionFalse
		rolloutReason = reason
		if good {
			rolloutReason = "RolloutNotAuthorized"
			if result.Rollout != nil {
				rolloutReason = result.Rollout.Reason
				if result.Rollout.Ready {
					rolloutState = metav1.ConditionTrue
				}
			}
		}
	}
	readyReason := reason
	if good && rolloutState == metav1.ConditionTrue {
		ready = metav1.ConditionTrue
	} else if good && rollout {
		readyReason = rolloutReason
	}
	for _, c := range []metav1.Condition{{Type: "Ready", Status: ready, Reason: readyReason, Message: "Readiness combines current verified data and any requested workload rollout."}, {Type: "DataCurrent", Status: current, Reason: reason, Message: "Only a complete currently authorized snapshot may update the target."}, {Type: "BootstrapReady", Status: bootstrap, Reason: reason, Message: "Administrative bootstrap and ownership are validated before fetching."}, {Type: "WitnessReady", Status: witness, Reason: witnessReason, Message: witnessMessage}, {Type: "RolloutReady", Status: rolloutState, Reason: rolloutReason, Message: "Optional Deployment rollout has separate authorization and progress checks."}} {
		c.ObservedGeneration = generation
		meta.SetStatusCondition(&status.Conditions, c)
	}
	return status
}

func (r *Reconciler) stillAuthorized(ctx context.Context, expected *api.SekvyrSecret, store *api.SekvyrStore, binding api.Binding) error {
	var current api.SekvyrSecret
	var currentStore api.SekvyrStore
	if r.APIReader.Get(ctx, client.ObjectKeyFromObject(expected), &current) != nil || r.APIReader.Get(ctx, client.ObjectKeyFromObject(store), &currentStore) != nil {
		return &syncer.Error{Reason: "AuthorizationChanged"}
	}
	if current.UID != expected.UID || current.Generation != expected.Generation || current.Spec.Suspend || !current.DeletionTimestamp.IsZero() || !reflect.DeepEqual(current.Spec, expected.Spec) || currentStore.UID != store.UID || currentStore.Generation != store.Generation || !currentStore.DeletionTimestamp.IsZero() || !reflect.DeepEqual(currentStore.Spec, store.Spec) {
		return &syncer.Error{Reason: "AuthorizationChanged"}
	}
	if err := r.bootstrap(ctx); err != nil {
		return err
	}
	if _, err := r.stores(ctx); err != nil {
		return err
	}
	found, err := ValidateSecret(r.Installation, &current, &currentStore)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(*found, binding) {
		return &syncer.Error{Reason: "AuthorizationChanged"}
	}
	return nil
}

func scaffoldStatus(previous api.ResourceStatus, generation int64, reason string) api.ResourceStatus {
	status := previous
	status.ObservedGeneration = generation
	// Never preserve stale success/checkpoint claims in this scaffold.
	status.LastSuccessfulSyncTime, status.LastAppliedRevision, status.LastVerifiedCheckpoint = nil, "", nil
	status.Conditions = append([]metav1.Condition(nil), previous.Conditions...)
	bootstrap := metav1.ConditionFalse
	if reason == "VerificationNotImplemented" || reason == "Suspended" || reason == "Deleting" {
		bootstrap = metav1.ConditionUnknown
	}
	if reason == "VerificationNotImplemented" {
		bootstrap = metav1.ConditionTrue
	}
	for _, condition := range []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionFalse, Reason: reason, Message: "Stage 2 scaffold cannot synchronize data or restart workloads."},
		{Type: "BootstrapReady", Status: bootstrap, Reason: reason, Message: "Only bootstrap metadata and current binding shape are checked; E2E2 trust and durable ownership are not verified."},
		{Type: "DataCurrent", Status: metav1.ConditionFalse, Reason: "ScaffoldOnly", Message: "No source data has been fetched or applied."},
		{Type: "RolloutReady", Status: metav1.ConditionFalse, Reason: "ScaffoldOnly", Message: "No rollout implementation is installed."},
		{Type: "WitnessReady", Status: metav1.ConditionUnknown, Reason: "NotImplemented", Message: "Witness and ledger verification are not implemented."},
	} {
		condition.ObservedGeneration = generation
		if condition.Type == "BootstrapReady" && bootstrap == metav1.ConditionTrue {
			condition.Reason = "BootstrapMetadataValid"
		}
		meta.SetStatusCondition(&status.Conditions, condition)
	}
	return status
}

func (r *Reconciler) bootstrap(ctx context.Context) error {
	return r.Installation.ValidateRuntime(ctx, r.APIReader, r.Namespace, r.ServiceAccount)
}

func (r *Reconciler) stores(ctx context.Context) ([]api.SekvyrStore, error) {
	var stores api.SekvyrStoreList
	if err := r.APIReader.List(ctx, &stores, client.InNamespace(r.Namespace)); err != nil {
		return nil, installation.Reject("BootstrapMismatch")
	}
	if err := ValidateBindings(r.Installation, stores.Items); err != nil {
		return nil, err
	}
	return stores.Items, nil
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Reject before any API request, including status updates, outside the fixed namespace.
	if req.Namespace != r.Namespace {
		return ctrl.Result{}, nil
	}
	var secret api.SekvyrSecret
	if err := r.APIReader.Get(ctx, req.NamespacedName, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	reason := "VerificationNotImplemented"
	var synchronized *syncer.Result
	syncMode := ""
	var observedStoreUID string
	var observedStoreGeneration int64
	if !secret.DeletionTimestamp.IsZero() {
		reason = "Deleting"
	} else if secret.Spec.Suspend {
		reason = "Suspended"
	} else if err := r.bootstrap(ctx); err != nil {
		reason = installation.Reason(err)
	} else {
		stores, err := r.stores(ctx)
		if err != nil {
			reason = installation.Reason(err)
		} else {
			var store *api.SekvyrStore
			for i := range stores {
				if stores[i].Name == secret.Spec.StoreRef.Name {
					store = &stores[i]
					break
				}
			}
			if store == nil {
				reason = "BootstrapMissing"
			} else if binding, err := ValidateSecret(r.Installation, &secret, store); err != nil {
				reason = installation.Reason(err)
			} else if r.Synchronizer != nil {
				syncMode = binding.Encryption.Mode
				observedStoreUID, observedStoreGeneration = string(store.UID), store.Generation
				result, err := r.Synchronizer.Sync(ctx, &secret, store, *binding, func(ctx context.Context) error { return r.stillAuthorized(ctx, &secret, store, *binding) })
				if err != nil {
					reason = syncer.Reason(err)
				} else {
					synchronized = &result
				}
			}
		}
	}
	before := secret.DeepCopy()
	secret.Status = scaffoldStatus(before.Status, secret.Generation, reason)
	if r.Synchronizer != nil {
		status := syncStatus(before.Status, secret.Generation, synchronized, reason, secret.Spec.Rollout.Enabled, syncMode)
		status.ObservedStoreUID, status.ObservedStoreGeneration = observedStoreUID, observedStoreGeneration
		secret.Status = status
	}
	if !reflect.DeepEqual(secret.Status, before.Status) {
		if err := r.Client.Status().Patch(ctx, &secret, client.MergeFrom(before)); err != nil {
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
	}
	interval := time.Minute
	if synchronized != nil && secret.Spec.RefreshIntervalSeconds >= 30 {
		interval = time.Duration(secret.Spec.RefreshIntervalSeconds) * time.Second
	}
	if synchronized != nil && synchronized.Rollout != nil && synchronized.Rollout.RequeueAfter > 0 && synchronized.Rollout.RequeueAfter < interval {
		interval = synchronized.Rollout.RequeueAfter
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

type StoreReconciler struct{ *Reconciler }

func (r *StoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Namespace != r.Namespace {
		return ctrl.Result{}, nil
	}
	var store api.SekvyrStore
	if err := r.APIReader.Get(ctx, req.NamespacedName, &store); err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	reason := "VerificationNotImplemented"
	if !store.DeletionTimestamp.IsZero() {
		reason = "Deleting"
	} else if err := r.bootstrap(ctx); err != nil {
		reason = installation.Reason(err)
	} else if _, err := r.stores(ctx); err != nil {
		reason = installation.Reason(err)
	}
	before := store.DeepCopy()
	store.Status = scaffoldStatus(before.Status, store.Generation, reason)
	if r.Synchronizer != nil {
		store.Status = syncStatus(before.Status, store.Generation, nil, reason, false)
		if reason == "VerificationNotImplemented" {
			store.Status = r.aggregateStore(ctx, &store, before.Status)
		}
	}
	if !reflect.DeepEqual(store.Status, before.Status) {
		if r.Client.Status().Patch(ctx, &store, client.MergeFrom(before)) != nil {
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
	}
	return ctrl.Result{RequeueAfter: time.Minute}, nil
}

func (r *Reconciler) aggregateStore(ctx context.Context, store *api.SekvyrStore, previous api.ResourceStatus) api.ResourceStatus {
	status := previous
	status.Conditions = append([]metav1.Condition(nil), previous.Conditions...)
	status.ObservedGeneration = store.Generation
	now := metav1.Now()
	status.LastAttemptTime = &now
	status.LastAppliedRevision, status.LastVerifiedCheckpoint = "", nil
	var children api.SekvyrSecretList
	listed := r.APIReader.List(ctx, &children, client.InNamespace(r.Namespace)) == nil
	readyGood, dataGood, witnessGood, rolloutGood := listed, listed, listed, listed
	hasWitness := false
	for _, binding := range store.Spec.Bindings {
		needsWitness := binding.Encryption.Mode == "E2E"
		hasWitness = hasWitness || needsWitness
		found := false
		for _, cr := range children.Items {
			if cr.Name != binding.ResourceName || cr.Spec.Binding != binding.Name || cr.Spec.StoreRef.Name != store.Name || cr.Spec.StoreRef.UID != string(store.UID) {
				continue
			}
			found = true
			current := !cr.Spec.Suspend && cr.DeletionTimestamp.IsZero() && cr.Status.ObservedGeneration == cr.Generation && cr.Status.ObservedStoreUID == string(store.UID) && cr.Status.ObservedStoreGeneration == store.Generation
			condition := func(name string) bool {
				c := meta.FindStatusCondition(cr.Status.Conditions, name)
				return current && c != nil && c.Status == metav1.ConditionTrue && c.ObservedGeneration == cr.Generation
			}
			readyGood = readyGood && condition("Ready")
			dataGood = dataGood && condition("DataCurrent")
			if needsWitness {
				witnessGood = witnessGood && condition("WitnessReady")
			}
			rolloutGood = rolloutGood && condition("RolloutReady")
			break
		}
		if !found {
			readyGood, dataGood, rolloutGood = false, false, false
			if needsWitness {
				witnessGood = false
			}
		}
	}
	state := func(good bool) metav1.ConditionStatus {
		if good {
			return metav1.ConditionTrue
		}
		return metav1.ConditionFalse
	}
	readyGood = readyGood && dataGood && (!hasWitness || witnessGood) && rolloutGood
	reason := "BindingsNotCurrent"
	if readyGood {
		reason = "Synchronized"
	}
	if dataGood {
		status.LastSuccessfulSyncTime = &now
	}
	witnessStatus, witnessReason := state(witnessGood), reason
	if !hasWitness {
		witnessStatus, witnessReason = metav1.ConditionUnknown, "NotApplicablePlain"
	}
	for _, c := range []metav1.Condition{
		{Type: "Ready", Status: state(readyGood), Reason: reason, Message: "Aggregate state of the exact authorized child resources."},
		{Type: "DataCurrent", Status: state(dataGood), Reason: reason, Message: "All configured bindings must have a current successful child reconciliation."},
		{Type: "BootstrapReady", Status: metav1.ConditionTrue, Reason: "BindingsAuthorized", Message: "Namespace bootstrap and binding reservations are valid."},
		{Type: "WitnessReady", Status: witnessStatus, Reason: witnessReason, Message: "Aggregate witness verification state of E2E2 bindings only."},
		{Type: "RolloutReady", Status: state(rolloutGood), Reason: reason, Message: "All requested child Deployment rollouts must be current and ready."},
	} {
		c.ObservedGeneration = store.Generation
		meta.SetStatusCondition(&status.Conditions, c)
	}
	return status
}

func (r *Reconciler) allSecrets(ctx context.Context, _ client.Object) []reconcile.Request {
	var secrets api.SekvyrSecretList
	if r.Client.List(ctx, &secrets, client.InNamespace(r.Namespace)) != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(secrets.Items))
	for _, secret := range secrets.Items {
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: r.Namespace, Name: secret.Name}})
	}
	return out
}
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	filter := predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() || !reflect.DeepEqual(e.ObjectOld.GetAnnotations(), e.ObjectNew.GetAnnotations()) || !reflect.DeepEqual(e.ObjectOld.GetDeletionTimestamp(), e.ObjectNew.GetDeletionTimestamp())
	}}
	if err := ctrl.NewControllerManagedBy(mgr).For(&api.SekvyrSecret{}).
		Watches(&api.SekvyrStore{}, handler.EnqueueRequestsFromMapFunc(r.allSecrets)).WithEventFilter(filter).Complete(r); err != nil {
		return err
	}
	storeFilter := predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		if _, ok := e.ObjectNew.(*api.SekvyrStore); ok {
			return filter.Update(e)
		}
		return true
	}}
	return ctrl.NewControllerManagedBy(mgr).For(&api.SekvyrStore{}).Watches(&api.SekvyrSecret{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		cr, ok := obj.(*api.SekvyrSecret)
		if !ok || cr.Namespace != r.Namespace {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: r.Namespace, Name: cr.Spec.StoreRef.Name}}}
	})).WithEventFilter(storeFilter).Complete(&StoreReconciler{Reconciler: r})
}
