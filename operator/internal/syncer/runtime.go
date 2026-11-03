package syncer

import (
	"context"
	"encoding/json"
	"errors"
	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/panelauth"
	"github.com/mihsergeev/Sekvyr/operator/internal/rollout"
	"github.com/mihsergeev/Sekvyr/operator/internal/transport"
	"github.com/mihsergeev/Sekvyr/operator/internal/verification"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Runtime struct {
	Config              installation.Config
	Reader              client.Reader
	Writer              client.Client
	TokenFile           string
	EnableRollout       bool
	PodUID              string
	LeaseHolderIdentity string
	FencerTokenFile     string
}

func (r *Runtime) bootstrapData(ctx context.Context, pin installation.SecretPin, max int) ([]byte, error) {
	var value corev1.Secret
	if r.Reader.Get(ctx, types.NamespacedName{Namespace: r.Config.Namespace, Name: pin.Name}, &value) != nil || string(value.UID) != pin.UID || value.Immutable == nil || !*value.Immutable || value.Type != corev1.SecretTypeOpaque || len(value.Data[pin.Key]) == 0 || len(value.Data[pin.Key]) > max {
		return nil, fail("BootstrapMismatch")
	}
	return value.Data[pin.Key], nil
}
func (r *Runtime) Sync(ctx context.Context, cr *api.SekvyrSecret, store *api.SekvyrStore, binding api.Binding, revalidate func(context.Context) error) (Result, error) {
	if binding.Encryption.Mode == "Plain" {
		return r.syncPlain(ctx, cr, store, binding, revalidate)
	}
	if binding.Encryption.Mode != "E2E" || binding.Encryption.Protocol != "e2e2" {
		return Result{}, fail("UpgradeRequired")
	}
	if err := r.Config.ValidateRuntime(ctx, r.Reader, r.Config.Namespace, r.Config.ServiceAccount); err != nil {
		return Result{}, err
	}
	raw, err := r.bootstrapData(ctx, r.Config.TrustBundleSecret, 64<<10)
	if err != nil {
		return Result{}, err
	}
	var meta struct {
		NodeFingerprint string `json:"nodePublicKeyFingerprint"`
	}
	if json.Unmarshal(raw, &meta) != nil || meta.NodeFingerprint == "" {
		return Result{}, fail("TrustInvalid")
	}
	key, err := r.bootstrapData(ctx, r.Config.IdentityKeySecret, 16<<10)
	if err != nil {
		return Result{}, err
	}
	node, err := verification.ParseNodeKey(key, meta.NodeFingerprint)
	if err != nil {
		return Result{}, failureFrom(err)
	}
	bundle, err := verification.DecodeTrustBundle(raw, verification.InstallationIdentity{InstallationID: r.Config.InstallationID, Namespace: r.Config.Namespace, ServiceAccount: r.Config.ServiceAccount, PanelOrigin: store.Spec.Endpoint.URL, BootstrapGeneration: r.Config.BootstrapGeneration, NodeFingerprint: meta.NodeFingerprint, AllowedWitnessOrigins: r.Config.AllowedWitnessOrigins})
	if err != nil {
		return Result{}, failureFrom(err)
	}
	trust, err := bundle.Authorize(binding.Encryption.TrustKey, string(store.UID), binding.ID, binding.Source.ViewID)
	if err != nil {
		return Result{}, failureFrom(err)
	}
	if r.Config.HA != nil && bundle.ViewCount() != 1 {
		return Result{}, fail("HAProfileInvalid")
	}
	policy := rollout.Policy{Enabled: r.EnableRollout && r.Config.RolloutEnabled, AllowedDeployments: r.Config.AllowedDeployments}
	engine := Engine{Config: r.Config, Reader: r.Reader, Writer: r.Writer, NodeFingerprint: meta.NodeFingerprint, RolloutPolicy: policy}
	if _, err = engine.Preflight(ctx, cr, store, binding); err != nil {
		return Result{}, err
	}
	writer, fenceCheck, closeFence, err := r.fencedWriter(ctx, trust)
	if err != nil {
		return Result{}, err
	}
	defer closeFence()
	engine.Writer = writer
	if r.Config.HA != nil {
		engine.VerifyHead = func(ctx context.Context, head witness.Head) error { return fenceCheck(ctx, &head) }
	}
	previousRevalidate := revalidate
	revalidate = func(ctx context.Context) error {
		if err := previousRevalidate(ctx); err != nil {
			return err
		}
		return fenceCheck(ctx, nil)
	}
	if !policy.Enabled || !cr.Spec.Rollout.Enabled {
		// Turning the installation feature off invalidates an existing candidate;
		// re-enabling it must not turn an old marker into a new restart request.
		if err = engine.CancelRollout(ctx, cr, store, binding); err != nil {
			return Result{}, err
		}
	}
	var panelRef *installation.CARef
	if store.Spec.Endpoint.CAConfigMapRef != nil {
		panelRef = &installation.CARef{Name: store.Spec.Endpoint.CAConfigMapRef.Name, Key: store.Spec.Endpoint.CAConfigMapRef.Key}
	}
	panelCA, err := r.Config.CABytes(ctx, r.Reader, panelRef)
	if err != nil {
		return Result{}, err
	}
	witnessCA, err := r.Config.CABytes(ctx, r.Reader, r.Config.WitnessCAConfigMapRef)
	if err != nil {
		return Result{}, err
	}
	source, err := transport.NewPanelSource(panelauth.Config{Origin: store.Spec.Endpoint.URL, AllowedOrigins: r.Config.AllowedPanelOrigins, TokenFile: r.TokenFile, Namespace: r.Config.Namespace, ServiceAccount: r.Config.ServiceAccount, Audience: "sekvyr", CustomCAPEM: panelCA}, trust.Scope)
	if err != nil {
		return Result{}, failureFrom(err)
	}
	defer source.Close()
	source.SetNodePublicKey(node.PublicKey().Bytes())
	heads, err := transport.NewWitnessClient(trust.WitnessOrigin, r.Config.AllowedWitnessOrigins, witnessCA)
	if err != nil {
		return Result{}, failureFrom(err)
	}
	defer heads.Close()
	reader, err := verification.NewReader(trust, node, heads, source)
	if err != nil {
		return Result{}, failureFrom(err)
	}
	result, err := engine.Sync(ctx, cr, store, binding, reader, revalidate)
	if err != nil {
		classified := failureFrom(err)
		switch Reason(classified) {
		case "AccessDenied", "AuthenticationDenied", "ScopeDenied":
			if cancelErr := engine.CancelRollout(ctx, cr, store, binding); cancelErr != nil {
				return result, fail("RolloutCancellationFailed")
			}
		}
		return result, classified
	}
	rolloutResult := rollout.Result{Ready: true, Reason: "Disabled"}
	if cr.Spec.Rollout.Enabled {
		switch {
		case !policy.Enabled:
			rolloutResult = rollout.Result{Reason: "InstallationDisabled"}
		case result.RolloutReason == "InitialCreate" || result.RolloutReason == "Ineligible" || result.RolloutReason == "Cancelled" || result.RolloutReason == "RolloutInvalidated":
			rolloutResult = rollout.Result{Ready: true, Reason: result.RolloutReason}
		case result.RolloutGuard == nil:
			rolloutResult = rollout.Result{Reason: result.RolloutReason}
			if rolloutResult.Reason == "" {
				rolloutResult.Reason = "RolloutNotAuthorized"
			}
		default:
			rolloutResult = (rollout.Runner{Reader: r.Reader, Writer: writer}).Reconcile(ctx, rollout.Request{
				Policy: policy, CR: cr, Store: store, Binding: binding,
				BootstrapGeneration: r.Config.BootstrapGeneration,
				TargetUID:           result.TargetUID, StrictCurrent: true, Guard: result.RolloutGuard,
			}, revalidate)
		}
	}
	result.Rollout = &rolloutResult
	return result, nil
}
func failureFrom(err error) error {
	var v *verification.Error
	if errors.As(err, &v) {
		return fail(v.Reason)
	}
	var a *panelauth.Error
	if errors.As(err, &a) {
		return fail(a.Reason)
	}
	var t *transport.Error
	if errors.As(err, &t) {
		return fail(t.Reason)
	}
	var s *Error
	if errors.As(err, &s) {
		return err
	}
	var i *installation.Failure
	if errors.As(err, &i) {
		return err
	}
	return fail("SynchronizationFailed")
}
