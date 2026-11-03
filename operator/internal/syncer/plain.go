package syncer

import (
	"context"
	"encoding/json"
	"errors"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/panelauth"
	"github.com/mihsergeev/Sekvyr/operator/internal/rollout"
	"github.com/mihsergeev/Sekvyr/operator/internal/verification"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
)

// SyncPlain is deliberately disjoint from CurrentReader/verification.Accepted.
// It uses authenticated panel values and carries no signed freshness assertion.
func (e Engine) SyncPlain(ctx context.Context, cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding, snapshot *panelauth.PlainSnapshot, revalidate func(context.Context) error) (Result, error) {
	if b.Encryption.Mode != "Plain" || b.Encryption.Protocol != "" || b.Encryption.TrustKey != "" || b.Encryption.Freshness != nil || b.Source.ViewID != "" || e.Config.HA != nil {
		return Result{}, fail("ModeMismatch")
	}
	if _, err := e.Preflight(ctx, cr, store, b); err != nil {
		return Result{}, err
	}
	if !snapshot.Valid() {
		return Result{}, fail("SourceInvalid")
	}
	if !snapshot.Matches(b.Source.Project, b.Source.Environment, b.Source.Group) {
		return Result{}, fail("ScopeDenied")
	}
	data, err := selectValues(snapshot.Values(), b)
	if err != nil {
		return Result{}, err
	}
	return e.applySnapshot(ctx, cr, store, b, witness.Head{}, data, revalidate)
}

func (r *Runtime) syncPlain(ctx context.Context, cr *api.SekvyrSecret, store *api.SekvyrStore, b api.Binding, revalidate func(context.Context) error) (Result, error) {
	if b.Encryption.Protocol != "" || b.Encryption.TrustKey != "" || b.Encryption.Freshness != nil || b.Source.ViewID != "" || r.Config.HA != nil {
		return Result{}, fail("ModeMismatch")
	}
	if err := r.Config.ValidateRuntime(ctx, r.Reader, r.Config.Namespace, r.Config.ServiceAccount); err != nil {
		return Result{}, err
	}
	raw, err := r.bootstrapData(ctx, r.Config.TrustBundleSecret, 64<<10)
	if err != nil {
		return Result{}, err
	}
	var metadata struct {
		NodeFingerprint string `json:"nodePublicKeyFingerprint"`
	}
	if json.Unmarshal(raw, &metadata) != nil || metadata.NodeFingerprint == "" {
		return Result{}, fail("TrustInvalid")
	}
	key, err := r.bootstrapData(ctx, r.Config.IdentityKeySecret, 16<<10)
	if err != nil {
		return Result{}, err
	}
	if _, err = verification.ParseNodeKey(key, metadata.NodeFingerprint); err != nil {
		return Result{}, failureFrom(err)
	}
	if err = verification.ValidatePlainTrustBundle(raw, verification.InstallationIdentity{InstallationID: r.Config.InstallationID,
		Namespace: r.Config.Namespace, ServiceAccount: r.Config.ServiceAccount, PanelOrigin: store.Spec.Endpoint.URL,
		BootstrapGeneration: r.Config.BootstrapGeneration, NodeFingerprint: metadata.NodeFingerprint, AllowedWitnessOrigins: r.Config.AllowedWitnessOrigins}); err != nil {
		return Result{}, failureFrom(err)
	}
	policy := rollout.Policy{Enabled: r.EnableRollout && r.Config.RolloutEnabled, AllowedDeployments: r.Config.AllowedDeployments}
	engine := Engine{Config: r.Config, Reader: r.Reader, Writer: r.Writer, NodeFingerprint: metadata.NodeFingerprint, RolloutPolicy: policy}
	if _, err = engine.Preflight(ctx, cr, store, b); err != nil {
		return Result{}, err
	}
	if !policy.Enabled || !cr.Spec.Rollout.Enabled {
		if err = engine.CancelRollout(ctx, cr, store, b); err != nil {
			return Result{}, err
		}
	}
	var ref *installation.CARef
	if store.Spec.Endpoint.CAConfigMapRef != nil {
		ref = &installation.CARef{Name: store.Spec.Endpoint.CAConfigMapRef.Name, Key: store.Spec.Endpoint.CAConfigMapRef.Key}
	}
	ca, err := r.Config.CABytes(ctx, r.Reader, ref)
	if err != nil {
		return Result{}, err
	}
	transport, err := panelauth.New(panelauth.Config{Origin: store.Spec.Endpoint.URL, AllowedOrigins: r.Config.AllowedPanelOrigins,
		TokenFile: r.TokenFile, Namespace: r.Config.Namespace, ServiceAccount: r.Config.ServiceAccount, Audience: "sekvyr", CustomCAPEM: ca})
	if err != nil {
		return Result{}, failureFrom(err)
	}
	defer transport.Close()
	var snapshot *panelauth.PlainSnapshot
	for attempt := 0; attempt < 2; attempt++ {
		session, loginErr := transport.Login(ctx)
		if loginErr != nil {
			err = loginErr
			break
		}
		snapshot, err = transport.PlainSecrets(ctx, session, b.Source.Group, b.Source.Project, b.Source.Environment)
		var typed *panelauth.Error
		if err == nil || !errors.As(err, &typed) || (typed.Reason != "AuthenticationDenied" && typed.Reason != "SessionInvalid") {
			break
		}
	}
	if err != nil {
		classified := failureFrom(err)
		if Reason(classified) == "AccessDenied" || Reason(classified) == "AuthenticationDenied" || Reason(classified) == "ScopeDenied" {
			if cancelErr := engine.CancelRollout(ctx, cr, store, b); cancelErr != nil {
				return Result{}, fail("RolloutCancellationFailed")
			}
		}
		// No cached response, E2E2 downgrade or new rollout on a failed read.
		return Result{}, classified
	}
	result, err := engine.SyncPlain(ctx, cr, store, b, snapshot, revalidate)
	if err != nil {
		return result, failureFrom(err)
	}
	progress := rollout.Result{Ready: true, Reason: "Disabled"}
	if cr.Spec.Rollout.Enabled {
		switch {
		case !policy.Enabled:
			progress = rollout.Result{Reason: "InstallationDisabled"}
		case result.RolloutReason == "InitialCreate" || result.RolloutReason == "Ineligible" || result.RolloutReason == "Cancelled" || result.RolloutReason == "RolloutInvalidated":
			progress = rollout.Result{Ready: true, Reason: result.RolloutReason}
		case result.RolloutGuard == nil:
			progress = rollout.Result{Reason: result.RolloutReason}
			if progress.Reason == "" {
				progress.Reason = "RolloutNotAuthorized"
			}
		default:
			progress = (rollout.Runner{Reader: r.Reader, Writer: r.Writer}).Reconcile(ctx, rollout.Request{
				Policy: policy, CR: cr, Store: store, Binding: b, BootstrapGeneration: r.Config.BootstrapGeneration,
				TargetUID: result.TargetUID, AuthenticatedPlain: true, Guard: result.RolloutGuard,
			}, revalidate)
		}
	}
	result.Rollout = &progress
	return result, nil
}
