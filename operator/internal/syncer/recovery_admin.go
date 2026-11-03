package syncer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"reflect"
	"time"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	"github.com/mihsergeev/Sekvyr/operator/internal/recovery"
	"github.com/mihsergeev/Sekvyr/operator/internal/rollout"
	"github.com/mihsergeev/Sekvyr/operator/internal/transport"
	"github.com/mihsergeev/Sekvyr/operator/internal/verification"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
	"k8s.io/apimachinery/pkg/types"
)

type encryptedRecoverySource struct {
	scope          witness.Scope
	hash           string
	envelope, wrap []byte
}

func (s encryptedRecoverySource) EnvelopeByHash(ctx context.Context, scope witness.Scope, hash string) ([]byte, error) {
	if ctx.Err() != nil || scope != s.scope || hash != s.hash {
		return nil, fail("RecoverySourceMismatch")
	}
	return bytes.Clone(s.envelope), nil
}
func (s encryptedRecoverySource) ReaderWrap(ctx context.Context, scope witness.Scope, _, _, _, _ string) ([]byte, error) {
	if ctx.Err() != nil || scope != s.scope {
		return nil, fail("RecoverySourceMismatch")
	}
	return bytes.Clone(s.wrap), nil
}

// RecoverFromFiles uses only encrypted offline export files for data transport.
// Both independent journal and nonce witness are still required ONLINE. No
// missing-state fallback, panel key discovery, or plaintext import exists.
func (r *Runtime) RecoverFromFiles(ctx context.Context, planRaw, envelopeRaw, wrapRaw []byte) error {
	if ctx == nil || ctx.Err() != nil || r.Config.HA == nil || len(planRaw) > recovery.Limit || len(envelopeRaw) > e2e2.MaxEnvelopeBytes || len(wrapRaw) > e2e2.MaxReaderWrapBytes {
		return fail("RecoveryProfileInvalid")
	}
	if err := r.Config.ValidateRuntime(ctx, r.Reader, r.Config.Namespace, r.Config.ServiceAccount); err != nil {
		return err
	}
	var route recovery.Plan
	if e2e2.DecodeStrict(planRaw, &route, recovery.Limit) != nil || !installation.ValidName(route.Body.Binding.CRName) || !installation.ValidName(route.Body.Binding.StoreName) {
		return fail("RecoveryPlanInvalid")
	}
	var cr api.SekvyrSecret
	var store api.SekvyrStore
	if r.Reader.Get(ctx, types.NamespacedName{Namespace: r.Config.Namespace, Name: route.Body.Binding.CRName}, &cr) != nil || r.Reader.Get(ctx, types.NamespacedName{Namespace: r.Config.Namespace, Name: route.Body.Binding.StoreName}, &store) != nil {
		return fail("RecoveryBindingMismatch")
	}
	var binding *api.Binding
	for i := range store.Spec.Bindings {
		candidate := &store.Spec.Bindings[i]
		if candidate.ID == route.Body.Binding.BindingID {
			binding = candidate
		}
	}
	if binding == nil || cr.Spec.StoreRef.Name != store.Name || cr.Spec.StoreRef.UID != string(store.UID) || cr.Spec.Binding != binding.Name || binding.Encryption.Mode != "E2E" || binding.Encryption.Protocol != "e2e2" {
		return fail("RecoveryBindingMismatch")
	}
	raw, err := r.bootstrapData(ctx, r.Config.TrustBundleSecret, 64<<10)
	if err != nil {
		return err
	}
	var meta struct {
		NodeFingerprint string `json:"nodePublicKeyFingerprint"`
	}
	if json.Unmarshal(raw, &meta) != nil {
		return fail("TrustInvalid")
	}
	key, err := r.bootstrapData(ctx, r.Config.IdentityKeySecret, 16<<10)
	if err != nil {
		return err
	}
	node, err := verification.ParseNodeKey(key, meta.NodeFingerprint)
	if err != nil {
		return failureFrom(err)
	}
	bundle, err := verification.DecodeTrustBundle(raw, verification.InstallationIdentity{InstallationID: r.Config.InstallationID, Namespace: r.Config.Namespace, ServiceAccount: r.Config.ServiceAccount, PanelOrigin: store.Spec.Endpoint.URL, BootstrapGeneration: r.Config.BootstrapGeneration, NodeFingerprint: meta.NodeFingerprint, AllowedWitnessOrigins: r.Config.AllowedWitnessOrigins})
	if err != nil {
		return failureFrom(err)
	}
	if bundle.ViewCount() != 1 {
		return fail("HAProfileInvalid")
	}
	trust, err := bundle.Authorize(binding.Encryption.TrustKey, string(store.UID), binding.ID, binding.Source.ViewID)
	if err != nil {
		return failureFrom(err)
	}
	h := r.Config.HA
	ca, err := r.Config.CABytes(ctx, r.Reader, h.GatewayCAConfigMapRef)
	if err != nil {
		return err
	}
	certPEM, err := r.bootstrapData(ctx, h.GatewayClientSecret, 64<<10)
	if err != nil {
		return err
	}
	keyPin := h.GatewayClientSecret
	keyPin.Key = h.GatewayClientKeyKey
	clientKey, err := r.bootstrapData(ctx, keyPin, 64<<10)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, clientKey)
	if err != nil {
		return fail("HAIdentityInvalid")
	}
	storage, err := journal.NewAPIStorageClient(h.GatewayOrigin, ca, cert)
	if err != nil {
		return fail("JournalUnavailable")
	}
	defer storage.Close()
	ledger, err := journal.New(storage, []journal.Registration{h.Journal}, nil)
	if err != nil {
		return fail("HAProfileInvalid")
	}
	current, err := ledger.ReadCurrent(ctx, h.Journal.LogID, h.Journal.MinimumCursor)
	if err != nil {
		return fail("JournalUnavailable")
	}
	if !trustMatchesAuthority(trust, current) {
		return fail("AuthorityUpgradeRequired")
	}
	plan, err := recovery.Verify(ctx, planRaw, r.Config, current, time.Now())
	if err != nil {
		return err
	}
	ca, err = r.Config.CABytes(ctx, r.Reader, r.Config.WitnessCAConfigMapRef)
	if err != nil {
		return err
	}
	heads, err := transport.NewWitnessClient(trust.WitnessOrigin, r.Config.AllowedWitnessOrigins, ca)
	if err != nil {
		return failureFrom(err)
	}
	defer heads.Close()
	reader, err := verification.NewReader(trust, node, heads, encryptedRecoverySource{scope: trust.Scope, hash: current.Snapshot.EnvelopeHash, envelope: bytes.Clone(envelopeRaw), wrap: bytes.Clone(wrapRaw)})
	if err != nil {
		return failureFrom(err)
	}
	floor := current.Head()
	accepted, err := reader.ReadCurrent(ctx, &floor)
	if err != nil {
		return failureFrom(err)
	}
	check := func(ctx context.Context) error {
		if ctx.Err() != nil {
			return fail("Cancelled")
		}
		next, err := ledger.ReadCurrent(ctx, h.Journal.LogID, plan.Body().Cursor)
		if err != nil || next.Cursor != plan.Body().Cursor {
			return fail("RecoveryJournalChanged")
		}
		if _, err := recovery.Verify(ctx, planRaw, r.Config, next, time.Now()); err != nil {
			return err
		}
		var freshCR api.SekvyrSecret
		var freshStore api.SekvyrStore
		if r.Reader.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: cr.Name}, &freshCR) != nil || r.Reader.Get(ctx, types.NamespacedName{Namespace: store.Namespace, Name: store.Name}, &freshStore) != nil || freshCR.UID != cr.UID || freshStore.UID != store.UID || freshCR.Generation != cr.Generation || freshStore.Generation != store.Generation || !freshCR.DeletionTimestamp.IsZero() || !freshStore.DeletionTimestamp.IsZero() || !reflect.DeepEqual(freshCR.Spec, cr.Spec) || !reflect.DeepEqual(freshStore.Spec, store.Spec) {
			return fail("RecoveryBindingChanged")
		}
		return r.Config.ValidateRuntime(ctx, r.Reader, r.Config.Namespace, r.Config.ServiceAccount)
	}
	engine := Engine{Config: r.Config, Reader: r.Reader, Writer: r.Writer, NodeFingerprint: meta.NodeFingerprint, RolloutPolicy: rollout.Policy{Enabled: r.EnableRollout && r.Config.RolloutEnabled, AllowedDeployments: r.Config.AllowedDeployments}}
	return engine.RestoreCheckpoint(ctx, plan, accepted, &cr, &store, *binding, check)
}
