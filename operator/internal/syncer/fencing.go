package syncer

import (
	"bytes"
	"context"
	"crypto/tls"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/fencing"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	"github.com/mihsergeev/Sekvyr/operator/internal/verification"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// fencedWriter is created per reconciliation; its immutable session must never
// be updated to a later process's grant while a request is in flight.
func (r *Runtime) fencedWriter(ctx context.Context, trust verification.Trust) (client.Client, func(context.Context, *witness.Head) error, func(), error) {
	if r.Config.HA == nil {
		return r.Writer, func(context.Context, *witness.Head) error { return nil }, func() {}, nil
	}
	h := r.Config.HA
	if r.PodUID == "" || r.LeaseHolderIdentity == "" || r.FencerTokenFile == "" || trust.Scope.LogID != h.Journal.LogID {
		return nil, nil, nil, fail("HAProfileInvalid")
	}
	ca, err := r.Config.CABytes(ctx, r.Reader, h.GatewayCAConfigMapRef)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM, err := r.bootstrapData(ctx, h.GatewayClientSecret, 64<<10)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPin := h.GatewayClientSecret
	keyPin.Key = h.GatewayClientKeyKey
	keyPEM, err := r.bootstrapData(ctx, keyPin, 64<<10)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fail("HAIdentityInvalid")
	}
	storage, err := journal.NewAPIStorageClient(h.GatewayOrigin, ca, cert)
	if err != nil {
		return nil, nil, nil, fail("JournalUnavailable")
	}
	closeStorage := func() { storage.Close() }
	ledger, err := journal.New(storage, []journal.Registration{h.Journal}, nil)
	if err != nil {
		closeStorage()
		return nil, nil, nil, fail("HAProfileInvalid")
	}
	current, err := ledger.ReadCurrent(ctx, h.Journal.LogID, h.Journal.MinimumCursor)
	if err != nil {
		closeStorage()
		return nil, nil, nil, fail("JournalUnavailable")
	}
	if !trustMatchesAuthority(trust, current) {
		closeStorage()
		return nil, nil, nil, fail("AuthorityUpgradeRequired")
	}
	enrollment, ok := current.Enrollments[r.Config.InstallationID]
	if !ok || enrollment.BootstrapGeneration != r.Config.BootstrapGeneration || enrollment.Namespace != r.Config.Namespace || enrollment.OperatorServiceAccount != r.Config.ServiceAccount || enrollment.NodeFingerprint != trust.NodeFingerprint || enrollment.IdentityKeySecretUID != r.Config.IdentityKeySecret.UID || enrollment.TrustBundleSecretUID != r.Config.TrustBundleSecret.UID {
		closeStorage()
		return nil, nil, nil, fail("EnrollmentMismatch")
	}
	ca, err = r.Config.CABytes(ctx, r.Reader, h.FencerCAConfigMapRef)
	if err != nil {
		closeStorage()
		return nil, nil, nil, err
	}
	f, err := fencing.NewClient(fencing.ClientConfig{Origin: h.FencerOrigin, AllowedOrigins: h.AllowedFencerOrigins, CustomCAPEM: ca, TokenFile: r.FencerTokenFile, PodUID: r.PodUID, ExpectedLeaseHolderIdentity: r.LeaseHolderIdentity, InstallationID: r.Config.InstallationID, LogID: h.Journal.LogID, MinimumCursor: h.Journal.MinimumCursor, Journal: ledger})
	if err != nil {
		closeStorage()
		return nil, nil, nil, fail("FencingUnavailable")
	}
	closeAll := func() { f.Close(); closeStorage() }
	session, err := f.Acquire(ctx, r.Config.InstallationID, r.Config.BootstrapGeneration)
	if err == nil {
		session, err = f.Barriers(ctx, session)
	}
	if err != nil {
		closeAll()
		return nil, nil, nil, fail("FencingUnavailable")
	}
	check := func(ctx context.Context, accepted *witness.Head) error {
		if err := f.Ready(ctx, session); err != nil {
			return fenceReadyFailure(err)
		}
		// Acquisition may race an authority/enrollment transition. A fresh grant
		// under a new policy must not let an old independently pinned reader write.
		state, err := ledger.ReadCurrent(ctx, h.Journal.LogID, h.Journal.MinimumCursor)
		if err != nil {
			return fail("JournalUnavailable")
		}
		if !trustMatchesAuthority(trust, state) {
			return fail("AuthorityUpgradeRequired")
		}
		if accepted != nil && *accepted != state.Head() {
			return fail("CanonicalHeadMismatch")
		}
		enrolled, ok := state.Enrollments[r.Config.InstallationID]
		if !ok || enrolled.BootstrapGeneration != r.Config.BootstrapGeneration || enrolled.Namespace != r.Config.Namespace || enrolled.OperatorServiceAccount != r.Config.ServiceAccount || enrolled.NodeFingerprint != trust.NodeFingerprint || enrolled.IdentityKeySecretUID != r.Config.IdentityKeySecret.UID || enrolled.TrustBundleSecretUID != r.Config.TrustBundleSecret.UID {
			return fail("EnrollmentMismatch")
		}
		return nil
	}
	if err := check(ctx, nil); err != nil {
		closeAll()
		return nil, nil, nil, err
	}
	return fencing.Writer(r.Writer, session), check, closeAll, nil
}

// Diagnostic projection remains closed even if an upstream error type carries
// an arbitrary reason. Every result still denies the pending operation.
func fenceReadyFailure(err error) error {
	switch fencing.Reason(err) {
	case "JournalUnavailable":
		return fail("FenceJournalUnavailable")
	case "FencerUnavailable":
		return fail("FenceTransportUnavailable")
	case "LeaseMismatch":
		return fail("FenceLeaseMismatch")
	case "LeaseExpired":
		return fail("FenceLeaseExpired")
	case "LeaseUnavailable":
		return fail("FenceLeaseUnavailable")
	case "GrantChanged", "GrantInvalid", "GrantUnavailable":
		return fail("FenceGrantChanged")
	case "BarriersIncomplete", "ObjectMissing", "ObjectReplaced", "ObjectDenied":
		return fail("FenceBarriersIncomplete")
	case "ProjectedTokenInvalid":
		return fail("FenceTokenInvalid")
	case "ProjectedTokenUnavailable":
		return fail("FenceTokenUnavailable")
	case "AuthenticationDenied", "BoundPodRequired":
		return fail("FenceAuthenticationDenied")
	case "IdentityMismatch", "IdentityRoleCollision", "NamespaceReplaced", "ServiceAccountReplaced", "PodReplaced":
		return fail("FenceIdentityMismatch")
	case "EnrollmentMismatch":
		return fail("FenceEnrollmentMismatch")
	case "FencerBusy":
		return fail("FenceBusy")
	case "Cancelled":
		return fail("FenceCancelled")
	case "ResponseInvalid":
		return fail("FenceResponseInvalid")
	case "RedirectDenied":
		return fail("FenceRedirectDenied")
	default:
		return fail("FenceDenied")
	}
}

func trustMatchesAuthority(t verification.Trust, s journal.CurrentState) bool {
	if t.Scope != s.Head().Scope || t.PublisherPolicyEpoch != s.Authority.PublisherPolicyEpoch || t.WitnessEpoch != s.Authority.WitnessEpoch || t.WitnessKeyID != s.Authority.WitnessKey.KeyID || len(t.PublisherKeys) != len(s.Authority.PublisherKeys) {
		return false
	}
	w, err := e2e2.DecodeBase64(s.Authority.WitnessKey.PublicKey, 32)
	if err != nil || !bytes.Equal(w, t.WitnessPublicKey) {
		return false
	}
	for _, key := range s.Authority.PublisherKeys {
		p, err := e2e2.DecodeBase64(key.PublicKey, 32)
		if err != nil || !bytes.Equal(p, t.PublisherKeys[key.KeyID]) {
			return false
		}
	}
	return true
}
