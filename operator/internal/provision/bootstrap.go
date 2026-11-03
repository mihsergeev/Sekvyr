package provision

import (
	"context"
	"reflect"
	"time"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/controller"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	"github.com/mihsergeev/Sekvyr/operator/internal/recovery"
	"github.com/mihsergeev/Sekvyr/operator/internal/syncer"
	"github.com/mihsergeev/Sekvyr/operator/internal/verification"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type materialInput struct {
	config           installation.Config
	receipts         UIDReceipts
	binding          api.Binding
	identityComputed bool
}

func material(f files, p replayed, configFile, receiptsFile, bindingFile string, allowDerivedIdentity bool) (materialInput, error) {
	var m materialInput
	if decodeFile(f, configFile, &m.config, 64<<10) != nil || m.config.Validate() != nil || m.config.HA == nil || decodeFile(f, receiptsFile, &m.receipts, 64<<10) != nil || decodeFile(f, bindingFile, &m.binding, 64<<10) != nil {
		return m, ErrInvalid
	}
	c := m.config
	e := m.receipts.Enrollment
	b := m.receipts.Binding
	if known, ok := p.state.Enrollments[e.InstallationID]; ok && (e.BootstrapGeneration < known.BootstrapGeneration || e.BootstrapGeneration == known.BootstrapGeneration && !reflect.DeepEqual(e, known)) {
		return m, ErrAuthority
	}
	if c.HA.Journal != p.registration || !c.AllowsPanelOrigin(p.state.PanelOrigin) || e.InstallationID != c.InstallationID || e.BootstrapGeneration != c.BootstrapGeneration || e.Namespace != c.Namespace || e.OperatorServiceAccount != c.ServiceAccount || e.OperatorServiceAccountUID != c.ServiceAccountUID || e.Lease.Name != c.LeaderElectionLeaseName || e.Lease.UID != c.LeaderElectionLeaseUID || e.IdentityKeySecretUID != c.IdentityKeySecret.UID || e.TrustBundleSecretUID != c.TrustBundleSecret.UID {
		return m, ErrAuthority
	}
	if e.Lease.APIVersion != "coordination.k8s.io/v1" || e.Lease.Kind != "Lease" || e.Lease.Namespace != c.Namespace || e.FencerServiceAccount == e.OperatorServiceAccount || e.FencerServiceAccountUID == e.OperatorServiceAccountUID || !installation.ValidName(e.FencerServiceAccount) {
		return m, ErrAuthority
	}
	for _, id := range []string{e.InstallationID, e.NamespaceUID, e.OperatorServiceAccountUID, e.FencerServiceAccountUID, e.Lease.UID, e.IdentityKeySecretUID, e.TrustBundleSecretUID, b.StoreUID, b.CRUID, b.BindingID, b.TargetUID} {
		if !installation.ValidUUID(id) {
			return m, ErrInvalid
		}
	}
	refs, err := journal.CanonicalObjectRefs(e.AllowedObjects)
	if err != nil || !reflect.DeepEqual(refs, e.AllowedObjects) {
		return m, ErrInvalid
	}
	if b.BindingID != m.binding.ID || b.TargetName != m.binding.Target.Name || b.ViewID != p.state.Scope.ViewID || m.binding.Source.ViewID != b.ViewID || m.binding.Encryption.Mode != "E2E" || !c.TargetAllowed(b.TargetName) || c.Protected(b.TargetName, types.UID(b.TargetUID)) || b.CRGeneration < 1 || b.StoreGeneration < 1 {
		return m, ErrAuthority
	}
	hasState, hasTarget := false, false
	for _, ref := range e.AllowedObjects {
		if ref.Namespace != c.Namespace || ref.UID == c.IdentityKeySecret.UID || ref.UID == c.TrustBundleSecret.UID {
			return m, ErrAuthority
		}
		if ref.APIVersion == "v1" && ref.Kind == "Secret" && ref.Namespace == c.Namespace {
			hasState = hasState || ref.Name == c.StateSecret.Name && ref.UID == c.StateSecret.UID
			hasTarget = hasTarget || ref.Name == b.TargetName && ref.UID == b.TargetUID
		}
	}
	if !hasState || !hasTarget || b.TargetUID == c.StateSecret.UID {
		return m, ErrAuthority
	}
	store := &api.SekvyrStore{ObjectMeta: metav1.ObjectMeta{Name: b.StoreName, Namespace: c.Namespace, UID: types.UID(b.StoreUID), Generation: b.StoreGeneration}, Spec: api.SekvyrStoreSpec{Endpoint: api.Endpoint{URL: p.state.PanelOrigin}, Bindings: []api.Binding{m.binding}}}
	cr := &api.SekvyrSecret{ObjectMeta: metav1.ObjectMeta{Name: b.CRName, Namespace: c.Namespace, UID: types.UID(b.CRUID), Generation: b.CRGeneration}, Spec: api.SekvyrSecretSpec{StoreRef: api.StoreReference{Name: b.StoreName, UID: b.StoreUID}, Binding: m.binding.Name}}
	if controller.ValidateStore(c, store) != nil {
		return m, ErrInvalid
	}
	if _, err := controller.ValidateSecret(c, cr, store); err != nil {
		return m, ErrInvalid
	}
	identity := syncer.BindingIdentity(m.binding)
	if b.Identity == "" && allowDerivedIdentity {
		m.receipts.Binding.Identity = identity
		m.identityComputed = true
	} else if b.Identity == "" || b.Identity != identity {
		return m, ErrAuthority
	}
	return m, nil
}

type trustBundle struct {
	SchemaVersion            int         `json:"schemaVersion"`
	InstallationID           string      `json:"installationID"`
	BootstrapGeneration      int64       `json:"bootstrapGeneration"`
	Namespace                string      `json:"namespace"`
	ServiceAccount           string      `json:"serviceAccount"`
	PanelOrigin              string      `json:"panelOrigin"`
	NodePublicKeyFingerprint string      `json:"nodePublicKeyFingerprint"`
	ViewTrust                []trustView `json:"viewTrust"`
}
type trustView struct {
	TrustKey                string          `json:"trustKey"`
	StoreUID                string          `json:"storeUID"`
	BindingID               string          `json:"bindingID"`
	RealmID                 string          `json:"realmID"`
	ProjectID               string          `json:"projectID"`
	EnvironmentID           string          `json:"environmentID"`
	ViewID                  string          `json:"viewID"`
	LogID                   string          `json:"logID"`
	PublisherPolicyEpoch    string          `json:"publisherPolicyEpoch"`
	PublisherPublicKey      string          `json:"publisherPublicKey"`
	PublisherKeyFingerprint string          `json:"publisherKeyFingerprint"`
	Witness                 trustWitness    `json:"witness"`
	MinimumCheckpoint       trustCheckpoint `json:"minimumCheckpoint"`
}
type trustWitness struct {
	Origin         string `json:"origin"`
	Epoch          string `json:"epoch"`
	PublicKey      string `json:"publicKey"`
	KeyFingerprint string `json:"keyFingerprint"`
}
type trustCheckpoint struct {
	Sequence     string `json:"sequence"`
	EnvelopeHash string `json:"envelopeHash"`
}

func bootstrap(f files, r BootstrapRequest) (artifacts, error) {
	return bootstrapPrepared(f, r, nil)
}

func bootstrapPrepared(f files, r BootstrapRequest, info *preparationInfo) (artifacts, error) {
	p, err := replay(f, r.Chain)
	if err != nil {
		return nil, err
	}
	m, err := material(f, p, r.ConfigFile, r.ReceiptsFile, r.BindingFile, true)
	if err != nil {
		return nil, err
	}
	node, err := publicFile(f, r.NodePublicFile, "node")
	if err != nil || node.KeyID != m.receipts.Enrollment.NodeFingerprint || r.TrustKey != m.binding.Encryption.TrustKey {
		return nil, ErrAuthority
	}
	var pub string
	for _, key := range p.state.Authority.PublisherKeys {
		if key.KeyID == r.PublisherKeyID {
			pub = key.PublicKey
		}
	}
	if pub == "" {
		return nil, ErrAuthority
	}
	c := m.config
	s := p.state
	scope := s.Scope
	wire := trustBundle{SchemaVersion: 2, InstallationID: c.InstallationID, BootstrapGeneration: c.BootstrapGeneration, Namespace: c.Namespace, ServiceAccount: c.ServiceAccount, PanelOrigin: s.PanelOrigin, NodePublicKeyFingerprint: node.KeyID,
		ViewTrust: []trustView{{TrustKey: r.TrustKey, StoreUID: m.receipts.Binding.StoreUID, BindingID: m.binding.ID, RealmID: scope.RealmID, ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID, ViewID: scope.ViewID, LogID: scope.LogID, PublisherPolicyEpoch: s.Authority.PublisherPolicyEpoch, PublisherPublicKey: pub, PublisherKeyFingerprint: r.PublisherKeyID, Witness: trustWitness{Origin: c.AllowedWitnessOrigins[0], Epoch: s.Authority.WitnessEpoch, PublicKey: s.Authority.WitnessKey.PublicKey, KeyFingerprint: s.Authority.WitnessKey.KeyID}, MinimumCheckpoint: trustCheckpoint{Sequence: s.Snapshot.Sequence, EnvelopeHash: s.Snapshot.EnvelopeHash}}}}
	raw, err := encode(wire, 64<<10)
	if err != nil {
		return nil, err
	}
	bundle, err := verification.DecodeTrustBundle(raw, verification.InstallationIdentity{InstallationID: c.InstallationID, Namespace: c.Namespace, ServiceAccount: c.ServiceAccount, PanelOrigin: s.PanelOrigin, BootstrapGeneration: c.BootstrapGeneration, NodeFingerprint: node.KeyID, AllowedWitnessOrigins: c.AllowedWitnessOrigins})
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err = bundle.Authorize(r.TrustKey, m.receipts.Binding.StoreUID, m.binding.ID, scope.ViewID); err != nil {
		return nil, ErrAuthority
	}
	config, err := encode(c, 64<<10)
	if err != nil {
		return nil, err
	}
	marker, err := encode(installation.StateMarker{InstallationID: c.InstallationID, BootstrapGeneration: c.BootstrapGeneration}, 4096)
	if err != nil {
		return nil, err
	}
	receipts, err := encode(m.receipts, 64<<10)
	if err != nil {
		return nil, err
	}
	if info != nil {
		info.identityComputed = m.identityComputed
	}
	return artifacts{"installation.json": config, "trust.json": raw, "state-marker.json": marker, "receipts.json": receipts}, nil
}
func recoveryPlan(f files, r RecoveryRequest, now time.Time) (artifacts, error) {
	p, err := replay(f, r.Chain)
	if err != nil {
		return nil, err
	}
	m, err := material(f, p, r.ConfigFile, r.ReceiptsFile, r.BindingFile, false)
	if err != nil {
		return nil, err
	}
	var body recovery.Body
	if decodeFile(f, r.BodyFile, &body, recovery.Limit) != nil || body.Binding != m.receipts.Binding {
		return nil, ErrInvalid
	}
	var state []byte
	if r.StateFile == "" {
		if body.Operation != "initialize" {
			return nil, ErrInvalid
		}
	} else {
		state, err = f.ReadFile(r.StateFile, 512<<10)
		if err != nil {
			return nil, ErrFiles
		}
		defer clear(state)
	}
	if body.ExpectedStateSHA256 != syncer.StateDigest(state) {
		return nil, ErrAuthority
	}
	key, err := edKey(f, r.AdminKeyFile)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	plan, err := recovery.Sign(body, key)
	if err != nil {
		return nil, ErrInvalid
	}
	raw, err := encode(plan, recovery.Limit)
	if err != nil {
		return nil, err
	}
	if _, err = recovery.Verify(context.Background(), raw, m.config, p.state, now); err != nil {
		return nil, ErrAuthority
	}
	return artifacts{"plan.json": raw}, nil
}
