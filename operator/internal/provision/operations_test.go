package provision

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	"github.com/mihsergeev/Sekvyr/operator/internal/recovery"
	"github.com/mihsergeev/Sekvyr/operator/internal/syncer"
	"github.com/mihsergeev/Sekvyr/operator/internal/verification"
)

type memoryFiles map[string][]byte

func (m memoryFiles) ReadFile(path string, max int) ([]byte, error) {
	v, ok := m[path]
	if !ok || len(v) > max {
		return nil, ErrFiles
	}
	return bytes.Clone(v), nil
}
func put(t *testing.T, f memoryFiles, path string, v any) {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	f[path] = b
}

type fixture struct {
	f       memoryFiles
	reg     journal.Registration
	records []journal.Record
	state   journal.CurrentState
	keys    map[string]PublicKey
	scope   e2e2.Scope
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	x := &fixture{f: memoryFiles{}, keys: map[string]PublicKey{}, scope: e2e2.Scope{RealmID: uuid.NewString(), ProjectID: uuid.NewString(), EnvironmentID: uuid.NewString(), ViewID: uuid.NewString(), LogID: uuid.NewString()}}
	for _, role := range []string{"admin", "publisher", "witness", "fencer", "node", "read"} {
		a, e := keygen(role)
		if e != nil {
			t.Fatal(e)
		}
		for n, b := range a {
			x.f[role+"/"+n] = b
		}
		if role != "read" {
			var d PublicKey
			if json.Unmarshal(a["public.json"], &d) != nil {
				t.Fatal("public output")
			}
			x.keys[role] = d
		}
	}
	a := journal.Authority{Revision: "1", AdminKey: x.keys["admin"].journalKey(), PublisherPolicyEpoch: "1", PublisherKeys: []journal.Key{x.keys["publisher"].journalKey()}, ReadKeyEpoch: "1", WitnessEpoch: "1", WitnessKey: x.keys["witness"].journalKey(), FencerEpoch: "1", FencerKeys: []journal.Key{x.keys["fencer"].journalKey()}}
	put(t, x.f, "genesis-body", journal.GenesisBody{Format: "sekvyr-journal-genesis-v1", Scope: x.scope, PanelOrigin: "https://panel.example.invalid", Authority: a})
	out, e := genesis(x.f, GenesisRequest{BodyFile: "genesis-body", AdminKeyFile: "admin/private.pem", AdminPublicFile: "admin/public.json"})
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(out["registration.json"], &x.reg) != nil || json.Unmarshal(out["records.json"], &x.records) != nil {
		t.Fatal("genesis output")
	}
	x.refresh(t)
	return x
}
func (x *fixture) refresh(t *testing.T) {
	t.Helper()
	put(t, x.f, "registration", x.reg)
	put(t, x.f, "records", x.records)
	slots := []journal.StoredSlot{}
	for _, r := range x.records {
		b, e := journal.EncodeRecord(r)
		if e != nil {
			t.Fatal(e)
		}
		slots = append(slots, journal.StoredSlot{Raw: b})
	}
	s, e := journal.Replay(x.reg, slots)
	if e != nil {
		t.Fatal(e)
	}
	x.state = s
}
func (x *fixture) chain() ChainFiles {
	return ChainFiles{RegistrationFile: "registration", RecordsFile: "records", ExpectedCursor: x.state.Cursor}
}
func (x *fixture) commit(t *testing.T, out artifacts) {
	t.Helper()
	var r journal.Record
	if json.Unmarshal(out["record.json"], &r) != nil {
		t.Fatal("not a canonical candidate")
	}
	x.records = append(x.records, r)
	x.refresh(t)
}
func (x *fixture) snapshotRequest(t *testing.T) SnapshotRequest {
	t.Helper()
	sequence, e := nextCounter(x.state.Snapshot.Sequence)
	if e != nil {
		t.Fatal(e)
	}
	action := "update"
	if sequence == "1" {
		action = "initial"
	}
	put(t, x.f, "header", e2e2.Header{Protocol: "e2e2", Suite: "HKDF-SHA256+A256GCM+Ed25519", Intent: "publish", Scope: x.scope, Sequence: sequence, PreviousHash: x.state.Snapshot.EnvelopeHash, ReadKeyEpoch: x.state.Authority.ReadKeyEpoch, PublisherPolicyEpoch: x.state.Authority.PublisherPolicyEpoch, PublisherKeyID: x.keys["publisher"].KeyID, EntryCount: 1, Action: action, Parents: []e2e2.Parent{}})
	put(t, x.f, "plaintext", e2e2.Plaintext{Format: "sekvyr-e2e2-values-v1", Context: x.scope, Entries: []e2e2.Entry{{Path: "/", Name: "DEMO_VALUE", Value: "public synthetic canary"}}})
	return SnapshotRequest{Chain: x.chain(), HeaderFile: "header", PlaintextFile: "plaintext", ReadKeyFile: "read/read-key.bin", PublisherKeyFile: "publisher/private.pem", PublisherPublicFile: "publisher/public.json", RecipientPublicFile: "node/public.json"}
}
func (x *fixture) transitionBody(kind string) journal.TransitionBody {
	a := x.state.Authority
	a.Revision, _ = nextCounter(a.Revision)
	return journal.TransitionBody{Format: "sekvyr-authority-transition-v1", Scope: x.scope, GenesisHash: x.reg.GenesisHash, Expected: x.state.Cursor, PreviousAuthorityDigest: x.state.AuthorityDigest, Kind: kind, Authority: a}
}

func TestNativeSnapshotAndWrapConsumers(t *testing.T) {
	x := newFixture(t)
	r := x.snapshotRequest(t)
	out, e := snapshot(x.f, r)
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := e2e2.DecodeBase64(x.keys["publisher"].PublicKey, 32)
	hash, _ := e2e2.EnvelopeHash(out["envelope.json"])
	v, e := e2e2.VerifyEnvelope(out["envelope.json"], e2e2.Expected{Scope: x.scope, Sequence: "1", EnvelopeHash: hash, ReadKeyEpoch: "1", PublisherPolicyEpoch: "1", PublisherKeys: map[string]ed25519.PublicKey{x.keys["publisher"].KeyID: pub}})
	if e != nil {
		t.Fatal(e)
	}
	node, e := parsePrivate(x.f["node/private.pem"])
	if e != nil {
		t.Fatal(e)
	}
	key, e := e2e2.UnwrapReader(out["reader-wrap.json"], node.(*ecdh.PrivateKey), v)
	if e != nil || !bytes.Equal(key, x.f["read/read-key.bin"]) {
		t.Fatal("native unwrap", e)
	}
	decoded, e := v.Decrypt(key)
	if e != nil || decoded.Entries[0].Value != "public synthetic canary" {
		t.Fatal("native decrypt", e)
	}
	clear(key)
	wrong, e := keygen("node")
	if e != nil {
		t.Fatal(e)
	}
	n, e := parsePrivate(wrong["private.pem"])
	if e != nil {
		t.Fatal(e)
	}
	if _, e = e2e2.UnwrapReader(out["reader-wrap.json"], n.(*ecdh.PrivateKey), v); e == nil {
		t.Fatal("wrong recipient accepted")
	}
	x.commit(t, out)
	if x.state.Snapshot.Sequence != "1" {
		t.Fatal("native journal consume")
	}
}
func TestPendingRotationRequiresAtomicAdminTransition(t *testing.T) {
	x := newFixture(t)
	r := x.snapshotRequest(t)
	first, e := snapshot(x.f, r)
	if e != nil {
		t.Fatal(e)
	}
	x.commit(t, first)
	r = x.snapshotRequest(t)
	var h e2e2.Header
	json.Unmarshal(x.f["header"], &h)
	h.ReadKeyEpoch = "2"
	h.Action = "rotate-read-key"
	put(t, x.f, "header", h)
	if _, e = snapshot(x.f, r); e == nil {
		t.Fatal("pending used as canonical")
	}
	r.Pending = true
	pending, e := snapshot(x.f, r)
	if e != nil {
		t.Fatal(e)
	}
	if pending["record.json"] != nil {
		t.Fatal("pending record exported")
	}
	var env e2e2.Envelope
	json.Unmarshal(pending["envelope.json"], &env)
	b := x.transitionBody("rotate-read-key")
	b.Authority.ReadKeyEpoch = "2"
	b.ActivatingEnvelope = &env
	put(t, x.f, "transition-body", b)
	req := TransitionRequest{Chain: x.chain(), BodyFile: "transition-body", AdminKeyFile: "admin/private.pem"}
	good, e := transition(x.f, req)
	if e != nil {
		t.Fatal(e)
	}
	b.ActivatingEnvelope = nil
	put(t, x.f, "transition-body", b)
	if _, e = transition(x.f, req); e == nil {
		t.Fatal("ignored activation")
	}
	b.ActivatingEnvelope = &env
	b.Authority.ReadKeyEpoch = "3"
	put(t, x.f, "transition-body", b)
	if _, e = transition(x.f, req); e == nil {
		t.Fatal("epoch mismatch")
	}
	x.commit(t, good)
	if x.state.Authority.ReadKeyEpoch != "2" || x.state.Snapshot.Sequence != "2" {
		t.Fatal("atomic rotation consumer")
	}
}

func TestPublisherRotationPendingAndRoleSeparation(t *testing.T) {
	x := newFixture(t)
	first, err := snapshot(x.f, x.snapshotRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	x.commit(t, first)
	next, err := keygen("publisher")
	if err != nil {
		t.Fatal(err)
	}
	x.f["new-publisher/private.pem"] = next["private.pem"]
	x.f["new-publisher/public.json"] = next["public.json"]
	var pub PublicKey
	if json.Unmarshal(next["public.json"], &pub) != nil {
		t.Fatal("public descriptor")
	}
	r := x.snapshotRequest(t)
	r.Pending = true
	r.PublisherKeyFile = "new-publisher/private.pem"
	r.PublisherPublicFile = "new-publisher/public.json"
	var h e2e2.Header
	json.Unmarshal(x.f["header"], &h)
	h.PublisherKeyID = pub.KeyID
	put(t, x.f, "header", h)
	if _, err = snapshot(x.f, r); err == nil {
		t.Fatal("new publisher in old policy epoch")
	}
	h.PublisherPolicyEpoch = "2"
	put(t, x.f, "header", h)
	rogue := x.keys["witness"]
	rogue.Role = "publisher"
	put(t, x.f, "role-confused-public", rogue)
	savedHeader := h
	h.PublisherKeyID = rogue.KeyID
	put(t, x.f, "header", h)
	bad := r
	bad.PublisherPublicFile = "role-confused-public"
	bad.PublisherKeyFile = "witness/private.pem"
	if _, err = snapshot(x.f, bad); err == nil {
		t.Fatal("pending known-role substitution")
	}
	h = savedHeader
	put(t, x.f, "header", h)
	pending, err := snapshot(x.f, r)
	if err != nil {
		t.Fatal(err)
	}
	if pending["record.json"] != nil {
		t.Fatal("pending exported canonical record")
	}
	var envelope e2e2.Envelope
	json.Unmarshal(pending["envelope.json"], &envelope)
	body := x.transitionBody("rotate-publisher")
	body.Authority.PublisherPolicyEpoch = "2"
	body.Authority.PublisherKeys = []journal.Key{pub.journalKey()}
	body.ActivatingEnvelope = &envelope
	put(t, x.f, "transition-body", body)
	output, err := transition(x.f, TransitionRequest{Chain: x.chain(), BodyFile: "transition-body", AdminKeyFile: "admin/private.pem"})
	if err != nil {
		t.Fatal(err)
	}
	x.commit(t, output)
	if x.state.Authority.PublisherKeys[0] != pub.journalKey() {
		t.Fatal("rotation lost publisher")
	}
	var genesisBody journal.GenesisBody
	json.Unmarshal(x.f["genesis-body"], &genesisBody)
	genesisBody.Authority.WitnessKey = genesisBody.Authority.AdminKey
	put(t, x.f, "invalid-genesis-body", genesisBody)
	if _, err = genesis(x.f, GenesisRequest{BodyFile: "invalid-genesis-body", AdminKeyFile: "admin/private.pem", AdminPublicFile: "admin/public.json"}); err == nil {
		t.Fatal("validly signed but role-confused genesis")
	}
}

func TestRoleSpecificKeyOutputs(t *testing.T) {
	for _, role := range []string{"admin", "publisher", "witness", "fencer", "node", "read"} {
		t.Run(role, func(t *testing.T) {
			a, err := keygen(role)
			if err != nil {
				t.Fatal(err)
			}
			if role == "read" {
				if len(a) != 1 || len(a["read-key.bin"]) != 32 {
					t.Fatal("read role exports other key material")
				}
				return
			}
			if len(a) != 2 {
				t.Fatal("unexpected role bundle")
			}
			f := memoryFiles{"private": a["private.pem"]}
			out, err := publicArtifact(f, PublicRequest{Role: role, PrivateFile: "private"})
			if err != nil || !bytes.Equal(a["public.json"], out["public.json"]) {
				t.Fatal("PKCS8 public roundtrip", err)
			}
			if _, err = publicArtifact(f, PublicRequest{Role: "read", PrivateFile: "private"}); err == nil {
				t.Fatal("read public oracle")
			}
		})
	}
	if _, err := keygen("all"); err == nil {
		t.Fatal("all-role private bundle exposed")
	}
}
func TestIndependentPinsAndExactCursor(t *testing.T) {
	x := newFixture(t)
	r := x.snapshotRequest(t)
	tests := map[string]func(){
		"stale expected":             func() { r.Chain.ExpectedCursor.JournalSequence = "1" },
		"floor above chain":          func() { x.reg.MinimumCursor.JournalSequence = "1"; put(t, x.f, "registration", x.reg) },
		"fork floor":                 func() { x.reg.MinimumCursor.RecordHash = strings.Repeat("a", 64); put(t, x.f, "registration", x.reg) },
		"incoming state":             func() { put(t, x.f, "records", x.state) },
		"wrong admin pin":            func() { x.reg.AdminPublicKey = x.keys["witness"].PublicKey; put(t, x.f, "registration", x.reg) },
		"wrong publisher private":    func() { r.PublisherKeyFile = "witness/private.pem" },
		"wrong publisher descriptor": func() { r.PublisherPublicFile = "witness/public.json" },
		"wrong node descriptor":      func() { r.RecipientPublicFile = "publisher/public.json" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			savedReg, savedRecords := bytes.Clone(x.f["registration"]), bytes.Clone(x.f["records"])
			savedReq, savedPin := r, x.reg
			change()
			if _, e := snapshot(x.f, r); e == nil {
				t.Fatal("authority bypass")
			}
			r = savedReq
			x.reg = savedPin
			x.f["registration"] = savedReg
			x.f["records"] = savedRecords
		})
	}
}
func TestStrictInputsNoSecretFormatting(t *testing.T) {
	for _, raw := range []string{`{"role":"admin","role":"publisher"}`, `{"Role":"admin"}`, `{"role":null}`, `{"role":"admin","private_key":"synthetic-private-canary"}`, `{"role":"admin"} {}`, `{"role":"read","n":1.0}`} {
		if _, e := execute("keygen", []byte(raw), memoryFiles{}, time.Now()); e == nil || strings.Contains(e.Error(), "synthetic-private-canary") {
			t.Fatal("strict input/error failure")
		}
	}
	for _, command := range []string{"head-proof", "fence-grant", "fence-activation", "apply", "discover"} {
		if _, e := execute(command, []byte(`{}`), nil, time.Now()); e == nil {
			t.Fatal("online command exposed")
		}
	}
	a := artifacts{"private.pem": []byte("synthetic-private-canary")}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, a), "synthetic-private-canary") {
			t.Fatal("format leak")
		}
	}
	if _, e := Run(nil, "keygen", "/unused", "input", "output", time.Now()); e == nil {
		t.Fatal("nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Run(ctx, "keygen", "/unused", "input", "output", time.Now()); e == nil {
		t.Fatal("cancelled context")
	}
}

func (x *fixture) installation(t *testing.T) (installation.Config, UIDReceipts, api.Binding) {
	t.Helper()
	ca := installation.CARef{Name: "ca", Key: "ca.crt"}
	c := installation.Config{InstallationID: uuid.NewString(), Namespace: "trial-apps", ServiceAccount: "operator", ServiceAccountUID: uuid.NewString(), LeaderElectionLeaseName: "leader", LeaderElectionLeaseUID: uuid.NewString(), BootstrapGeneration: 1, AllowedPanelOrigins: []string{x.state.PanelOrigin}, AllowedWitnessOrigins: []string{"https://witness.example.invalid"}, IdentityKeySecret: installation.SecretPin{Name: "node", UID: uuid.NewString(), Key: "node.pem"}, TrustBundleSecret: installation.SecretPin{Name: "trust", UID: uuid.NewString(), Key: "trust.json"}, StateSecret: installation.SecretPin{Name: "state", UID: uuid.NewString(), Key: "installation.json"}, AllowedTargetSecrets: []string{"target"}, CAConfigMaps: []installation.CAPin{{Name: ca.Name, UID: uuid.NewString(), Key: ca.Key, DERSetSHA256: strings.Repeat("a", 64)}}}
	c.HA = &installation.HAConfig{Trial: true, FencerOrigin: "https://fencer.example.invalid", AllowedFencerOrigins: []string{"https://fencer.example.invalid"}, FencerCAConfigMapRef: &ca, GatewayOrigin: "https://gateway.example.invalid", GatewayCAConfigMapRef: &ca, GatewayClientSecret: installation.SecretPin{Name: "gateway-client", UID: uuid.NewString(), Key: "tls.crt"}, GatewayClientKeyKey: "tls.key", Journal: x.reg}
	b := api.Binding{ID: uuid.NewString(), Name: "app", ResourceName: "app-secret", Source: api.Source{Project: "demo", Environment: "prod", PathPrefix: "/", ViewID: x.scope.ViewID}, Selection: api.Selection{Mode: "All"}, Encryption: api.Encryption{Mode: "E2E", Protocol: "e2e2", TrustKey: "view", Freshness: &api.Freshness{Mode: "WitnessCurrent"}}, Target: api.Target{Name: "target"}, Rollout: api.BindingRollout{AllowedDeployments: []string{}}}
	e := journal.Enrollment{InstallationID: c.InstallationID, BootstrapGeneration: 1, Namespace: c.Namespace, NamespaceUID: uuid.NewString(), OperatorServiceAccount: c.ServiceAccount, OperatorServiceAccountUID: c.ServiceAccountUID, FencerServiceAccount: "fencer", FencerServiceAccountUID: uuid.NewString(), Lease: journal.ObjectRef{APIVersion: "coordination.k8s.io/v1", Kind: "Lease", Namespace: c.Namespace, Name: c.LeaderElectionLeaseName, UID: c.LeaderElectionLeaseUID}, NodeFingerprint: x.keys["node"].KeyID, IdentityKeySecretUID: c.IdentityKeySecret.UID, TrustBundleSecretUID: c.TrustBundleSecret.UID, AllowedObjects: []journal.ObjectRef{{APIVersion: "v1", Kind: "Secret", Namespace: c.Namespace, Name: c.StateSecret.Name, UID: c.StateSecret.UID}, {APIVersion: "v1", Kind: "Secret", Namespace: c.Namespace, Name: b.Target.Name, UID: uuid.NewString()}}}
	receipt := UIDReceipts{Enrollment: e, Binding: recovery.Binding{StoreName: "store", StoreUID: uuid.NewString(), CRName: b.ResourceName, CRUID: uuid.NewString(), BindingID: b.ID, ViewID: x.scope.ViewID, TargetName: b.Target.Name, TargetUID: e.AllowedObjects[1].UID, CRGeneration: 1, StoreGeneration: 1, Identity: syncer.BindingIdentity(b)}}
	put(t, x.f, "config", c)
	put(t, x.f, "receipts", receipt)
	put(t, x.f, "binding", b)
	return c, receipt, b
}
func TestBootstrapAndRecoveryNativeConsumers(t *testing.T) {
	x := newFixture(t)
	out, e := snapshot(x.f, x.snapshotRequest(t))
	if e != nil {
		t.Fatal(e)
	}
	x.commit(t, out)
	c, receipts, b := x.installation(t)
	transitionBody := x.transitionBody("enroll-installation")
	transitionBody.Enrollment = &receipts.Enrollment
	put(t, x.f, "transition-body", transitionBody)
	enrolled, e := transition(x.f, TransitionRequest{Chain: x.chain(), BodyFile: "transition-body", AdminKeyFile: "admin/private.pem"})
	if e != nil {
		t.Fatal(e)
	}
	x.commit(t, enrolled)
	reviewedReceipts := receipts
	receipts.Binding.Identity = ""
	put(t, x.f, "receipts", receipts)
	request := BootstrapRequest{Chain: x.chain(), ConfigFile: "config", ReceiptsFile: "receipts", BindingFile: "binding", NodePublicFile: "node/public.json", TrustKey: b.Encryption.TrustKey, PublisherKeyID: x.keys["publisher"].KeyID}
	info := &preparationInfo{}
	boot, e := bootstrapPrepared(x.f, request, info)
	if e != nil {
		t.Fatal(e)
	}
	wantReceipts, _ := encode(reviewedReceipts, 64<<10)
	if !info.identityComputed || !bytes.Equal(boot["receipts.json"], wantReceipts) {
		t.Fatal("derived identity altered reviewed metadata")
	}
	if json.Unmarshal(boot["receipts.json"], &receipts) != nil || receipts.Binding.Identity != syncer.BindingIdentity(b) {
		t.Fatal("normalized identity")
	}
	x.f["receipts"] = bytes.Clone(boot["receipts.json"])
	if _, e = installation.Decode(bytes.NewReader(boot["installation.json"])); e != nil {
		t.Fatal("native installation", e)
	}
	if _, e = verification.DecodeTrustBundle(boot["trust.json"], verification.InstallationIdentity{InstallationID: c.InstallationID, Namespace: c.Namespace, ServiceAccount: c.ServiceAccount, PanelOrigin: x.state.PanelOrigin, BootstrapGeneration: 1, NodeFingerprint: x.keys["node"].KeyID, AllowedWitnessOrigins: c.AllowedWitnessOrigins}); e != nil {
		t.Fatal("native trust", e)
	}
	for name, change := range map[string]func(){
		"namespace receipt":        func() { receipts.Enrollment.Namespace = "other" },
		"secret UID receipt":       func() { receipts.Enrollment.IdentityKeySecretUID = uuid.NewString() },
		"store UID receipt":        func() { receipts.Binding.StoreUID = "invalid" },
		"explicit wrong identity":  func() { receipts.Binding.Identity = strings.Repeat("b", 64) },
		"node fingerprint receipt": func() { receipts.Enrollment.NodeFingerprint = x.keys["publisher"].KeyID },
		"foreign object receipt":   func() { receipts.Enrollment.AllowedObjects[1].Namespace = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			saved, _ := json.Marshal(receipts)
			change()
			put(t, x.f, "receipts", receipts)
			if _, err := bootstrap(x.f, request); err == nil {
				t.Fatal("UID receipt mismatch")
			}
			json.Unmarshal(saved, &receipts)
			put(t, x.f, "receipts", receipts)
		})
	}
	now := time.Now().UTC().Truncate(time.Second)
	body := recovery.Body{Format: "sekvyr-checkpoint-recovery-v1", Operation: "initialize", RecoveryID: uuid.NewString(), InstallationID: c.InstallationID, BootstrapGeneration: 1, StateSecretName: c.StateSecret.Name, StateSecretUID: c.StateSecret.UID, IdentityKeySecretUID: c.IdentityKeySecret.UID, TrustBundleSecretUID: c.TrustBundleSecret.UID, NodeFingerprint: x.keys["node"].KeyID, Scope: x.scope, GenesisHash: x.reg.GenesisHash, Cursor: x.state.Cursor, Snapshot: x.state.Snapshot, Binding: receipts.Binding, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), ExpectedStateSHA256: syncer.StateDigest(nil)}
	put(t, x.f, "recovery-body", body)
	req := RecoveryRequest{Chain: x.chain(), ConfigFile: "config", ReceiptsFile: "receipts", BindingFile: "binding", BodyFile: "recovery-body", AdminKeyFile: "admin/private.pem"}
	plan, e := recoveryPlan(x.f, req, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = recovery.Verify(context.Background(), plan["plan.json"], c, x.state, now); e != nil {
		t.Fatal("native recovery plan", e)
	}
	savedReceiptRaw := bytes.Clone(x.f["receipts"])
	emptyReceipt := receipts
	emptyReceipt.Binding.Identity = ""
	put(t, x.f, "receipts", emptyReceipt)
	if a, err := recoveryPlan(x.f, req, now); err == nil || a != nil {
		t.Fatal("recovery silently derived empty receipt identity")
	}
	var missing map[string]any
	json.Unmarshal(savedReceiptRaw, &missing)
	delete(missing["binding"].(map[string]any), "identity")
	put(t, x.f, "receipts", missing)
	if a, err := recoveryPlan(x.f, req, now); err == nil || a != nil {
		t.Fatal("recovery accepted missing receipt identity")
	}
	x.f["receipts"] = savedReceiptRaw
	emptyBody := body
	emptyBody.Binding.Identity = ""
	put(t, x.f, "recovery-body", emptyBody)
	if a, err := recoveryPlan(x.f, req, now); err == nil || a != nil {
		t.Fatal("recovery silently filled signed body identity")
	}
	put(t, x.f, "recovery-body", body)
	for name, change := range map[string]func(){"expired": func() { body.ExpiresAt = now.Format(time.RFC3339) }, "over24h": func() { body.ExpiresAt = now.Add(25 * time.Hour).Format(time.RFC3339) }, "wrong state bytes": func() { body.ExpectedStateSHA256 = strings.Repeat("b", 64) }, "binding forgery": func() { body.Binding.Identity = strings.Repeat("b", 64) }, "wrong cursor": func() { body.Cursor.RecordHash = strings.Repeat("b", 64) }} {
		t.Run(name, func(t *testing.T) {
			saved := body
			change()
			put(t, x.f, "recovery-body", body)
			if _, e := recoveryPlan(x.f, req, now); e == nil {
				t.Fatal("recovery bypass")
			}
			body = saved
		})
	}
}

func TestGenerationTwoRecoveryUsesExactStateBytesAndSignedEnrollment(t *testing.T) {
	x := newFixture(t)
	first, err := snapshot(x.f, x.snapshotRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	x.commit(t, first)
	c, receipts, binding := x.installation(t)
	enroll := func() {
		body := x.transitionBody("enroll-installation")
		body.Enrollment = &receipts.Enrollment
		put(t, x.f, "transition-body", body)
		out, e := transition(x.f, TransitionRequest{Chain: x.chain(), BodyFile: "transition-body", AdminKeyFile: "admin/private.pem"})
		if e != nil {
			t.Fatal(e)
		}
		x.commit(t, out)
	}
	enroll()
	oldStateUID := c.StateSecret.UID
	c.BootstrapGeneration = 2
	c.StateSecret = installation.SecretPin{Name: "state-gen2", UID: uuid.NewString(), Key: "installation.json"}
	c.TrustBundleSecret = installation.SecretPin{Name: "trust-gen2", UID: uuid.NewString(), Key: "trust.json"}
	receipts.Enrollment.BootstrapGeneration = 2
	receipts.Enrollment.TrustBundleSecretUID = c.TrustBundleSecret.UID
	receipts.Enrollment.AllowedObjects[0].Name = c.StateSecret.Name
	receipts.Enrollment.AllowedObjects[0].UID = c.StateSecret.UID
	put(t, x.f, "config", c)
	put(t, x.f, "receipts", receipts)
	put(t, x.f, "binding", binding)
	retained := []byte(`{"public_test_state":"exact previous retained state bytes"}`)
	x.f["retained-state"] = retained
	now := time.Now().UTC().Truncate(time.Second)
	makeBody := func() recovery.Body {
		return recovery.Body{Format: "sekvyr-checkpoint-recovery-v1", Operation: "recover", RecoveryID: uuid.NewString(), InstallationID: c.InstallationID, PreviousBootstrapGeneration: 1, PreviousStateSecretUID: oldStateUID, BootstrapGeneration: 2, StateSecretName: c.StateSecret.Name, StateSecretUID: c.StateSecret.UID, IdentityKeySecretUID: c.IdentityKeySecret.UID, TrustBundleSecretUID: c.TrustBundleSecret.UID, NodeFingerprint: receipts.Enrollment.NodeFingerprint, Scope: x.scope, GenesisHash: x.reg.GenesisHash, Cursor: x.state.Cursor, Snapshot: x.state.Snapshot, Binding: receipts.Binding, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), ExpectedStateSHA256: syncer.StateDigest(retained)}
	}
	body := makeBody()
	put(t, x.f, "recovery-body", body)
	req := RecoveryRequest{Chain: x.chain(), ConfigFile: "config", ReceiptsFile: "receipts", BindingFile: "binding", BodyFile: "recovery-body", StateFile: "retained-state", AdminKeyFile: "admin/private.pem"}
	if _, err = recoveryPlan(x.f, req, now); err == nil {
		t.Fatal("new generation not independently enrolled")
	}
	enroll()
	body = makeBody()
	put(t, x.f, "recovery-body", body)
	req.Chain = x.chain()
	plan, err := recoveryPlan(x.f, req, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = recovery.Verify(context.Background(), plan["plan.json"], c, x.state, now); err != nil {
		t.Fatal("native gen2 verifier", err)
	}
	x.f["retained-state"] = append(bytes.Clone(retained), ' ')
	if _, err = recoveryPlan(x.f, req, now); err == nil {
		t.Fatal("state bytes silently normalized")
	}
}
