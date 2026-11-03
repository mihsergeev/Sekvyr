package journal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/text/unicode/norm"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"k8s.io/apimachinery/pkg/util/validation"
)

func canonical(value any, max int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, Failure("EncodingInvalid")
	}
	out, err := e2e2.Canonical(raw, max)
	if err != nil {
		return nil, Failure("EncodingInvalid")
	}
	return out, nil
}

// DecodeStrict extends the restricted JSON parser to this schema's explicit
// nullable union fields and typed maps. Canonical round-trip equality rejects
// missing fields, case aliases, null scalar coercions and unexpected shapes.
func DecodeStrict(raw []byte, out any, max int) error {
	encoded, err := e2e2.Canonical(raw, max)
	if err != nil {
		return Failure("EncodingInvalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return Failure("EncodingInvalid")
	}
	round, err := canonical(out, max)
	if err != nil || !bytes.Equal(round, encoded) {
		return Failure("EncodingInvalid")
	}
	return nil
}
func hashValue(domain string, value any, max int) (string, error) {
	raw, err := canonical(value, max)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(e2e2.Domain(domain), raw...))
	return hex.EncodeToString(sum[:]), nil
}
func validHash(value string, zero bool) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value && (zero || value != ZeroHash)
}
func validUUID(value string) bool {
	return e2e2.ValidScope(e2e2.Scope{RealmID: value, ProjectID: value, EnvironmentID: value, ViewID: value, LogID: value})
}
func validName(value string) bool {
	return len(value) > 0 && len(value) <= 253 && len(validation.IsDNS1123Subdomain(value)) == 0
}
func validNamespace(value string) bool {
	return len(value) > 0 && len(validation.IsDNS1123Label(value)) == 0
}
func public(key Key) (ed25519.PublicKey, error) {
	pub, err := e2e2.DecodeBase64(key.PublicKey, 32)
	if err != nil || !e2e2.ValidEd25519PublicKey(pub) || key.KeyID != e2e2.KeyID(pub) {
		return nil, Failure("AuthorityInvalid")
	}
	return ed25519.PublicKey(pub), nil
}
func validKeys(keys []Key) bool {
	if len(keys) < 1 || len(keys) > 16 {
		return false
	}
	previous := ""
	for _, key := range keys {
		if _, err := public(key); err != nil || key.KeyID <= previous {
			return false
		}
		previous = key.KeyID
	}
	return true
}
func validAuthority(a Authority) bool {
	for _, counter := range []string{a.Revision, a.PublisherPolicyEpoch, a.ReadKeyEpoch, a.WitnessEpoch, a.FencerEpoch} {
		if _, err := e2e2.Counter(counter, false); err != nil {
			return false
		}
	}
	_, adminErr := public(a.AdminKey)
	_, witnessErr := public(a.WitnessKey)
	if adminErr != nil || witnessErr != nil || !validKeys(a.PublisherKeys) || !validKeys(a.FencerKeys) {
		return false
	}
	_, err := authorityRoles(a, nil)
	return err == nil
}
func authorityRoles(a Authority, previous map[string]string) (map[string]string, error) {
	roles := map[string]string{}
	for id, role := range previous {
		roles[id] = role
	}
	groups := map[string][]Key{"admin": {a.AdminKey}, "witness": {a.WitnessKey}, "publisher": a.PublisherKeys, "fencer": a.FencerKeys}
	for role, keys := range groups {
		for _, key := range keys {
			if existing, ok := roles[key.KeyID]; ok && existing != role {
				return nil, Failure("AuthorityRoleConflict")
			}
			roles[key.KeyID] = role
		}
	}
	return roles, nil
}
func validCursor(c Cursor) bool {
	_, err := e2e2.Counter(c.JournalSequence, true)
	return err == nil && validHash(c.RecordHash, false)
}
func keysMap(keys []Key) map[string]ed25519.PublicKey {
	out := map[string]ed25519.PublicKey{}
	for _, key := range keys {
		p, _ := public(key)
		out[key.KeyID] = p
	}
	return out
}
func signValue(domain string, value any, private ed25519.PrivateKey, max int) (string, error) {
	if len(private) != ed25519.PrivateKeySize || !ed25519.NewKeyFromSeed(private[:32]).Equal(private) {
		return "", Failure("SigningKeyInvalid")
	}
	raw, err := canonical(value, max)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append(e2e2.Domain(domain), raw...))), nil
}
func verifyValue(domain string, value any, keyID, signature string, key Key, max int) error {
	pub, err := public(key)
	if err != nil || keyID != key.KeyID {
		return Failure("SignatureInvalid")
	}
	raw, err := canonical(value, max)
	if err != nil {
		return err
	}
	sig, err := e2e2.DecodeBase64(signature, 64)
	if err != nil || !ed25519.Verify(pub, append(e2e2.Domain(domain), raw...), sig) {
		return Failure("SignatureInvalid")
	}
	return nil
}
func KeyFromPublic(pub ed25519.PublicKey) (Key, error) {
	if !e2e2.ValidEd25519PublicKey(pub) {
		return Key{}, Failure("AuthorityInvalid")
	}
	return Key{KeyID: e2e2.KeyID(pub), PublicKey: base64.RawURLEncoding.EncodeToString(pub)}, nil
}
func RecordHash(r Record) (string, error)   { return hashValue(RecordHashDomain, r, MaxRecordBytes) }
func EncodeRecord(r Record) ([]byte, error) { return canonical(r, MaxRecordBytes) }
func DecodeRecord(raw []byte) (Record, error) {
	var r Record
	if DecodeStrict(raw, &r, MaxRecordBytes) != nil {
		return r, Failure("RecordInvalid")
	}
	return r, nil
}
func FenceGrantHash(body FenceGrant) (string, error) {
	return hashValue(FenceGrantHashDomain, body, 64<<10)
}
func SignFenceGrant(body FenceGrant, private ed25519.PrivateKey) (SignedFenceGrant, error) {
	if !validGrantShape(body) {
		return SignedFenceGrant{}, Failure("GrantInvalid")
	}
	sig, err := signValue(FenceGrantDomain, body, private, 64<<10)
	if err != nil {
		return SignedFenceGrant{}, err
	}
	return SignedFenceGrant{Body: body, KeyID: e2e2.KeyID(private.Public().(ed25519.PublicKey)), Signature: sig}, nil
}
func SignFenceActivation(body FenceActivation, private ed25519.PrivateKey) (SignedFenceActivation, error) {
	if !validActivationShape(body) {
		return SignedFenceActivation{}, Failure("ActivationInvalid")
	}
	sig, err := signValue("sekvyr-e2e2/fence-activation/v1", body, private, 64<<10)
	if err != nil {
		return SignedFenceActivation{}, err
	}
	return SignedFenceActivation{Body: body, KeyID: e2e2.KeyID(private.Public().(ed25519.PublicKey)), Signature: sig}, nil
}
func FenceActivationHash(body FenceActivation) (string, error) {
	return hashValue("sekvyr-e2e2/fence-activation-hash/v1", body, 64<<10)
}
func VerifyFenceActivation(a SignedFenceActivation, authority Authority) error {
	if !validActivationShape(a.Body) {
		return Failure("ActivationInvalid")
	}
	for _, key := range authority.FencerKeys {
		if key.KeyID == a.KeyID {
			return verifyValue("sekvyr-e2e2/fence-activation/v1", a.Body, a.KeyID, a.Signature, key, 64<<10)
		}
	}
	return Failure("SignatureInvalid")
}
func VerifyFenceGrant(grant SignedFenceGrant, authority Authority) error {
	if !validGrantShape(grant.Body) {
		return Failure("GrantInvalid")
	}
	for _, key := range authority.FencerKeys {
		if key.KeyID == grant.KeyID {
			return verifyValue(FenceGrantDomain, grant.Body, grant.KeyID, grant.Signature, key, 64<<10)
		}
	}
	return Failure("SignatureInvalid")
}
func SignGenesis(body GenesisBody, private ed25519.PrivateKey) (SignedGenesis, error) {
	sig, err := signValue(GenesisDomain, body, private, 128<<10)
	if err != nil {
		return SignedGenesis{}, err
	}
	return SignedGenesis{Body: body, KeyID: e2e2.KeyID(private.Public().(ed25519.PublicKey)), Signature: sig}, nil
}
func SignTransition(body TransitionBody, private ed25519.PrivateKey) (SignedTransition, error) {
	sig, err := signValue(TransitionDomain, body, private, MaxRecordBytes)
	if err != nil {
		return SignedTransition{}, err
	}
	return SignedTransition{Body: body, KeyID: e2e2.KeyID(private.Public().(ed25519.PublicKey)), Signature: sig}, nil
}
func ObjectRefKey(r ObjectRef) string {
	return r.APIVersion + "\x00" + r.Kind + "\x00" + r.Namespace + "\x00" + r.Name
}
func CanonicalObjectRefs(refs []ObjectRef) ([]ObjectRef, error) {
	if refs == nil || len(refs) < 1 || len(refs) > 64 {
		return nil, Failure("ObjectRefsInvalid")
	}
	out := append([]ObjectRef(nil), refs...)
	sort.Slice(out, func(i, j int) bool { return ObjectRefKey(out[i]) < ObjectRefKey(out[j]) })
	previous := ""
	for _, r := range out {
		key := ObjectRefKey(r)
		if key == previous || !validNamespace(r.Namespace) || !validName(r.Name) || !validUUID(r.UID) || !((r.APIVersion == "v1" && r.Kind == "Secret") || (r.APIVersion == "apps/v1" && r.Kind == "Deployment")) {
			return nil, Failure("ObjectRefsInvalid")
		}
		previous = key
	}
	return out, nil
}
func validHolder(s string) bool {
	if s == "" || len(s) > 512 || !utf8.ValidString(s) || !norm.NFC.IsNormalString(s) {
		return false
	}
	for _, r := range s {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs) {
			return false
		}
	}
	return true
}
func validSnapshot(s Snapshot) bool {
	if _, err := e2e2.Counter(s.Sequence, false); err != nil {
		return false
	}
	if _, err := e2e2.Counter(s.ReadKeyEpoch, false); err != nil {
		return false
	}
	if _, err := e2e2.Counter(s.PublisherPolicyEpoch, false); err != nil {
		return false
	}
	return validHash(s.EnvelopeHash, false)
}
func validGrantShape(g FenceGrant) bool {
	if g.Format != "sekvyr-fence-grant-v1" || !e2e2.ValidScope(g.Scope) || !validHash(g.GenesisHash, false) || !validHash(g.AuthorityDigest, false) || !validHash(g.PreviousGrantHash, true) || !validUUID(g.InstallationID) || !validUUID(g.OwnerPodUID) || !validHolder(g.LeaseHolderIdentity) || !validSnapshot(g.Snapshot) || g.BootstrapGeneration < 1 || g.BootstrapGeneration > 9007199254740991 {
		return false
	}
	if _, err := e2e2.Counter(g.Term, false); err != nil {
		return false
	}
	refs, err := CanonicalObjectRefs(g.Objects)
	return err == nil && reflect.DeepEqual(refs, g.Objects)
}
func validActivationShape(a FenceActivation) bool {
	refs, err := CanonicalObjectRefs(a.Objects)
	if err != nil || !reflect.DeepEqual(refs, a.Objects) || a.Format != "sekvyr-fence-activation-v1" || !e2e2.ValidScope(a.Scope) || !validHash(a.GenesisHash, false) || !validHash(a.GrantHash, false) || !validHash(a.AuthorityDigest, false) || !validSnapshot(a.Snapshot) || !validUUID(a.InstallationID) || !validUUID(a.OwnerPodUID) || !validHolder(a.LeaseHolderIdentity) || a.BootstrapGeneration < 1 || a.BootstrapGeneration > 9007199254740991 {
		return false
	}
	_, err = e2e2.Counter(a.Term, false)
	return err == nil
}
func validEnrollment(e Enrollment) bool {
	if e.OperatorServiceAccount == e.FencerServiceAccount || e.OperatorServiceAccountUID == e.FencerServiceAccountUID {
		return false
	}
	refs, err := CanonicalObjectRefs(e.AllowedObjects)
	if err != nil || !reflect.DeepEqual(refs, e.AllowedObjects) || !validUUID(e.InstallationID) || e.BootstrapGeneration < 1 || e.BootstrapGeneration > 9007199254740991 || !validNamespace(e.Namespace) || !validUUID(e.NamespaceUID) || !validName(e.OperatorServiceAccount) || !validUUID(e.OperatorServiceAccountUID) || !validName(e.FencerServiceAccount) || !validUUID(e.FencerServiceAccountUID) || !validUUID(e.IdentityKeySecretUID) || !validUUID(e.TrustBundleSecretUID) || e.IdentityKeySecretUID == e.TrustBundleSecretUID {
		return false
	}
	if !strings.HasPrefix(e.NodeFingerprint, "p256-sha256:") || !validHash(strings.TrimPrefix(e.NodeFingerprint, "p256-sha256:"), false) {
		return false
	}
	if e.Lease.APIVersion != "coordination.k8s.io/v1" || e.Lease.Kind != "Lease" || e.Lease.Namespace != e.Namespace || !validName(e.Lease.Name) || !validUUID(e.Lease.UID) {
		return false
	}
	for _, r := range refs {
		if r.Namespace != e.Namespace || r.UID == e.IdentityKeySecretUID || r.UID == e.TrustBundleSecretUID {
			return false
		}
	}
	return true
}
func authorityDigest(s CurrentState) (string, error) {
	return hashValue(AuthorityHashDomain, struct {
		Scope       e2e2.Scope            `json:"scope"`
		GenesisHash string                `json:"genesis_hash"`
		Authority   Authority             `json:"authority"`
		Enrollments map[string]Enrollment `json:"enrollments"`
	}{s.Scope, s.GenesisHash, s.Authority, s.Enrollments}, 1<<20)
}
func nextCounter(raw string) (string, error) {
	n, err := e2e2.Counter(raw, true)
	if err != nil || n == ^uint64(0) {
		return "", Failure("SequenceExhausted")
	}
	return fmtCounter(n + 1), nil
}
func fmtCounter(value uint64) string { return strconv.FormatUint(value, 10) }
func cloneState(s CurrentState) CurrentState {
	raw, _ := json.Marshal(s)
	var out CurrentState
	_ = json.Unmarshal(raw, &out)
	return out
}
func same(a, b any) bool { return reflect.DeepEqual(a, b) }
