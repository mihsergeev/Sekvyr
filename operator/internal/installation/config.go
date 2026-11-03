// Package installation validates independently provisioned administrative bootstrap metadata.
package installation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Failure struct{ Reason string }

func (e *Failure) Error() string { return e.Reason }
func Reject(reason string) error { return &Failure{Reason: reason} }
func Reason(err error) string {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Reason
	}
	return "BootstrapMismatch"
}

type SecretPin struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
	Key  string `json:"key"`
}
type CAPin struct {
	Name         string `json:"name"`
	UID          string `json:"uid"`
	Key          string `json:"key"`
	DERSetSHA256 string `json:"derSetSHA256"`
}
type Config struct {
	InstallationID          string    `json:"installationID"`
	Namespace               string    `json:"namespace"`
	ServiceAccount          string    `json:"serviceAccount"`
	ServiceAccountUID       string    `json:"serviceAccountUID,omitempty"`
	LeaderElectionLeaseUID  string    `json:"leaderElectionLeaseUID,omitempty"`
	LeaderElectionLeaseName string    `json:"leaderElectionLeaseName,omitempty"`
	BootstrapGeneration     int64     `json:"bootstrapGeneration"`
	AllowedPanelOrigins     []string  `json:"allowedPanelOrigins"`
	AllowedWitnessOrigins   []string  `json:"allowedWitnessOrigins"`
	IdentityKeySecret       SecretPin `json:"identityKeySecret"`
	TrustBundleSecret       SecretPin `json:"trustBundleSecret"`
	StateSecret             SecretPin `json:"stateSecret"`
	ProtectedSecretNames    []string  `json:"protectedSecretNames"`
	ProtectedSecretUIDs     []string  `json:"protectedSecretUIDs"`
	ProtectedPrefixes       []string  `json:"protectedPrefixes"`
	CAConfigMaps            []CAPin   `json:"caConfigMaps"`
	AllowedTargetSecrets    []string  `json:"allowedTargetSecrets,omitempty"`
	WitnessCAConfigMapRef   *CARef    `json:"witnessCAConfigMapRef,omitempty"`
	RolloutEnabled          bool      `json:"rolloutEnabled,omitempty"`
	AllowedDeployments      []string  `json:"allowedDeployments,omitempty"`
	HA                      *HAConfig `json:"ha,omitempty"`
}

// HAConfig is independently provisioned. Its presence enables the narrow
// single-log trial profile; there is no development-storage fallback.
type HAConfig struct {
	Trial                 bool                 `json:"trial"`
	FencerOrigin          string               `json:"fencerOrigin"`
	AllowedFencerOrigins  []string             `json:"allowedFencerOrigins"`
	FencerCAConfigMapRef  *CARef               `json:"fencerCAConfigMapRef"`
	GatewayOrigin         string               `json:"gatewayOrigin"`
	GatewayCAConfigMapRef *CARef               `json:"gatewayCAConfigMapRef"`
	GatewayClientSecret   SecretPin            `json:"gatewayClientSecret"`
	GatewayClientKeyKey   string               `json:"gatewayClientKeyKey"`
	Journal               journal.Registration `json:"journal"`
}
type CARef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}
type StateMarker struct {
	InstallationID      string `json:"installationID"`
	BootstrapGeneration int64  `json:"bootstrapGeneration"`
}

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidUUID(value string) bool { return uuid.MatchString(value) }
func ValidName(value string) bool { return len(validation.IsDNS1123Subdomain(value)) == 0 }

// CanonicalOrigin accepts HTTPS origins only. Paths, credentials, queries and fragments are rejected.
func CanonicalOrigin(raw string) (string, error) {
	if len(raw) > 2048 || strings.ContainsAny(raw, "\\\t\r\n ") {
		return "", Reject("ScopeDenied")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", Reject("ScopeDenied")
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", Reject("ScopeDenied")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return "", Reject("ScopeDenied")
	}
	if net.ParseIP(host) == nil && !ValidName(host) {
		return "", Reject("ScopeDenied")
	}
	port := u.Port()
	if port != "" && port != "443" {
		// A numeric nonzero TCP port, without alternate spellings.
		var n int
		for _, ch := range port {
			if ch < '0' || ch > '9' {
				return "", Reject("ScopeDenied")
			}
			n = n*10 + int(ch-'0')
			if n > 65535 {
				return "", Reject("ScopeDenied")
			}
		}
		if n == 0 || (len(port) > 1 && port[0] == '0') {
			return "", Reject("ScopeDenied")
		}
		return "https://" + net.JoinHostPort(host, port), nil
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}
func originAllowed(value string, allowed []string) bool {
	origin, err := CanonicalOrigin(value)
	if err != nil {
		return false
	}
	for _, entry := range allowed {
		expected, err := CanonicalOrigin(entry)
		if err == nil && origin == expected {
			return true
		}
	}
	return false
}
func (c Config) AllowsPanelOrigin(value string) bool {
	return originAllowed(value, c.AllowedPanelOrigins)
}
func (c Config) AllowsWitnessOrigin(value string) bool {
	return originAllowed(value, c.AllowedWitnessOrigins)
}

func Decode(reader io.Reader) (Config, error) {
	var c Config
	if err := decodeStrict(reader, &c, 65536); err != nil {
		return c, Reject("BootstrapMismatch")
	}
	return c, c.Validate()
}
func LoadFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, Reject("BootstrapMissing")
	}
	defer f.Close()
	return Decode(f)
}
func decodeStrict(reader io.Reader, out any, maximum int64) error {
	raw, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return Reject("BootstrapMismatch")
	}
	if rejectDuplicateKeys(raw) != nil {
		return Reject("BootstrapMismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return Reject("BootstrapMismatch")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Reject("BootstrapMismatch")
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return Reject("BootstrapMismatch")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, nested := token.(json.Delim)
		if !nested {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return Reject("BootstrapMismatch")
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return Reject("BootstrapMismatch")
			}
		case '[':
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return Reject("BootstrapMismatch")
			}
		default:
			return Reject("BootstrapMismatch")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Reject("BootstrapMismatch")
	}
	return nil
}
func (c Config) Validate() error {
	if !ValidUUID(c.InstallationID) || len(validation.IsDNS1123Label(c.Namespace)) != 0 ||
		!ValidName(c.ServiceAccount) || c.BootstrapGeneration < 1 || c.BootstrapGeneration > 9007199254740991 || len(c.AllowedPanelOrigins) == 0 {
		return Reject("BootstrapMismatch")
	}
	if c.ServiceAccountUID != "" && !ValidUUID(c.ServiceAccountUID) || c.LeaderElectionLeaseUID != "" && !ValidUUID(c.LeaderElectionLeaseUID) {
		return Reject("BootstrapMismatch")
	}
	if (c.LeaderElectionLeaseUID == "") != (c.LeaderElectionLeaseName == "") || c.LeaderElectionLeaseName != "" && !ValidName(c.LeaderElectionLeaseName) {
		return Reject("BootstrapMismatch")
	}
	for _, origins := range [][]string{c.AllowedPanelOrigins, c.AllowedWitnessOrigins} {
		seen := map[string]bool{}
		for _, raw := range origins {
			origin, err := CanonicalOrigin(raw)
			if err != nil || seen[origin] {
				return Reject("BootstrapMismatch")
			}
			seen[origin] = true
		}
	}
	names, uids := map[string]bool{}, map[string]bool{}
	for _, pin := range []SecretPin{c.IdentityKeySecret, c.TrustBundleSecret, c.StateSecret} {
		if !ValidName(pin.Name) || !ValidUUID(pin.UID) || len(validation.IsConfigMapKey(pin.Key)) != 0 || names[pin.Name] || uids[pin.UID] {
			return Reject("BootstrapMismatch")
		}
		names[pin.Name], uids[pin.UID] = true, true
	}
	for _, name := range c.ProtectedSecretNames {
		if !ValidName(name) {
			return Reject("BootstrapMismatch")
		}
	}
	for _, uid := range c.ProtectedSecretUIDs {
		if !ValidUUID(uid) {
			return Reject("BootstrapMismatch")
		}
	}
	for _, prefix := range c.ProtectedPrefixes {
		if prefix == "" || len(prefix) > 253 || strings.ContainsAny(prefix, "/\\\r\n\t") {
			return Reject("BootstrapMismatch")
		}
	}
	caNames := map[string]bool{}
	for _, pin := range c.CAConfigMaps {
		if !ValidName(pin.Name) || !ValidUUID(pin.UID) || len(validation.IsConfigMapKey(pin.Key)) != 0 || !digest.MatchString(pin.DERSetSHA256) || caNames[pin.Name] {
			return Reject("BootstrapMismatch")
		}
		caNames[pin.Name] = true
	}
	seenTargets := map[string]bool{}
	if len(c.AllowedTargetSecrets) > 64 {
		return Reject("BootstrapMismatch")
	}
	for _, name := range c.AllowedTargetSecrets {
		if !ValidName(name) || seenTargets[name] || c.Protected(name, "") {
			return Reject("BootstrapMismatch")
		}
		seenTargets[name] = true
	}
	if len(c.AllowedDeployments) > 64 || c.RolloutEnabled && len(c.AllowedDeployments) == 0 {
		return Reject("BootstrapMismatch")
	}
	seenDeployments := map[string]bool{}
	for _, name := range c.AllowedDeployments {
		if !ValidName(name) || seenDeployments[name] {
			return Reject("BootstrapMismatch")
		}
		seenDeployments[name] = true
	}
	if c.WitnessCAConfigMapRef != nil {
		found := false
		for _, pin := range c.CAConfigMaps {
			if pin.Name == c.WitnessCAConfigMapRef.Name && pin.Key == c.WitnessCAConfigMapRef.Key {
				found = true
			}
		}
		if !found {
			return Reject("BootstrapMismatch")
		}
	}
	if c.HA != nil {
		h := c.HA
		if !h.Trial || !originAllowed(h.FencerOrigin, h.AllowedFencerOrigins) || len(h.AllowedFencerOrigins) != 1 || len(c.AllowedTargetSecrets) != 1 || len(c.AllowedWitnessOrigins) != 1 {
			return Reject("HAProfileInvalid")
		}
		if _, err := CanonicalOrigin(h.GatewayOrigin); err != nil {
			return Reject("HAProfileInvalid")
		}
		if h.FencerOrigin == h.GatewayOrigin || h.FencerOrigin == c.AllowedWitnessOrigins[0] || h.GatewayOrigin == c.AllowedWitnessOrigins[0] {
			return Reject("HAProfileInvalid")
		}
		p := h.GatewayClientSecret
		if !ValidName(p.Name) || !ValidUUID(p.UID) || names[p.Name] || uids[p.UID] || len(validation.IsConfigMapKey(p.Key)) != 0 || len(validation.IsConfigMapKey(h.GatewayClientKeyKey)) != 0 || p.Key == h.GatewayClientKeyKey {
			return Reject("HAProfileInvalid")
		}
		for _, ref := range []*CARef{h.FencerCAConfigMapRef, h.GatewayCAConfigMapRef} {
			found := false
			if ref != nil {
				for _, pin := range c.CAConfigMaps {
					if pin.Name == ref.Name && pin.Key == ref.Key {
						found = true
					}
				}
			}
			if !found {
				return Reject("HAProfileInvalid")
			}
		}
		if !ValidUUID(h.Journal.LogID) || !digest.MatchString(h.Journal.GenesisHash) || h.Journal.GenesisHash == journal.ZeroHash || h.Journal.AdminPublicKey == "" || !digest.MatchString(h.Journal.MinimumCursor.RecordHash) || h.Journal.MinimumCursor.RecordHash == journal.ZeroHash {
			return Reject("HAProfileInvalid")
		}
		key, err := e2e2.DecodeBase64(h.Journal.AdminPublicKey, ed25519.PublicKeySize)
		if err != nil || !e2e2.ValidEd25519PublicKey(key) {
			return Reject("HAProfileInvalid")
		}
		if _, err := journalCounter(h.Journal.MinimumCursor.JournalSequence); err != nil {
			return err
		}
	}
	return nil
}
func journalCounter(value string) (uint64, error) {
	// Decimal uint64, with exactly one spelling and an independently pinned floor.
	if value == "" || len(value) > 20 || len(value) > 1 && value[0] == '0' {
		return 0, Reject("HAProfileInvalid")
	}
	var n uint64
	for _, v := range []byte(value) {
		if v < '0' || v > '9' || n > (^uint64(0)-uint64(v-'0'))/10 {
			return 0, Reject("HAProfileInvalid")
		}
		n = n*10 + uint64(v-'0')
	}
	return n, nil
}
func (c Config) TargetAllowed(name string) bool {
	for _, allowed := range c.AllowedTargetSecrets {
		if name == allowed {
			return true
		}
	}
	return false
}
func (c Config) CABytes(ctx context.Context, reader client.Reader, ref *CARef) ([]byte, error) {
	if ref == nil {
		return nil, nil
	}
	if err := c.ValidateCA(ctx, reader, ref.Name, ref.Key); err != nil {
		return nil, err
	}
	var value corev1.ConfigMap
	if reader.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: ref.Name}, &value) != nil {
		return nil, Reject("BootstrapMismatch")
	}
	for _, pin := range c.CAConfigMaps {
		if pin.Name == ref.Name && pin.Key == ref.Key {
			actual, err := CertificateSetSHA256([]byte(value.Data[ref.Key]))
			if string(value.UID) != pin.UID || value.Immutable == nil || !*value.Immutable || err != nil || actual != pin.DERSetSHA256 {
				return nil, Reject("BootstrapMismatch")
			}
			return []byte(value.Data[ref.Key]), nil
		}
	}
	return nil, Reject("BootstrapMismatch")
}

func (c Config) Protected(name string, uid types.UID) bool {
	if c.HA != nil && (name == c.HA.GatewayClientSecret.Name || uid != "" && string(uid) == c.HA.GatewayClientSecret.UID) {
		return true
	}
	for _, pin := range []SecretPin{c.IdentityKeySecret, c.TrustBundleSecret, c.StateSecret} {
		if name == pin.Name || (uid != "" && string(uid) == pin.UID) {
			return true
		}
	}
	for _, protected := range c.ProtectedSecretNames {
		if protected == name {
			return true
		}
	}
	for _, protected := range c.ProtectedSecretUIDs {
		if uid != "" && protected == string(uid) {
			return true
		}
	}
	for _, prefix := range append([]string{"sh.helm.release.v1."}, c.ProtectedPrefixes...) {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// ValidateRuntime uses a direct API reader: Secret objects must never enter an informer cache.
// This validates pinned administrative metadata, not E2E2 trust or ownership verification.
func (c Config) ValidateRuntime(ctx context.Context, reader client.Reader, namespace, serviceAccount string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if namespace != c.Namespace || serviceAccount != c.ServiceAccount {
		return Reject("ScopeDenied")
	}
	if c.ServiceAccountUID != "" {
		var account corev1.ServiceAccount
		if reader.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: c.ServiceAccount}, &account) != nil || string(account.UID) != c.ServiceAccountUID || !account.DeletionTimestamp.IsZero() {
			return Reject("BootstrapMismatch")
		}
	}
	if c.LeaderElectionLeaseUID != "" {
		var lease coordinationv1.Lease
		if reader.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: c.LeaderElectionLeaseName}, &lease) != nil || string(lease.UID) != c.LeaderElectionLeaseUID || !lease.DeletionTimestamp.IsZero() {
			return Reject("BootstrapMismatch")
		}
	}
	for i, pin := range []SecretPin{c.IdentityKeySecret, c.TrustBundleSecret, c.StateSecret} {
		var secret corev1.Secret
		err := reader.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: pin.Name}, &secret)
		if err != nil {
			if apierrors.IsNotFound(err) {
				if i == 2 {
					return Reject("StateMissing")
				}
				return Reject("BootstrapMissing")
			}
			return Reject("BootstrapMismatch")
		}
		maximum := 65536
		if i == 0 {
			maximum = 16384
		}
		if string(secret.UID) != pin.UID || secret.Type != corev1.SecretTypeOpaque || len(secret.Data[pin.Key]) == 0 || len(secret.Data[pin.Key]) > maximum {
			return Reject("BootstrapMismatch")
		}
		if i < 2 && (secret.Immutable == nil || !*secret.Immutable) {
			return Reject("BootstrapMismatch")
		}
		if i == 2 {
			var marker StateMarker
			if decodeStrict(bytes.NewReader(secret.Data[pin.Key]), &marker, 65536) != nil || marker.InstallationID != c.InstallationID || marker.BootstrapGeneration != c.BootstrapGeneration {
				return Reject("BootstrapMismatch")
			}
		}
	}
	for _, pin := range c.CAConfigMaps {
		if err := c.ValidateCA(ctx, reader, pin.Name, pin.Key); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) ValidateCA(ctx context.Context, reader client.Reader, name, key string) error {
	var pin *CAPin
	for i := range c.CAConfigMaps {
		if c.CAConfigMaps[i].Name == name && c.CAConfigMaps[i].Key == key {
			pin = &c.CAConfigMaps[i]
			break
		}
	}
	if pin == nil {
		return Reject("ScopeDenied")
	}
	var config corev1.ConfigMap
	if reader.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: name}, &config) != nil || string(config.UID) != pin.UID || config.Immutable == nil || !*config.Immutable {
		return Reject("BootstrapMismatch")
	}
	data, ok := config.Data[key]
	if !ok {
		return Reject("BootstrapMismatch")
	}
	actual, err := CertificateSetSHA256([]byte(data))
	if err != nil || actual != pin.DERSetSHA256 {
		return Reject("BootstrapMismatch")
	}
	return nil
}

// CertificateSetSHA256 hashes sorted unique DER certificates, each prefixed by uint32 big-endian length.
func CertificateSetSHA256(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 1048576 {
		return "", Reject("BootstrapMismatch")
	}
	certs := map[string]bool{}
	for len(bytes.TrimSpace(raw)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN CERTIFICATE-----")) {
			return "", Reject("BootstrapMismatch")
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return "", Reject("BootstrapMismatch")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", Reject("BootstrapMismatch")
		}
		certs[string(block.Bytes)] = true
		raw = rest
	}
	ordered := make([]string, 0, len(certs))
	if len(certs) == 0 {
		return "", Reject("BootstrapMismatch")
	}
	for der := range certs {
		ordered = append(ordered, der)
	}
	sort.Strings(ordered)
	h := sha256.New()
	for _, der := range ordered {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(der)))
		h.Write(size[:])
		h.Write([]byte(der))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
