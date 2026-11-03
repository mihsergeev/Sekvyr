package e2e2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"filippo.io/edwards25519"
	"golang.org/x/text/unicode/norm"
)

const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidScope(s Scope) bool {
	for _, id := range []string{s.RealmID, s.ProjectID, s.EnvironmentID, s.ViewID, s.LogID} {
		if !uuidPattern.MatchString(id) {
			return false
		}
	}
	return true
}
func scopeOrder(s Scope) string {
	return strings.Join([]string{s.RealmID, s.ProjectID, s.EnvironmentID, s.ViewID, s.LogID}, "\x00")
}
func KeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return "ed25519-sha256:" + hex.EncodeToString(sum[:])
}

// ValidEd25519PublicKey requires a canonical nonidentity prime-subgroup point.
// The maintained group implementation is used only to validate independently pinned
// trust keys; signing and signature verification remain in crypto/ed25519.
func ValidEd25519PublicKey(public ed25519.PublicKey) bool {
	if len(public) != ed25519.PublicKeySize {
		return false
	}
	point, err := new(edwards25519.Point).SetBytes(public)
	if err != nil || !bytes.Equal(point.Bytes(), public) {
		return false
	}
	cofactor := new(edwards25519.Point).MultByCofactor(point)
	if cofactor.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	eight := make([]byte, 32)
	eight[0] = 8
	scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(eight)
	if err != nil {
		return false
	}
	inverse := new(edwards25519.Scalar).Invert(scalar)
	return new(edwards25519.Point).ScalarMult(inverse, cofactor).Equal(point) == 1
}
func RecipientFingerprint(public []byte) string {
	sum := sha256.Sum256(public)
	return "p256-sha256:" + hex.EncodeToString(sum[:])
}
func NodeKeyFingerprint(public *ecdh.PublicKey) (string, error) {
	if public == nil || public.Curve() != ecdh.P256() || len(public.Bytes()) != 65 {
		return "", fail("InvalidNodeKey")
	}
	return RecipientFingerprint(public.Bytes()), nil
}
func keyIDValid(value string) bool {
	return strings.HasPrefix(value, "ed25519-sha256:") && hashPattern.MatchString(strings.TrimPrefix(value, "ed25519-sha256:"))
}
func recipientValid(value string) bool {
	return strings.HasPrefix(value, "p256-sha256:") && hashPattern.MatchString(strings.TrimPrefix(value, "p256-sha256:"))
}
func nonzeroHash(value string) bool { return hashPattern.MatchString(value) && value != ZeroHash }
func metadata(value string) bool {
	return utf8.ValidString(value) && norm.NFC.IsNormalString(value) && strings.IndexFunc(value, func(r rune) bool { return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs) }) < 0
}
func ValidPath(value string) bool {
	if value == "" || utf8.RuneCountInString(value) > 200 || value[0] != '/' || !metadata(value) || strings.Contains(value, "\\") {
		return false
	}
	if value == "/" {
		return true
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
func ValidateHeader(h Header) error {
	if h.Protocol != "e2e2" || h.Suite != "HKDF-SHA256+A256GCM+Ed25519" || h.Intent != "publish" || !ValidScope(h.Scope) || !keyIDValid(h.PublisherKeyID) {
		return fail("InvalidHeader")
	}
	sequence, err := Counter(h.Sequence, false)
	if err != nil {
		return err
	}
	if _, err = Counter(h.ReadKeyEpoch, false); err != nil {
		return err
	}
	if _, err = Counter(h.PublisherPolicyEpoch, false); err != nil {
		return err
	}
	if sequence == 1 {
		if h.PreviousHash != ZeroHash || (h.Action != "initial" && h.Action != "migrate") {
			return fail("InvalidHeader")
		}
	} else {
		if !nonzeroHash(h.PreviousHash) || (h.Action != "update" && h.Action != "restore" && h.Action != "rotate-read-key") {
			return fail("InvalidHeader")
		}
	}
	if h.Action == "restore" {
		if h.RestoredFrom == nil || !nonzeroHash(*h.RestoredFrom) {
			return fail("InvalidHeader")
		}
	} else if h.RestoredFrom != nil {
		return fail("InvalidHeader")
	}
	if _, err := DecodeBase64(h.SnapshotSalt, 32); err != nil {
		return err
	}
	if h.EntryCount < 0 || h.EntryCount > MaxEntries || h.Parents == nil || len(h.Parents) > MaxParents {
		return fail("InvalidHeader")
	}
	previous := ""
	for i, parent := range h.Parents {
		order := scopeOrder(parent.Scope)
		if !ValidScope(parent.Scope) || parent.Scope == h.Scope || (i > 0 && order <= previous) || !nonzeroHash(parent.EnvelopeHash) {
			return fail("InvalidHeader")
		}
		if _, err := Counter(parent.Sequence, false); err != nil {
			return err
		}
		previous = order
	}
	return nil
}
func ValidatePlaintext(p Plaintext) error {
	if p.Format != "sekvyr-e2e2-values-v1" || !ValidScope(p.Context) || p.Entries == nil || len(p.Entries) > MaxEntries {
		return fail("InvalidPlaintext")
	}
	lastPath, lastName := "", ""
	remaining := MaxPlaintextBytes
	for i, entry := range p.Entries {
		// A lower bound on encoded size, checked without overflow or a large
		// json.Marshal allocation. Exact canonical size is checked separately.
		for _, field := range []string{entry.Path, entry.Name, entry.Value} {
			if len(field) > remaining {
				return fail("ResponseTooLarge")
			}
			remaining -= len(field)
		}
		if !ValidPath(entry.Path) || entry.Name == "" || utf8.RuneCountInString(entry.Name) > 200 || !metadata(entry.Name) || !utf8.ValidString(entry.Value) || utf8.RuneCountInString(entry.Value) > 200000 {
			return fail("InvalidPlaintext")
		}
		if i > 0 && (entry.Path < lastPath || (entry.Path == lastPath && entry.Name <= lastName)) {
			return fail("InvalidPlaintext")
		}
		lastPath, lastName = entry.Path, entry.Name
	}
	return nil
}
func ValidateWrapContext(c WrapContext) error {
	if c.Protocol != "e2e2-reader-key-v1" || !ValidScope(c.Scope) || !keyIDValid(c.PublisherKeyID) || !recipientValid(c.RecipientFingerprint) {
		return fail("InvalidReaderWrap")
	}
	if _, err := Counter(c.ReadKeyEpoch, false); err != nil {
		return err
	}
	if _, err := Counter(c.PublisherPolicyEpoch, false); err != nil {
		return err
	}
	return nil
}
func ValidateReaderWrap(w ReaderWrap) error {
	if err := ValidateWrapContext(w.Body.Context); err != nil {
		return err
	}
	for _, field := range []struct {
		s string
		n int
	}{{w.Body.EphemeralPublic, 65}, {w.Body.Salt, 32}, {w.Body.Nonce, 12}, {w.Signature, 64}} {
		if _, err := DecodeBase64(field.s, field.n); err != nil {
			return err
		}
	}
	if len(w.Body.Ciphertext) > 2752 {
		return fail("InvalidReaderWrap")
	}
	ciphertext, err := DecodeBase64(w.Body.Ciphertext, -1)
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > MaxReaderPayloadBytes+16 {
		return fail("InvalidReaderWrap")
	}
	return nil
}

// ValidateHeadProof checks exact semantic encoding, not signature, nonce freshness or independent trust.
func ValidateHeadProof(p HeadProof) error {
	b := p.Body
	if b.Format != "sekvyr-e2e2-head-v1" || !ValidScope(b.Scope) || !keyIDValid(b.WitnessKeyID) {
		return fail("InvalidHeadProof")
	}
	if _, err := Counter(b.WitnessEpoch, false); err != nil {
		return err
	}
	sequence, err := Counter(b.Sequence, true)
	if err != nil {
		return err
	}
	floor, err := Counter(b.FloorSequence, true)
	if err != nil {
		return err
	}
	read, err := Counter(b.ReadKeyEpoch, true)
	if err != nil {
		return err
	}
	policy, err := Counter(b.PublisherPolicyEpoch, true)
	if err != nil {
		return err
	}
	if !hashPattern.MatchString(b.EnvelopeHash) || !hashPattern.MatchString(b.FloorHash) || floor > sequence {
		return fail("InvalidHeadProof")
	}
	if sequence == 0 {
		if b.EnvelopeHash != ZeroHash || read != 0 || policy != 0 {
			return fail("InvalidHeadProof")
		}
	} else if b.EnvelopeHash == ZeroHash || read == 0 || policy == 0 {
		return fail("InvalidHeadProof")
	}
	if floor == 0 && b.FloorHash != ZeroHash || floor > 0 && b.FloorHash == ZeroHash || floor == sequence && b.FloorHash != b.EnvelopeHash {
		return fail("InvalidHeadProof")
	}
	if _, err := DecodeBase64(b.RequestNonce, 32); err != nil {
		return err
	}
	if _, err := DecodeBase64(p.Signature, 64); err != nil {
		return err
	}
	return nil
}
