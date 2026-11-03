package e2e2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// PUBLIC deterministic synthetic fixture material, never a production key source.
func publicMaterial(label string) []byte {
	sum := sha256.Sum256([]byte("sekvyr-e2e2-public-test-vector/" + label))
	return append([]byte(nil), sum[:]...)
}

type publicVector struct {
	Envelope      json.RawMessage `json:"envelope"`
	Plaintext     Plaintext       `json:"plaintext"`
	EnvelopeHash  string          `json:"envelope_hash"`
	Publisher     string          `json:"publisher_public_key"`
	CanonicalBody string          `json:"canonical_body_base64url"`
	Proof         HeadProof       `json:"head_proof"`
}

func fixtureVector(t *testing.T) publicVector {
	t.Helper()
	raw, err := os.ReadFile("../../design/e2e2.public-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v publicVector
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("invalid public fixture")
	}
	return v
}
func expectedFor(t *testing.T, raw []byte, pub ed25519.PublicKey) Expected {
	t.Helper()
	var e Envelope
	if err := DecodeStrict(raw, &e, MaxEnvelopeBytes); err != nil {
		t.Fatal(err)
	}
	hash, err := EnvelopeHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := e.Body.Header
	return Expected{Scope: h.Scope, Sequence: h.Sequence, EnvelopeHash: hash, ReadKeyEpoch: h.ReadKeyEpoch, PublisherPolicyEpoch: h.PublisherPolicyEpoch, PublisherKeys: map[string]ed25519.PublicKey{KeyID(pub): pub}}
}
func TestIndependentPublicEnvelopeAndWrap(t *testing.T) {
	v := fixtureVector(t)
	pub, err := DecodeBase64(v.Publisher, 32)
	if err != nil {
		t.Fatal(err)
	}
	expected := expectedFor(t, v.Envelope, ed25519.PublicKey(pub))
	if expected.EnvelopeHash != v.EnvelopeHash {
		t.Fatal("independent envelope hash mismatch")
	}
	verified, err := VerifyEnvelope(v.Envelope, expected)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := verified.Decrypt(publicMaterial("view-read"))
	if err != nil || !reflect.DeepEqual(plain, v.Plaintext) {
		t.Fatal("independent encrypted snapshot does not open", err)
	}
	var envelope Envelope
	_ = DecodeStrict(v.Envelope, &envelope, MaxEnvelopeBytes)
	body, err := marshal(envelope.Body, MaxEnvelopeBytes)
	want, _ := DecodeBase64(v.CanonicalBody, -1)
	if err != nil || !bytes.Equal(body, want) {
		t.Fatal("independent body canonicalization mismatch")
	}
	if err := ValidateHeadProof(v.Proof); err != nil {
		t.Fatal("independent head metadata refused", err)
	}
	raw, err := os.ReadFile("../../tests/e2e2/public-reader-wrap-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		Wrapper json.RawMessage `json:"wrapper"`
		Scalar  string          `json:"public_test_node_scalar"`
		ReadKey string          `json:"public_test_view_read_key"`
	}
	if json.Unmarshal(raw, &w) != nil {
		t.Fatal("invalid wrap fixture")
	}
	scalar, _ := DecodeBase64(w.Scalar, 32)
	node, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	key, err := UnwrapReader(w.Wrapper, node, verified)
	wantKey, _ := DecodeBase64(w.ReadKey, 32)
	if err != nil || !bytes.Equal(key, wantKey) || !bytes.Equal(key, publicMaterial("view-read")) {
		t.Fatal("independent signed reader wrap failed", err)
	}
	clear(key)
}
func TestTrustedPublisherFreshEncryptionAndReaderRoundtrip(t *testing.T) {
	v := fixtureVector(t)
	var template Envelope
	_ = DecodeStrict(v.Envelope, &template, MaxEnvelopeBytes)
	_, publisher, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	readKey, err := random(32)
	if err != nil {
		t.Fatal(err)
	}
	plain := v.Plaintext
	plain.Entries[0].Value = "exact e\u0301 <>& \u2028\u2029 𝄞\x00"
	header := template.Body.Header
	header.PublisherKeyID = KeyID(publisher.Public().(ed25519.PublicKey))
	first, err := SealSnapshot(header, plain, readKey, publisher)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SealSnapshot(header, plain, readKey, publisher)
	if err != nil || bytes.Equal(first, second) {
		t.Fatal("fresh encryption reused snapshot bytes")
	}
	expected := expectedFor(t, first, publisher.Public().(ed25519.PublicKey))
	verified, err := VerifyEnvelope(first, expected)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verified.Decrypt(readKey)
	if err != nil || !reflect.DeepEqual(got, plain) {
		t.Fatal("snapshot roundtrip failed", err)
	}
	node, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := NodeKeyFingerprint(node.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	context := WrapContext{Protocol: "e2e2-reader-key-v1", Scope: header.Scope, ReadKeyEpoch: header.ReadKeyEpoch, PublisherPolicyEpoch: header.PublisherPolicyEpoch, PublisherKeyID: header.PublisherKeyID, RecipientFingerprint: fp}
	wrapper, err := WrapReader(context, readKey, node.PublicKey(), publisher)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := UnwrapReader(wrapper, node, verified)
	if err != nil || !bytes.Equal(opened, readKey) {
		t.Fatal("signed wrap roundtrip failed", err)
	}
	clear(opened)
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := UnwrapReader(wrapper, other, verified); err == nil {
		t.Fatal("wrong recipient accepted")
	}
	var tampered ReaderWrap
	_ = DecodeStrict(wrapper, &tampered, MaxReaderWrapBytes)
	tampered.Body.Context.ReadKeyEpoch = "2"
	changed, _ := marshal(tampered, MaxReaderWrapBytes)
	if _, err := UnwrapReader(changed, node, verified); err == nil {
		t.Fatal("wrong wrap epoch accepted")
	}
	// Mutating data obtained through accessors or the caller's pin map cannot change verified state.
	access := verified.Header()
	access.Sequence = "99"
	expected.PublisherKeys[header.PublisherKeyID][0] ^= 1
	if _, err := UnwrapReader(wrapper, node, verified); err != nil {
		t.Fatal("verified pin state aliases caller map", err)
	}
}
func TestEnvelopeScopeSignatureAndReadKeyFailures(t *testing.T) {
	v := fixtureVector(t)
	pub, _ := DecodeBase64(v.Publisher, 32)
	expected := expectedFor(t, v.Envelope, ed25519.PublicKey(pub))
	wrong := expected
	wrong.Scope.ProjectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if _, err := VerifyEnvelope(v.Envelope, wrong); err == nil {
		t.Fatal("source substitution accepted")
	}
	wrong = expected
	wrong.Sequence = "2"
	if _, err := VerifyEnvelope(v.Envelope, wrong); err == nil {
		t.Fatal("revision substitution accepted")
	}
	wrong = expected
	wrong.ReadKeyEpoch = "2"
	if _, err := VerifyEnvelope(v.Envelope, wrong); err == nil {
		t.Fatal("read-key epoch substitution accepted")
	}
	var changed Envelope
	_ = DecodeStrict(v.Envelope, &changed, MaxEnvelopeBytes)
	ciphertext, _ := DecodeBase64(changed.Body.Ciphertext, -1)
	ciphertext[0] ^= 1
	changed.Body.Ciphertext = encodeBase64(ciphertext)
	raw, _ := marshal(changed, MaxEnvelopeBytes)
	if _, err := VerifyEnvelope(raw, expected); err == nil {
		t.Fatal("ciphertext changed without signing authority")
	}
	verified, err := VerifyEnvelope(v.Envelope, expected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verified.Decrypt(make([]byte, 32)); err == nil {
		t.Fatal("wrong AES key accepted")
	}
	if _, err := (&VerifiedEnvelope{}).Decrypt(publicMaterial("view-read")); err == nil {
		t.Fatal("zero verified envelope accepted")
	}
	if _, err := UnwrapReader(nil, nil, &VerifiedEnvelope{}); err == nil {
		t.Fatal("zero verified envelope trusted for a wrapper")
	}
}
func TestPublisherRejectsUnreviewedShapeAndRebase(t *testing.T) {
	v := fixtureVector(t)
	var template Envelope
	_ = DecodeStrict(v.Envelope, &template, MaxEnvelopeBytes)
	publisher := ed25519.NewKeyFromSeed(publicMaterial("publisher"))
	key := publicMaterial("view-read")
	for _, action := range []string{"update", "restore", "rotate-read-key"} {
		header := template.Body.Header
		header.Action = action
		if _, err := SealSnapshot(header, v.Plaintext, key, publisher); err == nil {
			t.Fatal("initial snapshot action accepted without valid history")
		}
	}
	header := template.Body.Header
	header.Sequence = "2"
	header.PreviousHash = v.EnvelopeHash
	header.Action = "initial"
	if _, err := SealSnapshot(header, v.Plaintext, key, publisher); err == nil {
		t.Fatal("reinitialized sequence accepted")
	}
	bad := v.Plaintext
	bad.Entries = []Entry{{Path: "/", Name: "B", Value: "one"}, {Path: "/", Name: "A", Value: "two"}}
	header = template.Body.Header
	header.EntryCount = 2
	if _, err := SealSnapshot(header, bad, key, publisher); err == nil {
		t.Fatal("unordered reviewed entries accepted")
	}
	bad = v.Plaintext
	bad.Entries = []Entry{{Path: "/", Name: "e\u0301", Value: "exact"}}
	header.EntryCount = 1
	if _, err := SealSnapshot(header, bad, key, publisher); err == nil {
		t.Fatal("non-NFC metadata accepted")
	}
	header = template.Body.Header
	header.Parents = []Parent{{Scope: header.Scope, Sequence: "1", EnvelopeHash: v.EnvelopeHash}}
	if _, err := SealSnapshot(header, v.Plaintext, key, publisher); err == nil {
		t.Fatal("self inheritance accepted")
	}
}

func TestPublisherRejectsAggregatePlaintextBeforeEncoding(t *testing.T) {
	v := fixtureVector(t)
	var envelope Envelope
	_ = DecodeStrict(v.Envelope, &envelope, MaxEnvelopeBytes)
	value := strings.Repeat("x", 200000)
	plain := Plaintext{Format: "sekvyr-e2e2-values-v1", Context: v.Plaintext.Context, Entries: make([]Entry, 50)}
	for i := range plain.Entries {
		plain.Entries[i] = Entry{Path: "/", Name: string([]byte{'A', byte('A' + i/26), byte('A' + i%26)}), Value: value}
	}
	if err := ValidatePlaintext(plain); err == nil {
		t.Fatal("oversized aggregate typed plaintext accepted")
	}
	header := envelope.Body.Header
	header.EntryCount = len(plain.Entries)
	publisher := ed25519.NewKeyFromSeed(publicMaterial("publisher"))
	if _, err := SealSnapshot(header, plain, publicMaterial("view-read"), publisher); err == nil {
		t.Fatal("publisher encoded oversized typed plaintext")
	}
	if _, err := SealSnapshot(envelope.Body.Header, v.Plaintext, publicMaterial("view-read"), nil); err == nil {
		t.Fatal("publisher signed without explicit private authority")
	}
}
