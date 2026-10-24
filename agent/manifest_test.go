package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// Описание версии подписывается двумя подписями: первой его проверяют агенты
// 1.0.1 и старше, второй, с датой, новые. Агент верит дате, только если она
// подписана.
func signedManifest(t *testing.T) (*manifest, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := PublicKey
	PublicKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { PublicKey = old })
	m := &manifest{Version: "9.9.9", SignedAt: "2026-10-25T10:00:00.123456+00:00"}
	m.Files = map[string]struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}{
		"amd64": {SHA256: "aa"},
		"arm64": {SHA256: "bb"},
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signedText(m)))
	m.SignatureV2 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signedTextV2(m)))
	return m, priv
}

func TestManifestWithDatedSignature(t *testing.T) {
	m, _ := signedManifest(t)
	if err := verifyManifest(m); err != nil {
		t.Fatal(err)
	}
	if got := signedDay(m); got != "2026-10-25" {
		t.Fatalf("signed day %q", got)
	}
}

func TestChangedDateBreaksTheSignature(t *testing.T) {
	m, _ := signedManifest(t)
	m.SignedAt = "2030-01-01T00:00:00+00:00"
	if err := verifyManifest(m); err == nil {
		t.Fatal("a changed date passed the check")
	}
}

// Описание от панели 1.0.1: только первая подпись. Обновление проходит, а
// дата не показывается - ее могла написать сама панель.
func TestManifestWithoutDatedSignature(t *testing.T) {
	m, _ := signedManifest(t)
	m.SignatureV2 = ""
	m.SignedAt = "2030-01-01T00:00:00+00:00"
	if err := verifyManifest(m); err != nil {
		t.Fatal(err)
	}
	if got := signedDay(m); got != "" {
		t.Fatalf("an unsigned date is shown: %q", got)
	}
}

// Первую подпись нельзя выдать за вторую: тексты начинаются по-разному.
func TestFirstSignatureIsNotTheSecond(t *testing.T) {
	m, _ := signedManifest(t)
	m.SignatureV2 = m.Signature
	if err := verifyManifest(m); err == nil {
		t.Fatal("the first signature passed as the second")
	}
}

func TestChangedHashBreaksBothSignatures(t *testing.T) {
	m, _ := signedManifest(t)
	m.Files["amd64"] = struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}{SHA256: "cc"}
	if err := verifyManifest(m); err == nil {
		t.Fatal("a changed hash passed the dated signature")
	}
	m.SignatureV2 = ""
	if err := verifyManifest(m); err == nil {
		t.Fatal("a changed hash passed the first signature")
	}
}
