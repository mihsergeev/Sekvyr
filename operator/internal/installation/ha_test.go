package installation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	"k8s.io/apimachinery/pkg/types"
)

func haFixture(t *testing.T) Config {
	t.Helper()
	c := fixture()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ref := &CARef{Name: "independent-ca", Key: "ca.crt"}
	c.CAConfigMaps = []CAPin{{Name: ref.Name, Key: ref.Key, UID: "55555555-5555-4555-8555-555555555555", DERSetSHA256: strings.Repeat("a", 64)}}
	c.AllowedTargetSecrets = []string{"application-data"}
	c.HA = &HAConfig{Trial: true, FencerOrigin: "https://fencer.example.test", AllowedFencerOrigins: []string{"https://fencer.example.test"}, FencerCAConfigMapRef: ref, GatewayOrigin: "https://journal.example.test", GatewayCAConfigMapRef: ref, GatewayClientSecret: SecretPin{Name: "journal-client", UID: "66666666-6666-4666-8666-666666666666", Key: "tls.crt"}, GatewayClientKeyKey: "tls.key", Journal: journal.Registration{LogID: "77777777-7777-4777-8777-777777777777", GenesisHash: strings.Repeat("b", 64), AdminPublicKey: base64.RawURLEncoding.EncodeToString(public), MinimumCursor: journal.Cursor{JournalSequence: "0", RecordHash: strings.Repeat("b", 64)}}}
	return c
}
func TestHARequiresExplicitIndependentPinsAndSingleTarget(t *testing.T) {
	if err := haFixture(t).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"production not configured": func(c *Config) { c.HA.Trial = false },
		"multi target":              func(c *Config) { c.AllowedTargetSecrets = append(c.AllowedTargetSecrets, "another") },
		"multi witness": func(c *Config) {
			c.AllowedWitnessOrigins = append(c.AllowedWitnessOrigins, "https://another.example.test")
		},
		"untrusted fencer":          func(c *Config) { c.HA.FencerOrigin = "https://unexpected.example.test" },
		"shared journal witness":    func(c *Config) { c.HA.GatewayOrigin = c.AllowedWitnessOrigins[0] },
		"mutable identity adoption": func(c *Config) { c.HA.GatewayClientSecret.UID = c.IdentityKeySecret.UID },
		"client credential target":  func(c *Config) { c.AllowedTargetSecrets = []string{c.HA.GatewayClientSecret.Name} },
		"missing CA pin":            func(c *Config) { c.HA.GatewayCAConfigMapRef = &CARef{Name: "untrusted", Key: "ca.crt"} },
		"unsigned genesis":          func(c *Config) { c.HA.Journal.GenesisHash = journal.ZeroHash },
		"invalid admin":             func(c *Config) { c.HA.Journal.AdminPublicKey = "invalid" },
		"ambiguous floor":           func(c *Config) { c.HA.Journal.MinimumCursor.JournalSequence = "00" },
		"overflow floor":            func(c *Config) { c.HA.Journal.MinimumCursor.JournalSequence = "18446744073709551616" },
	} {
		t.Run(name, func(t *testing.T) {
			c := haFixture(t)
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("unsafe HA profile accepted")
			}
		})
	}
	c := haFixture(t)
	if !c.Protected(c.HA.GatewayClientSecret.Name, "") || !c.Protected("renamed", types.UID(c.HA.GatewayClientSecret.UID)) {
		t.Fatal("journal client credentials not protected")
	}
}
