package installation

import "testing"

func TestAdministrativeRolloutAllowlist(t *testing.T) {
	c := fixture()
	if c.RolloutEnabled || c.Validate() != nil {
		t.Fatal("rollout must remain disabled for existing installation configuration")
	}
	c.RolloutEnabled = true
	if c.Validate() == nil {
		t.Fatal("enabled rollout accepted without an administrative allowlist")
	}
	c.AllowedDeployments = []string{"application"}
	if c.Validate() != nil {
		t.Fatal("exact names should permit explicit rollout configuration")
	}
	for _, bad := range [][]string{{"application", "application"}, {"other/application"}, {"*"}, {""}, make([]string, 65)} {
		c.AllowedDeployments = bad
		if c.Validate() == nil {
			t.Fatal("ambiguous or unbounded Deployment authority accepted")
		}
	}
}
