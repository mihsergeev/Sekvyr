package rollout

import (
	"context"
	"testing"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
)

func TestPlainRolloutRequiresFreshAuthenticationAndProtectedGuard(t *testing.T) {
	for _, scenario := range []string{"fresh", "outage", "no-guard", "e2e-downgrade", "ambiguous", "plain-with-current-flag"} {
		t.Run(scenario, func(t *testing.T) {
			r, q, writer, _, _ := fixture(t)
			q.Binding.Encryption = api.Encryption{Mode: "Plain"}
			q.StrictCurrent = false
			q.AuthenticatedPlain = true
			switch scenario {
			case "outage":
				q.AuthenticatedPlain = false
			case "no-guard":
				q.Guard = nil
			case "e2e-downgrade":
				q.Binding.Encryption = api.Encryption{Mode: "E2E", Protocol: "e2e2"}
			case "ambiguous":
				q.StrictCurrent = true
			case "plain-with-current-flag":
				q.StrictCurrent = true
				q.AuthenticatedPlain = false
			}
			result := r.Reconcile(context.Background(), q, authorize)
			if scenario == "fresh" {
				if writer.patches != 1 || result.Reason != "RolloutProgressing" {
					t.Fatal(result, writer.patches)
				}
			} else if writer.patches != 0 || result.Reason != "CurrentVerificationRequired" {
				t.Fatal("Plain authentication bypassed mode/current/protected-state gate", result, writer.patches)
			}
		})
	}
}
