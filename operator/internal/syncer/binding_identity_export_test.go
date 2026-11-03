package syncer

import (
	"testing"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
)

func TestOfflineBindingIdentityPreservesRuntimeGoJSON(t *testing.T) {
	b := api.Binding{ID: "11111111-1111-4111-8111-111111111111", Name: "app", ResourceName: "app-secret", Source: api.Source{Project: "demo", Environment: "prod", PathPrefix: "/"}, Encryption: api.Encryption{Mode: "Plain"}, Target: api.Target{Name: "target"}}
	if BindingIdentity(b) != bindingIdentity(b) || BindingIdentity(b) != "51750f938a57960371beebabd71e6d4e9e291fabf9a520e9a3d9f35eaa4fe240" {
		t.Fatal("Plain Go JSON identity changed")
	}
	b.Source.ViewID = "22222222-2222-4222-8222-222222222222"
	b.Encryption = api.Encryption{Mode: "E2E", Protocol: "e2e2", TrustKey: "view", Freshness: &api.Freshness{Mode: "WitnessCurrent"}}
	if BindingIdentity(b) != bindingIdentity(b) || BindingIdentity(b) != "fcd831130a7fbb0565712b406e45a931d21f964687a4261058155701066a91fc" {
		t.Fatal("E2E Go JSON identity changed")
	}
	before := BindingIdentity(b)
	b.Source.Project = "renamed"
	b.Source.PathPrefix = "/moved"
	if BindingIdentity(b) != before {
		t.Fatal("E2E routing-only rename changed identity")
	}
	b.Target.Name = "other-target"
	if BindingIdentity(b) == before {
		t.Fatal("target identity lost")
	}
}
