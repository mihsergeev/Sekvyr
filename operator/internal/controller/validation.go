package controller

import (
	"golang.org/x/text/unicode/norm"
	"strings"
	"unicode"
	"unicode/utf8"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"k8s.io/apimachinery/pkg/util/validation"
)

func validText(value string) bool {
	return utf8.ValidString(value) && norm.NFC.IsNormalString(value) && strings.IndexFunc(value, func(r rune) bool { return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs) }) < 0
}
func canonicalPath(path string) bool {
	if path == "" || len(path) > 400 || path[0] != '/' || strings.Contains(path, "\\") || !validText(path) {
		return false
	}
	if path == "/" {
		return true
	}
	for _, part := range strings.Split(path[1:], "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func within(path, prefix string) bool {
	return path == prefix || prefix == "/" || strings.HasPrefix(path, prefix+"/")
}
func label(value string) bool { return len(validation.IsDNS1123Label(value)) == 0 }
func uniqueNames(names []string, maximum int) bool {
	if len(names) > maximum {
		return false
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !installation.ValidName(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

// ValidateStore validates authorization shape only. Historical immutability and ownership
// need a durable registry and are intentionally not asserted by the stage-2 scaffold.
func ValidateStore(c installation.Config, store *api.SekvyrStore) error {
	if store.Namespace != c.Namespace {
		return installation.Reject("ScopeDenied")
	}
	if !installation.ValidName(store.Name) || !installation.ValidUUID(string(store.UID)) || len(store.Spec.Bindings) < 1 || len(store.Spec.Bindings) > 64 {
		return installation.Reject("InvalidSpec")
	}
	if !c.AllowsPanelOrigin(store.Spec.Endpoint.URL) {
		return installation.Reject("ScopeDenied")
	}
	if ref := store.Spec.Endpoint.CAConfigMapRef; ref != nil {
		found := false
		for _, pin := range c.CAConfigMaps {
			if ref.Name == pin.Name && ref.Key == pin.Key {
				found = true
			}
		}
		if !found {
			return installation.Reject("ScopeDenied")
		}
	}
	ids, names, resources, targets := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, b := range store.Spec.Bindings {
		if !installation.ValidUUID(b.ID) || !label(b.Name) || !installation.ValidName(b.ResourceName) || !installation.ValidName(b.Target.Name) {
			return installation.Reject("InvalidSpec")
		}
		if ids[b.ID] || names[b.Name] || resources[b.ResourceName] || targets[b.Target.Name] {
			return installation.Reject("BindingConflict")
		}
		ids[b.ID], names[b.Name], resources[b.ResourceName], targets[b.Target.Name] = true, true, true, true
		if c.Protected(b.Target.Name, "") {
			return installation.Reject("ProtectedTarget")
		}
		if b.Target.Type != "" && b.Target.Type != "Opaque" {
			return installation.Reject("InvalidSpec")
		}
		if b.Target.DeletionPolicy != "" && b.Target.DeletionPolicy != "Retain" && b.Target.DeletionPolicy != "Delete" {
			return installation.Reject("InvalidSpec")
		}
		if (b.Source.Group != "" && !label(b.Source.Group)) || !label(b.Source.Project) || !label(b.Source.Environment) || !canonicalPath(b.Source.PathPrefix) {
			return installation.Reject("InvalidSpec")
		}
		switch b.Encryption.Mode {
		case "Plain":
			if b.Encryption.Protocol != "" || b.Encryption.TrustKey != "" || b.Encryption.Freshness != nil || b.Source.ViewID != "" {
				return installation.Reject("InvalidSpec")
			}
		case "E2E":
			if b.Encryption.Protocol != "e2e2" || !installation.ValidUUID(b.Source.ViewID) || b.Encryption.Freshness == nil || b.Encryption.Freshness.Mode != "WitnessCurrent" || len(b.Encryption.TrustKey) > 63 || !installation.ValidName(b.Encryption.TrustKey) || len(c.AllowedWitnessOrigins) == 0 {
				return installation.Reject("InvalidSpec")
			}
		default:
			return installation.Reject("InvalidSpec")
		}
		if b.Selection.Mode == "All" {
			if len(b.Selection.Keys) != 0 {
				return installation.Reject("InvalidSpec")
			}
		} else if b.Selection.Mode == "Keys" {
			if len(b.Selection.Keys) < 1 || len(b.Selection.Keys) > 1024 {
				return installation.Reject("InvalidSpec")
			}
			sources, outputs := map[string]bool{}, map[string]bool{}
			for _, k := range b.Selection.Keys {
				if !canonicalPath(k.Path) || !within(k.Path, b.Source.PathPrefix) || k.Name == "" || len(k.Name) > 120 || !validText(k.Name) || len(validation.IsConfigMapKey(k.TargetKey)) != 0 {
					return installation.Reject("InvalidSpec")
				}
				tuple := k.Path + "\x00" + k.Name
				if sources[tuple] || outputs[k.TargetKey] {
					return installation.Reject("BindingConflict")
				}
				sources[tuple], outputs[k.TargetKey] = true, true
			}
		} else {
			return installation.Reject("InvalidSpec")
		}
		if !uniqueNames(b.Rollout.AllowedDeployments, 32) {
			return installation.Reject("InvalidSpec")
		}
	}
	return nil
}

// ValidateBindings checks all Store reservations before any panel/witness operation.
func ValidateBindings(c installation.Config, stores []api.SekvyrStore) error {
	resources, targets := map[string]bool{}, map[string]bool{}
	for i := range stores {
		store := &stores[i]
		if err := ValidateStore(c, store); err != nil {
			return err
		}
		for _, b := range store.Spec.Bindings {
			if resources[b.ResourceName] || targets[b.Target.Name] {
				return installation.Reject("BindingConflict")
			}
			resources[b.ResourceName], targets[b.Target.Name] = true, true
		}
	}
	return nil
}

func ValidateSecret(c installation.Config, secret *api.SekvyrSecret, store *api.SekvyrStore) (*api.Binding, error) {
	if secret.Namespace != c.Namespace || store.Namespace != c.Namespace {
		return nil, installation.Reject("ScopeDenied")
	}
	if !installation.ValidName(secret.Name) || !installation.ValidUUID(string(secret.UID)) || !installation.ValidName(secret.Spec.StoreRef.Name) || !installation.ValidUUID(secret.Spec.StoreRef.UID) || !label(secret.Spec.Binding) {
		return nil, installation.Reject("InvalidSpec")
	}
	if secret.Spec.StoreRef.Name != store.Name || secret.Spec.StoreRef.UID != string(store.UID) || !store.DeletionTimestamp.IsZero() {
		return nil, installation.Reject("BootstrapMismatch")
	}
	if secret.Spec.RefreshIntervalSeconds != 0 && (secret.Spec.RefreshIntervalSeconds < 30 || secret.Spec.RefreshIntervalSeconds > 86400) {
		return nil, installation.Reject("InvalidSpec")
	}
	if !uniqueNames(secret.Spec.Rollout.Deployments, 32) || (!secret.Spec.Rollout.Enabled && len(secret.Spec.Rollout.Deployments) != 0) || (secret.Spec.Rollout.Enabled && len(secret.Spec.Rollout.Deployments) == 0) {
		return nil, installation.Reject("InvalidSpec")
	}
	for i := range store.Spec.Bindings {
		b := &store.Spec.Bindings[i]
		if b.Name != secret.Spec.Binding {
			continue
		}
		if b.ResourceName != secret.Name {
			return nil, installation.Reject("ScopeDenied")
		}
		if c.Protected(b.Target.Name, "") {
			return nil, installation.Reject("ProtectedTarget")
		}
		for _, requested := range secret.Spec.Rollout.Deployments {
			allowed := false
			for _, name := range b.Rollout.AllowedDeployments {
				if name == requested {
					allowed = true
				}
			}
			if !allowed {
				return nil, installation.Reject("ScopeDenied")
			}
		}
		return b, nil
	}
	return nil, installation.Reject("ScopeDenied")
}
