package transport

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/panelauth"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
)

func TestPanelSourceReportsOnlyPinnedPublicKeyAndRedactsSession(t *testing.T) {
	const sessionMarker = "synthetic-private-panel-session"
	node, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ephemeral key generation failed")
	}
	var reports, envelopes int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/machine/token":
			fmt.Fprint(w, `{"access_token":"`+sessionMarker+`","token_type":"Bearer","expires_in":300,"name":"test-only"}`)
		case "/api/v1/machine/capabilities":
			fmt.Fprint(w, `{"protocols":["e2e2"]}`)
		case "/api/v1/machine/report":
			reports++
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["public_key"] != base64.StdEncoding.EncodeToString(node.PublicKey().Bytes()) {
				t.Error("unapproved report fields or node key")
			}
			fmt.Fprint(w, `{"ok":true}`)
		default:
			envelopes++
			fmt.Fprint(w, `{"fake":"wire-only"}`)
		}
	}))
	defer server.Close()
	claims := map[string]any{"sub": "system:serviceaccount:apps:operator", "aud": []string{"sekvyr"}, "exp": time.Now().Add(time.Hour).Unix(), "kubernetes.io": map[string]any{"namespace": "apps", "serviceaccount": map[string]string{"name": "operator", "uid": "test-sa"}, "pod": map[string]string{"uid": "test-pod"}}}
	raw, _ := json.Marshal(claims)
	tokenFile := filepath.Join(t.TempDir(), "projected-token")
	if os.WriteFile(tokenFile, []byte("test-header."+base64.RawURLEncoding.EncodeToString(raw)+".synthetic-not-a-signature"), 0600) != nil {
		t.Fatal("fixture token file failed")
	}
	s := testScope()
	scope := witness.Scope{RealmID: s.RealmID, ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID, ViewID: s.ViewID, LogID: s.LogID}
	source, err := NewPanelSource(panelauth.Config{Origin: server.URL, AllowedOrigins: []string{server.URL}, TokenFile: tokenFile, Namespace: "apps", ServiceAccount: "operator", Audience: "sekvyr", CustomCAPEM: ca(server)}, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	source.SetNodePublicKey(node.PublicKey().Bytes())
	for i := 0; i < 2; i++ {
		if _, err = source.EnvelopeByHash(context.Background(), scope, strings.Repeat("1", 64)); err != nil {
			t.Fatal(err)
		}
	}
	if reports != 1 || envelopes != 2 {
		t.Fatal("node public key report repeated or value request skipped")
	}
	for _, text := range []string{fmt.Sprintf("%v", source), fmt.Sprintf("%+v", source), fmt.Sprintf("%#v", source)} {
		if strings.Contains(text, sessionMarker) {
			t.Fatal("formatting disclosed panel session")
		}
	}
}
