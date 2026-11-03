package fencing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

func validUUID(value string) bool {
	return e2e2.ValidScope(e2e2.Scope{RealmID: value, ProjectID: value, EnvironmentID: value, ViewID: value, LogID: value})
}

func DecodeConfig(raw []byte) (Config, error) {
	var config Config
	if journal.DecodeStrict(raw, &config, maxWireBytes) != nil || !config.Trial || !validUUID(config.InstallationID) || !validUUID(config.LogID) ||
		len(validation.IsDNS1123Label(config.Namespace)) != 0 || !validUUID(config.NamespaceUID) || !validUUID(config.OperatorServiceAccountUID) || !validUUID(config.LeaseUID) ||
		len(validation.IsDNS1123Subdomain(config.FencerServiceAccount)) != 0 || !validUUID(config.FencerServiceAccountUID) || config.OperatorServiceAccountUID == config.FencerServiceAccountUID {
		return config, fail("ConfigInvalid")
	}
	refs, err := journal.CanonicalObjectRefs(config.ManagedObjects)
	if err != nil || !reflect.DeepEqual(refs, config.ManagedObjects) {
		return config, fail("ConfigInvalid")
	}
	for _, ref := range refs {
		if ref.Namespace != config.Namespace {
			return config, fail("ConfigInvalid")
		}
	}
	if len(config.MaterialPins) < 3 || len(config.MaterialPins) > 8 {
		return config, fail("ConfigInvalid")
	}
	materialNames := map[string]bool{}
	materialUIDs := map[string]bool{}
	for _, pin := range config.MaterialPins {
		if len(validation.IsDNS1123Subdomain(pin.Name)) != 0 || !validUUID(pin.UID) || pin.Key == "" || materialNames[pin.Name] || materialUIDs[pin.UID] {
			return config, fail("ConfigInvalid")
		}
		materialNames[pin.Name] = true
		materialUIDs[pin.UID] = true
	}
	if _, err = e2e2.Counter(config.MinimumCursor.JournalSequence, true); err != nil || len(config.MinimumCursor.RecordHash) != 64 {
		return config, fail("ConfigInvalid")
	}
	if len(config.BootstrapSubjects) < 1 || len(config.BootstrapSubjects) > 8 {
		return config, fail("ConfigInvalid")
	}
	seen := map[Subject]bool{}
	for _, subject := range config.BootstrapSubjects {
		if subject.Username == "" || len(subject.Username) > 253 || strings.ContainsAny(subject.Username, "\r\n\t") ||
			seen[subject] || subject.Username == serviceAccountUser(config.Namespace, config.FencerServiceAccount) || subject.UID == config.OperatorServiceAccountUID || subject.UID == config.FencerServiceAccountUID {
			return config, fail("ConfigInvalid")
		}
		seen[subject] = true
	}
	return config, nil
}

func (s *Service) Validate(ctx context.Context) error {
	raw, err := encodeWire(s.Config)
	if err != nil {
		return err
	}
	if _, err = DecodeConfig(raw); err != nil {
		return err
	}
	if len(s.SigningKey) != ed25519.PrivateKeySize || s.Reader == nil || s.Writer == nil || s.Auth == nil {
		return fail("ServiceConfigInvalid")
	}
	state, enrollment, err := s.read(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(s.Config.ManagedObjects, enrollment.AllowedObjects) {
		return fail("EnrollmentMismatch")
	}
	var ownAccount corev1.ServiceAccount
	if s.Reader.Get(ctx, types.NamespacedName{Namespace: s.Config.Namespace, Name: s.Config.FencerServiceAccount}, &ownAccount) != nil || string(ownAccount.UID) != s.Config.FencerServiceAccountUID {
		return fail("ServiceAccountReplaced")
	}
	for _, pin := range s.Config.MaterialPins {
		var secret corev1.Secret
		if s.Reader.Get(ctx, types.NamespacedName{Namespace: s.Config.Namespace, Name: pin.Name}, &secret) != nil || string(secret.UID) != pin.UID || secret.Immutable == nil || !*secret.Immutable || secret.Type != corev1.SecretTypeOpaque || len(secret.Data[pin.Key]) == 0 {
			return fail("MaterialReplaced")
		}
	}
	for _, subject := range s.Config.BootstrapSubjects {
		if subject.Username == serviceAccountUser(enrollment.Namespace, enrollment.OperatorServiceAccount) {
			return fail("ConfigInvalid")
		}
	}
	keyID := e2e2.KeyID(s.SigningKey.Public().(ed25519.PublicKey))
	found := false
	for _, key := range state.Authority.FencerKeys {
		if key.KeyID == keyID {
			found = true
		}
	}
	if !found {
		return fail("SigningKeyUnavailable")
	}
	return nil
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if !validRequestQuery(r) || r.URL.Fragment != "" || r.URL.RawPath != "" {
		httpError(w, http.StatusBadRequest, "RequestInvalid")
		return
	}
	if r.Method == http.MethodGet && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz") {
		if r.URL.Path == "/readyz" {
			if _, _, err := s.read(r.Context()); err != nil {
				httpError(w, http.StatusServiceUnavailable, "JournalUnavailable")
				return
			}
		}
		writeJSON(w, map[string]bool{"ready": true})
		return
	}
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "MethodDenied")
		return
	}
	if r.URL.Path == "/admit" {
		raw, err := readBody(w, r, maxAdmissionBytes)
		var review admissionv1.AdmissionReview
		if err != nil || journal.DecodeStrict(raw, &review, maxAdmissionBytes) != nil || review.APIVersion != "admission.k8s.io/v1" || review.Kind != "AdmissionReview" || review.Request == nil {
			httpError(w, http.StatusBadRequest, "AdmissionInvalid")
			return
		}
		writeJSON(w, admissionv1.AdmissionReview{TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}, Response: s.Admit(r.Context(), review.Request)})
		return
	}
	prefix := "/v1/installations/" + s.Config.InstallationID + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		httpError(w, http.StatusNotFound, "NotFound")
		return
	}
	header := r.Header.Values("Authorization")
	if len(header) != 1 || !strings.HasPrefix(header[0], "Bearer ") {
		httpError(w, http.StatusUnauthorized, "AuthenticationDenied")
		return
	}
	token := strings.TrimPrefix(header[0], "Bearer ")
	if token == "" || len(token) > 16384 || strings.ContainsAny(token, " \r\n\t") {
		httpError(w, http.StatusUnauthorized, "AuthenticationDenied")
		return
	}
	raw, err := readBody(w, r, 4096)
	if err != nil {
		httpError(w, http.StatusBadRequest, "RequestInvalid")
		return
	}
	var session *Session
	switch strings.TrimPrefix(r.URL.Path, prefix) {
	case "acquire":
		var body acquireRequest
		if journal.DecodeStrict(raw, &body, 4096) != nil || body.BootstrapGeneration < 1 || body.ExpectedLeaseHolderIdentity == "" {
			httpError(w, http.StatusBadRequest, "RequestInvalid")
			return
		}
		session, err = s.Acquire(r.Context(), token, body.BootstrapGeneration, body.ExpectedLeaseHolderIdentity)
	case "barriers", "ready":
		var body hashRequest
		if journal.DecodeStrict(raw, &body, 4096) != nil || len(body.GrantHash) != 64 {
			httpError(w, http.StatusBadRequest, "RequestInvalid")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/barriers") {
			session, err = s.Barriers(r.Context(), token, body.GrantHash)
		} else {
			session, err = s.Ready(r.Context(), token, body.GrantHash)
		}
	default:
		httpError(w, http.StatusNotFound, "NotFound")
		return
	}
	if err != nil {
		status := http.StatusConflict
		if Reason(err) == "AuthenticationDenied" || Reason(err) == "BoundPodRequired" {
			status = http.StatusUnauthorized
		}
		httpError(w, status, Reason(err))
		return
	}
	writeJSON(w, response{Grant: session.Grant(), GrantHash: session.hash, Active: session.ready})
}

// Kubernetes admission sends its remaining deadline as ?timeout=<seconds>s.
// Accept only that bounded canonical parameter on the admission endpoint;
// installation, health and grant APIs do not accept query parameters.
func validRequestQuery(r *http.Request) bool {
	if r.URL.RawQuery == "" {
		return !r.URL.ForceQuery
	}
	if r.Method != http.MethodPost || r.URL.Path != "/admit" || !strings.HasPrefix(r.URL.RawQuery, "timeout=") {
		return false
	}
	value := strings.TrimPrefix(r.URL.RawQuery, "timeout=")
	seconds, err := strconv.Atoi(strings.TrimSuffix(value, "s"))
	return err == nil && seconds >= 1 && seconds <= 30 && value == strconv.Itoa(seconds)+"s"
}

func readBody(w http.ResponseWriter, r *http.Request, max int) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, int64(max))
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fail("RequestInvalid")
	}
	return raw, nil
}
func writeJSON(w http.ResponseWriter, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "EncodingInvalid")
		return
	}
	_, _ = w.Write(raw)
}
func httpError(w http.ResponseWriter, status int, reason string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"reason":"` + reason + `"}`))
}
