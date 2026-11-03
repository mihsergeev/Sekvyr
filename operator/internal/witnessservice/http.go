package witnessservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if s == nil || s.slots == nil {
		writeFailure(w, fail("ServiceUnavailable"))
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		writeFailure(w, fail("RequestInvalid"))
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/capabilities" {
		json.NewEncoder(w).Encode(map[string]any{"format": "sekvyr-witness-capabilities-v1", "profile": DevelopmentProfile, "production_ready": false, "ledger": "full-replay-exclusive-cas-fsync", "authority_rotation": false})
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if r.Method != http.MethodPost || len(parts) != 5 || parts[0] != "" || parts[1] != "v1" || parts[2] != "logs" || !validLog(parts[3]) || (parts[4] != "head-challenge" && parts[4] != "commits") {
		writeFailure(w, fail("RouteDenied"))
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		writeFailure(w, fail("Busy"))
		return
	}
	content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || content != "application/json" {
		writeFailure(w, fail("RequestInvalid"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	if err != nil {
		writeFailure(w, fail("RequestInvalid"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if parts[4] == "head-challenge" {
		request, err := decodeHead(body)
		if err != nil {
			writeFailure(w, err)
			return
		}
		proof, err := s.Head(ctx, parts[3], request)
		if err != nil {
			writeFailure(w, err)
			return
		}
		w.Write(proof)
		return
	}
	request, err := decodeCommit(body)
	if err != nil {
		writeFailure(w, err)
		return
	}
	response, err := s.Commit(ctx, parts[3], request)
	if err != nil {
		writeFailure(w, err)
		return
	}
	json.NewEncoder(w).Encode(response)
}
func writeFailure(w http.ResponseWriter, err error) {
	reason := "ServiceUnavailable"
	var safe *Error
	if errors.As(err, &safe) {
		reason = safe.Reason
	}
	status := http.StatusServiceUnavailable
	switch reason {
	case "Busy":
		status = http.StatusTooManyRequests
	case "CASConflict":
		status = http.StatusConflict
	case "RouteDenied", "LogUnknown":
		status = http.StatusNotFound
	case "RequestInvalid", "ChallengeInvalid", "CommitInvalid", "FloorUnknownOrFork", "EnvelopeInvalid", "EnvelopeFork", "AuthorityTransitionNotSupported", "StagedEnvelopeHashMismatch":
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"reason": reason})
}
