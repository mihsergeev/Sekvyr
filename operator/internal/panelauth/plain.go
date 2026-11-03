package panelauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"golang.org/x/text/unicode/norm"
)

// PlainValue is accepted only from an authenticated fixed-origin legacy Plain
// endpoint. It is deliberately not verification.Value or an E2E2 Accepted.
type PlainValue struct{ path, name, value string }

func (PlainValue) String() string   { return "plain source value [redacted]" }
func (PlainValue) GoString() string { return "plain source value [redacted]" }
func (v PlainValue) Path() string   { return v.path }
func (v PlainValue) Name() string   { return v.name }
func (v PlainValue) Data() []byte   { return []byte(v.value) }

type PlainSnapshot struct {
	values                      []PlainValue
	valid                       bool
	project, environment, group string
}

func (PlainSnapshot) String() string   { return "authenticated plain snapshot [redacted]" }
func (PlainSnapshot) GoString() string { return "authenticated plain snapshot [redacted]" }
func (s *PlainSnapshot) Valid() bool   { return s != nil && s.valid }
func (s *PlainSnapshot) Matches(project, environment, group string) bool {
	return s.Valid() && s.project == project && s.environment == environment && s.group == group
}
func (s *PlainSnapshot) Values() []PlainValue {
	if s == nil {
		return nil
	}
	return append([]PlainValue{}, s.values...)
}

func plainSlug(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func plainMetadata(value string) bool {
	return utf8.ValidString(value) && norm.NFC.IsNormalString(value) && strings.IndexFunc(value, func(c rune) bool {
		return unicode.In(c, unicode.Cc, unicode.Cf, unicode.Cs)
	}) < 0
}

func plainPath(value string) bool {
	if len(value) == 0 || len(value) > 400 || value[0] != '/' || strings.Contains(value, "\\") || !plainMetadata(value) {
		return false
	}
	if value == "/" {
		return true
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// PlainSecrets never falls back from E2E2: callers must first authorize an
// explicit Plain binding. Encrypted projects/keys are rejected, even over TLS.
func (c *Client) PlainSecrets(ctx context.Context, s Session, group, project, environment string) (*PlainSnapshot, error) {
	if !plainSlug(project) || !plainSlug(environment) || group != "" && !plainSlug(group) {
		return nil, failure("ScopeDenied")
	}
	query := url.Values{"project": {project}, "env": {environment}}
	if group != "" {
		query.Set("group", group)
	}
	raw, err := c.boundedGET(ctx, s, "/api/v1/machine/secrets?"+query.Encode(), 32<<20)
	if err != nil {
		var typed *Error
		if errors.As(err, &typed) && typed.Reason == "CanonicalSnapshotUnavailable" {
			return nil, failure("SourceUnavailable")
		}
		return nil, err
	}
	snapshot, err := DecodePlainSnapshot(raw, project, environment)
	if err == nil {
		snapshot.group = group
	}
	return snapshot, err
}

// DecodePlainSnapshot validates the complete bounded response before any
// selection or Kubernetes mutation. No response field is a trust authority.
func DecodePlainSnapshot(raw []byte, project, environment string) (*PlainSnapshot, error) {
	var wire struct {
		Project     string `json:"project"`
		Environment string `json:"environment"`
		Values      []struct {
			Name  string `json:"name"`
			Path  string `json:"path"`
			Value string `json:"value"`
		} `json:"values"`
		E2E        *bool           `json:"e2e"`
		ProjectKey json.RawMessage `json:"project_key"`
	}
	canonical, err := e2e2.Canonical(raw, 32<<20)
	if err != nil {
		return nil, failure("SourceInvalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || wire.E2E == nil || wire.Values == nil {
		return nil, failure("SourceInvalid")
	}
	round, err := json.Marshal(wire)
	if err != nil {
		return nil, failure("SourceInvalid")
	}
	round, err = e2e2.Canonical(round, 32<<20)
	if err != nil || !bytes.Equal(round, canonical) {
		return nil, failure("SourceInvalid")
	}
	if *wire.E2E || !bytes.Equal(wire.ProjectKey, []byte("null")) {
		return nil, failure("UpgradeRequired")
	}
	if !plainSlug(project) || !plainSlug(environment) || wire.Project != project || wire.Environment != environment {
		return nil, failure("ScopeDenied")
	}
	if len(wire.Values) > 1024 {
		return nil, failure("SourceBounds")
	}
	seen, total := map[string]bool{}, 0
	values := make([]PlainValue, 0, len(wire.Values))
	for _, value := range wire.Values {
		if value.Name == "" || utf8.RuneCountInString(value.Name) > 120 || !plainMetadata(value.Name) || !plainPath(value.Path) {
			return nil, failure("SourceInvalid")
		}
		key := value.Path + "\x00" + value.Name
		if seen[key] {
			return nil, failure("DuplicateSourceKey")
		}
		seen[key] = true
		if len(value.Value) > (8<<20)-total {
			return nil, failure("SourceBounds")
		}
		total += len(value.Value)
		values = append(values, PlainValue{value.Path, value.Name, value.Value})
	}
	return &PlainSnapshot{values: values, valid: true, project: project, environment: environment}, nil
}
