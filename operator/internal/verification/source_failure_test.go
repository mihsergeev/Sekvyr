package verification

import (
	"errors"
	"testing"
)

type classifiedSourceFailure string

func (e classifiedSourceFailure) Error() string        { return "untrusted upstream response text" }
func (e classifiedSourceFailure) SourceReason() string { return string(e) }

func TestSourceFailureExposesOnlyExplicitSafeReasons(t *testing.T) {
	for _, reason := range []string{"AccessDenied", "AuthenticationDenied", "ScopeDenied", "PanelUnavailable", "RateLimited"} {
		var failure *Error
		if !errors.As(sourceFailure(classifiedSourceFailure(reason), "ReadKeyUnavailable"), &failure) || failure.Reason != reason {
			t.Fatal("safe classification was not preserved")
		}
	}
	for _, upstream := range []error{classifiedSourceFailure("unrecognized upstream content"), errors.New("raw upstream content")} {
		if sourceFailure(upstream, "ReadKeyUnavailable").Error() != "snapshot verification: ReadKeyUnavailable" {
			t.Fatal("untrusted source error escaped the fixed public reason boundary")
		}
	}
}
