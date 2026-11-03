package syncer

import (
	"errors"
	"strings"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/fencing"
)

func TestFenceReadyFailureProjectsOnlyClosedSafeReasons(t *testing.T) {
	cases := map[string]string{
		"JournalUnavailable": "FenceJournalUnavailable", "FencerUnavailable": "FenceTransportUnavailable",
		"LeaseMismatch": "FenceLeaseMismatch", "LeaseExpired": "FenceLeaseExpired", "LeaseUnavailable": "FenceLeaseUnavailable",
		"GrantChanged": "FenceGrantChanged", "GrantInvalid": "FenceGrantChanged", "GrantUnavailable": "FenceGrantChanged",
		"BarriersIncomplete": "FenceBarriersIncomplete", "ObjectMissing": "FenceBarriersIncomplete",
		"ObjectReplaced": "FenceBarriersIncomplete", "ObjectDenied": "FenceBarriersIncomplete",
		"ProjectedTokenInvalid": "FenceTokenInvalid", "ProjectedTokenUnavailable": "FenceTokenUnavailable",
		"AuthenticationDenied": "FenceAuthenticationDenied", "BoundPodRequired": "FenceAuthenticationDenied",
		"IdentityMismatch": "FenceIdentityMismatch", "IdentityRoleCollision": "FenceIdentityMismatch",
		"NamespaceReplaced": "FenceIdentityMismatch", "ServiceAccountReplaced": "FenceIdentityMismatch", "PodReplaced": "FenceIdentityMismatch",
		"EnrollmentMismatch": "FenceEnrollmentMismatch", "FencerBusy": "FenceBusy", "Cancelled": "FenceCancelled",
		"ResponseInvalid": "FenceResponseInvalid", "RedirectDenied": "FenceRedirectDenied", "FencerDenied": "FenceDenied",
		"PRIVATE_UPSTREAM_SENTINEL": "FenceDenied",
	}
	for source, expected := range cases {
		t.Run(source, func(t *testing.T) {
			err := fenceReadyFailure(&fencing.Error{Reason: source})
			if err == nil || Reason(err) != expected || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("diagnostic cause escaped the closed projection or failed open")
			}
		})
	}
	if err := fenceReadyFailure(errors.New("PRIVATE_ERROR_BODY")); err == nil || Reason(err) != "FenceDenied" || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("untyped failure was exposed or admitted")
	}
}
