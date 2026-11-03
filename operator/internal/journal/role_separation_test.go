package journal

import (
	"context"
	"testing"
)

func TestSignedEnrollmentCannotCombineOperatorAndFencerRoles(t *testing.T) {
	for _, sameName := range []bool{false, true} {
		name := "same-uid"
		if sameName {
			name = "same-name"
		}
		t.Run(name, func(t *testing.T) {
			f := setupJournal(t)
			f.initial(t)
			e := enrollment(t)
			if sameName {
				e.FencerServiceAccount = e.OperatorServiceAccount
			} else {
				e.FencerServiceAccountUID = e.OperatorServiceAccountUID
			}
			next := f.state.Authority
			next.Revision, _ = nextCounter(next.Revision)
			if _, err := f.transition(t, "enroll-installation", next, &e, nil); err == nil {
				t.Fatal("signed role collision accepted")
			}
			current, err := f.ledger.ReadCurrent(context.Background(), f.state.Scope.LogID, f.state.Cursor)
			if err != nil || current.Cursor != f.state.Cursor || len(current.Enrollments) != 0 {
				t.Fatal("rejected role collision mutated journal", err)
			}
		})
	}
}
