package sandbox

import (
	"testing"

	"github.com/cOmrade3267/authgraph/internal/report"
)

func TestAssignConfidence(t *testing.T) {
	cases := []struct {
		name, cwe, semgrep, in, want string
	}{
		{"cwe78_semgrep_high_becomes_likely", "CWE-78", "HIGH", "unconfirmed", "likely"},
		{"cwe78_semgrep_high_lowercase_becomes_likely", "CWE-78", "high", "unconfirmed", "likely"},
		{"cwe78_semgrep_medium_stays_unconfirmed", "CWE-78", "MEDIUM", "unconfirmed", "unconfirmed"},
		{"cwe862_semgrep_high_stays_unconfirmed", "CWE-862", "HIGH", "unconfirmed", "unconfirmed"},
		{"cwe918_semgrep_medium_stays_unconfirmed", "CWE-918", "MEDIUM", "unconfirmed", "unconfirmed"},
		{"already_confirmed_cwe78_is_not_downgraded", "CWE-78", "HIGH", "confirmed", "confirmed"},
		{"already_inconclusive_cwe78_is_not_changed", "CWE-78", "HIGH", "inconclusive", "inconclusive"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := report.Finding{CWE: c.cwe, SemgrepConfidence: c.semgrep, Confidence: c.in}
			assignConfidence(&f)
			if f.Confidence != c.want {
				t.Fatalf("confidence = %s, want %s", f.Confidence, c.want)
			}
		})
	}
}
