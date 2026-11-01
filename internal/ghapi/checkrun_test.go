package ghapi

import (
	"testing"

	"github.com/cOmrade3267/authgraph/internal/report"
)

func rep(fs ...report.Finding) *report.ScanReport {
	return &report.ScanReport{TotalFindings: len(fs), Findings: fs}
}

func f(sev, conf string) report.Finding {
	return report.Finding{FindingID: "x", Severity: sev, Confidence: conf}
}

func TestCheckRunConclusion(t *testing.T) {
	cases := []struct {
		name           string
		r              *report.ScanReport
		wantConclusion string
		wantTitle      string
	}{
		{"no_findings_gives_success", rep(), "success", "No issues found"},
		{"likely_high_cwe78_style_finding_gives_failure", rep(f("ERROR", "likely")), "failure", "1 finding(s), policy: block"},
		{"unconfirmed_error_gives_neutral", rep(f("ERROR", "unconfirmed")), "neutral", "1 finding(s), policy: warn"},
		{"unconfirmed_warning_gives_neutral", rep(f("WARNING", "unconfirmed")), "neutral", "1 finding(s), policy: warn"},
		{"unconfirmed_info_gives_success", rep(f("INFO", "unconfirmed")), "success", "1 finding(s), policy: note"},
		{"block_plus_warn_gives_failure", rep(f("ERROR", "likely"), f("WARNING", "unconfirmed")), "failure", "2 finding(s), policy: block"},
		{"unknown_severity_fails_closed", rep(f("CRITICAL", "likely")), "failure", "Policy evaluation failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotC, gotT := checkRunConclusion(c.r)
			if gotC != c.wantConclusion || gotT != c.wantTitle {
				t.Fatalf("got (%s, %q), want (%s, %q)", gotC, gotT, c.wantConclusion, c.wantTitle)
			}
		})
	}
}
