package ghapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cOmrade3267/authgraph/internal/report"
)

func fn(s string) *string { return &s }

func finding(sev, conf, cwe, file string, line int, function, msg, snippet string, refs ...string) report.Finding {
	f := report.Finding{
		FindingID: "id", Severity: sev, Confidence: conf, CWE: cwe, References: refs,
		Location: report.Location{File: file, Line: line, Function: fn(function)},
		Evidence: report.Evidence{Static: report.StaticEvidence{Message: msg, Snippet: snippet}},
	}
	return f
}

func rpt(fs ...report.Finding) *report.ScanReport {
	return &report.ScanReport{TotalFindings: len(fs), Findings: fs}
}

func mustContain(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("output missing %q\n---\n%s", w, got)
		}
	}
}

func mustNotContain(t *testing.T, got string, bad ...string) {
	t.Helper()
	for _, w := range bad {
		if strings.Contains(got, w) {
			t.Errorf("output must not contain %q\n---\n%s", w, got)
		}
	}
}

func TestComment_EmptyReportSaysNoIssuesUnderAuthGraphBrand(t *testing.T) {
	got := FormatReportAsComment(&report.ScanReport{})
	mustContain(t, got, "AuthGraph", "No issues found")
	mustNotContain(t, got, "SentryGrep")
}

func TestComment_BlockFindingShowsDecisionFunctionSnippetAndReferences(t *testing.T) {
	r := rpt(finding("ERROR", "likely", "CWE-78", "/target/run.go", 6, "vulnerable",
		"Command injection via exec.Command", "exec.Command(\"sh\", \"-c\", someVar).Run()",
		"https://github.com/civo/cli/pull/595"))
	got := FormatReportAsComment(r)
	mustContain(t, got,
		"AuthGraph — policy: **block**",
		"🔴 block", "`CWE-78`", "`run.go:6`", "`vulnerable()`",
		"confidence: likely", "Command injection via exec.Command",
		"exec.Command(\"sh\"", "- https://github.com/civo/cli/pull/595")
	mustNotContain(t, got, "/target/", "SentryGrep")
}

func TestComment_WarnOnlyReportHeadlineIsWarn(t *testing.T) {
	r := rpt(finding("WARNING", "unconfirmed", "CWE-862", "/target/t.go", 24, "removeTicket", "Missing ownership check", ""))
	got := FormatReportAsComment(r)
	mustContain(t, got, "policy: **warn**", "🟡 warn")
	mustNotContain(t, got, "🔴")
}

func TestComment_MixedFindingsHeadlineIsStrictestAndEachRowHasOwnDecision(t *testing.T) {
	r := rpt(
		finding("ERROR", "likely", "CWE-78", "/target/a.go", 1, "a", "m1", ""),
		finding("WARNING", "unconfirmed", "CWE-918", "/target/b.go", 2, "b", "m2", ""),
	)
	got := FormatReportAsComment(r)
	mustContain(t, got, "policy: **block**", "🔴 block", "🟡 warn")
}

func TestComment_SnippetContainingTripleBackticksCannotBreakOutOfFence(t *testing.T) {
	snippet := "x := 1\n```\n## injected heading\n```\n"
	got := FormatReportAsComment(rpt(finding("WARNING", "unconfirmed", "CWE-862", "/target/t.go", 1, "f", "m", snippet)))
	// the fence around the snippet must be longer than the 3 backticks inside it
	mustContain(t, got, "````go\n")
	mustContain(t, got, "\n````\n")
}

func TestComment_MarkdownHtmlAndMentionsInUntrustedTextAreNeutralized(t *testing.T) {
	r := rpt(finding("WARNING", "unconfirmed", "CWE-862", "/target/we`ird.go", 1, "f",
		"<img src=x onerror=1> ping @octocat", ""))
	got := FormatReportAsComment(r)
	mustNotContain(t, got, "<img", "@octocat")
	mustContain(t, got, "&lt;img", "@​octocat", "`we'ird.go:1`")
}

func TestComment_LongSnippetIsTruncated(t *testing.T) {
	long := strings.Repeat("line\n", 40)
	got := FormatReportAsComment(rpt(finding("WARNING", "unconfirmed", "CWE-862", "/target/t.go", 1, "f", "m", long)))
	mustContain(t, got, "// ... truncated")
	if n := strings.Count(got, "line\n"); n > 15 {
		t.Errorf("snippet shows %d lines, want at most 15", n)
	}
}

func TestComment_MoreThanTenFindingsListsTenAndCountsTheRest(t *testing.T) {
	var fs []report.Finding
	for i := 0; i < 13; i++ {
		fs = append(fs, finding("WARNING", "unconfirmed", "CWE-862", fmt.Sprintf("/target/f%d.go", i), i+1, "f", "m", ""))
	}
	got := FormatReportAsComment(rpt(fs...))
	mustContain(t, got, "3 more finding(s) not shown", "13 finding(s)")
	if n := strings.Count(got, "#### "); n != 10 {
		t.Errorf("listed %d findings, want 10", n)
	}
}

func TestComment_SuppressedFindingsAreCountedNotListed(t *testing.T) {
	s := finding("ERROR", "likely", "CWE-78", "/target/hidden.go", 1, "h", "m", "")
	s.Suppressed = true
	got := FormatReportAsComment(rpt(s, finding("WARNING", "unconfirmed", "CWE-918", "/target/b.go", 2, "b", "m2", "")))
	mustContain(t, got, "1 suppressed finding(s) not shown", "policy: **warn**", "`b.go:2`")
	mustNotContain(t, got, "hidden.go")
}

func TestComment_UnknownSeverityFailsClosedWithVisibleMessage(t *testing.T) {
	got := FormatReportAsComment(rpt(finding("CRITICAL", "likely", "CWE-78", "/target/a.go", 1, "a", "m", "")))
	mustContain(t, got, "policy evaluation failed", "fails closed")
}

func TestComment_MissingFunctionNameStillRenders(t *testing.T) {
	f := finding("WARNING", "unconfirmed", "CWE-862", "/target/t.go", 9, "", "m", "")
	f.Location.Function = nil
	got := FormatReportAsComment(rpt(f))
	mustContain(t, got, "`t.go:9`")
	mustNotContain(t, got, "in ``", "()`")
}
