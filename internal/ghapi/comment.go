package ghapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cOmrade3267/authgraph/internal/sandbox"
)

// commentBody mirrors the JSON body GitHub expects when creating an
// issue/PR comment. PRs are treated as issues for commenting purposes —
// that's why the endpoint says "issues" even though we're commenting on a PR.
type commentBody struct {
	Body string `json:"body"`
}

// postPRComment posts a single comment to the given PR, authenticated
// with an installation access token.
func PostPRComment(installToken, owner, repo string, prNumber int, body string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%d/comments", owner, repo, prNumber)

	payload, err := json.Marshal(commentBody{Body: body})
	if err != nil {
		return fmt.Errorf("encoding comment body: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building comment request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+installToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("posting comment: %w", err)
	}
	defer resp.Body.Close()

	// GitHub returns 201 Created on success.
	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d posting comment: %s", resp.StatusCode, respBody)
	}

	return nil
}

// formatReportAsComment turns a ScanReport into a readable Markdown
// comment body. Kept separate from postPRComment so formatting can
// change independently of the HTTP mechanics.
func FormatReportAsComment(report *sandbox.ScanReport) string {
	var b strings.Builder

	if report.TotalFindings == 0 {
		b.WriteString("### ✅ SentryGrep Scan — No issues found\n\n")
		b.WriteString("No security findings at or above the configured threshold.\n")
		return b.String()
	}

	b.WriteString(fmt.Sprintf("### ⚠️ SentryGrep Scan — %d finding(s)\n\n", report.TotalFindings))

	b.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sev := range []string{"ERROR", "WARNING", "INFO"} {
		if count, ok := report.BySeverity[sev]; ok && count > 0 {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", sev, count))
		}
	}
	b.WriteString("\n")

	// Cap how many individual findings we list inline — a huge PR with
	// hundreds of findings would produce a comment GitHub might truncate
	// or that's just unreadable. Point to the full report for the rest.
	const maxInline = 10
	shown := report.Findings
	if len(shown) > maxInline {
		shown = shown[:maxInline]
	}

	for _, f := range shown {
		b.WriteString(fmt.Sprintf("**[%s]** `%s:%d` — %s (%s)\n\n",
			f.Severity, f.File, f.Line, f.Message, f.CWE))
	}

	if len(report.Findings) > maxInline {
		b.WriteString(fmt.Sprintf("_...and %d more finding(s) not shown._\n",
			len(report.Findings)-maxInline))
	}

	return b.String()
}
