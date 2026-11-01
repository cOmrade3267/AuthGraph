package ghapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cOmrade3267/authgraph/internal/policy"
	"github.com/cOmrade3267/authgraph/internal/report"
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

// FormatReportAsComment renders a ScanReport as the Markdown shown in the PR
// comment and in the Check Run summary. One renderer for both.
//
// Everything that originates in the scanned PR (file paths, snippets) or the
// scanner (messages) is untrusted data: it is rendered inside code spans/fences
// or sanitized, never interpolated as raw Markdown.
func FormatReportAsComment(r *report.ScanReport) string {
	var b strings.Builder

	result, perr := policy.Evaluate(*r)

	if r.TotalFindings == 0 {
		b.WriteString("### ✅ AuthGraph — No issues found\n\n")
		b.WriteString("No security findings.\n")
		return b.String()
	}

	switch {
	case perr != nil:
		b.WriteString(fmt.Sprintf("### ❌ AuthGraph — policy evaluation failed · %d finding(s)\n\n", r.TotalFindings))
		b.WriteString("The policy could not be evaluated, so this check fails closed.\n\n")
	default:
		b.WriteString(fmt.Sprintf("### %s AuthGraph — policy: **%s** · %d finding(s)\n\n",
			decisionIcon(result.Overall), result.Overall, r.TotalFindings))
	}

	// Decisions are returned in input order with suppressed findings omitted,
	// so walk the findings the same way to pair each with its decision.
	decisions := map[int]string{}
	if perr == nil {
		k := 0
		for i, f := range r.Findings {
			if f.Suppressed {
				continue
			}
			if k < len(result.Findings) {
				decisions[i] = result.Findings[k].Decision
				k++
			}
		}
	}

	const maxInline = 10
	listed, suppressed := 0, 0
	for i, f := range r.Findings {
		if f.Suppressed {
			suppressed++
			continue
		}
		if listed >= maxInline {
			continue
		}
		listed++
		b.WriteString(renderFinding(f, decisions[i]))
	}

	if hidden := len(r.Findings) - suppressed - listed; hidden > 0 {
		b.WriteString(fmt.Sprintf("_...and %d more finding(s) not shown._\n\n", hidden))
	}
	if suppressed > 0 {
		b.WriteString(fmt.Sprintf("_%d suppressed finding(s) not shown._\n\n", suppressed))
	}

	b.WriteString("<sub>Decision key: **block** fails the check, **warn** is neutral, **note** passes. " +
		"Static findings are `unconfirmed` until dynamic verification exists; high-confidence CWE-78 matches are `likely`.</sub>\n")
	return b.String()
}

func renderFinding(f report.Finding, decision string) string {
	var b strings.Builder

	loc := fmt.Sprintf("%s:%d", relPath(f.Location.File), f.Location.Line)
	where := inlineCode(loc)
	if f.Location.Function != nil && *f.Location.Function != "" {
		where += " in " + inlineCode(*f.Location.Function+"()")
	}
	label := decision
	if label == "" {
		label = "n/a"
	}
	b.WriteString(fmt.Sprintf("#### %s %s · %s · %s · confidence: %s\n",
		decisionIcon(decision), label, inlineCode(f.CWE), oneLine(f.Severity), oneLine(f.Confidence)))
	b.WriteString(where + "\n\n")

	if msg := oneLine(f.Evidence.Static.Message); msg != "" {
		b.WriteString("> " + msg + "\n\n")
	}
	if snip := trimSnippet(f.Evidence.Static.Snippet); snip != "" {
		b.WriteString(fenced("go", snip) + "\n")
	}
	if len(f.References) > 0 {
		b.WriteString("References:\n")
		for _, ref := range f.References {
			b.WriteString("- " + oneLine(ref) + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func decisionIcon(d string) string {
	switch d {
	case policy.Block:
		return "🔴"
	case policy.Warn:
		return "🟡"
	case policy.Note:
		return "⚪"
	}
	return "❔"
}

// relPath drops the sandbox mount prefix so users see repo-relative paths.
func relPath(p string) string { return strings.TrimPrefix(p, "/target/") }

// oneLine makes untrusted text safe for a single Markdown line: collapses
// whitespace, neutralizes HTML and @mentions.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "@", "@\u200b")
	return s
}

// inlineCode wraps untrusted text in a code span that it cannot close early.
func inlineCode(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.ReplaceAll(s, "`", "'")
	return "`" + s + "`"
}

// trimSnippet caps snippet size so one finding cannot flood the comment.
func trimSnippet(s string) string {
	s = strings.TrimRight(s, "\n\r\t ")
	if s == "" {
		return ""
	}
	const maxLines, maxChars = 15, 1500
	lines := strings.Split(s, "\n")
	truncated := false
	if len(lines) > maxLines {
		lines, truncated = lines[:maxLines], true
	}
	s = strings.Join(lines, "\n")
	if len(s) > maxChars {
		s, truncated = s[:maxChars], true
	}
	if truncated {
		s += "\n// ... truncated"
	}
	return s
}

// fenced puts untrusted text in a code fence longer than any backtick run
// inside it, so the content cannot break out of the block.
func fenced(lang, content string) string {
	longest, run := 0, 0
	for _, r := range content {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	return fence + lang + "\n" + content + "\n" + fence + "\n"
}
