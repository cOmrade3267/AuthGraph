package ghapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cOmrade3267/authgraph/internal/sandbox"
)

type checkRunOutput struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

type checkRunBody struct {
	Name       string         `json:"name"`
	HeadSHA    string         `json:"head_sha,omitempty"`
	Status     string         `json:"status"`
	Conclusion string         `json:"conclusion,omitempty"`
	Output     checkRunOutput `json:"output"`
}

// createCheckRun creates a new Check Run in "in_progress" state.
// Returns the check run's ID so it can be updated later.
func CreateCheckRun(installToken, owner, repo, headSHA string) (int64, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/check-runs", owner, repo)

	body := checkRunBody{
		Name:    "SentryGrep Security Scan",
		HeadSHA: headSHA,
		Status:  "in_progress",
		Output: checkRunOutput{
			Title:   "Scanning for vulnerabilities...",
			Summary: "SentryGrep is running Semgrep against this PR's code.",
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("encoding check run body: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("building check run request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+installToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("creating check run: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("unexpected status %d creating check run: %s", resp.StatusCode, respBody)
	}

	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return 0, fmt.Errorf("decoding check run response: %w", err)
	}

	return created.ID, nil
}

// completeCheckRun updates an existing Check Run to "completed" with a
// pass/fail conclusion derived from the scan report.
func CompleteCheckRun(installToken, owner, repo string, checkRunID int64, report *sandbox.ScanReport) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/check-runs/%d", owner, repo, checkRunID)

	conclusion := "success"
	title := "No issues found"
	if report.TotalFindings > 0 {
		if report.BySeverity["ERROR"] > 0 {
			conclusion = "failure"
		} else {
			conclusion = "neutral"
		}
		title = fmt.Sprintf("%d finding(s)", report.TotalFindings)
	}

	body := checkRunBody{
		Name:       "SentryGrep Security Scan",
		Status:     "completed",
		Conclusion: conclusion,
		Output: checkRunOutput{
			Title:   title,
			Summary: FormatReportAsComment(report),
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encoding check run update: %w", err)
	}

	req, err := http.NewRequest("PATCH", url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building check run update request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+installToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("updating check run: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d updating check run: %s", resp.StatusCode, respBody)
	}

	return nil
}
