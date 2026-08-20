package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const dockerImage = "sentrygrep-scanner"
const scanTimeout = 3 * time.Minute

type Finding struct {
	RuleID     string `json:"rule_id"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Col        int    `json:"col"`
	EndLine    int    `json:"end_line"`
	Severity   string `json:"severity"`
	CWE        string `json:"cwe"`
	Message    string `json:"message"`
	Snippet    string `json:"snippet"`
	Confidence string `json:"confidence"`
}

type ScanReport struct {
	ScanTimestamp string         `json:"scan_timestamp"`
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCWE         map[string]int `json:"by_cwe"`
	Findings      []Finding      `json:"findings"`
}

func runDockerScan(targetDir string) (*ScanReport, error) {
	outputDir, err := os.MkdirTemp("", "sentrygrep-output-*")
	if err != nil {
		return nil, fmt.Errorf("creating output temp dir: %w", err)
	}
	defer os.RemoveAll(outputDir)

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	reportPath := filepath.Join(outputDir, "report.json")

	cmd := exec.CommandContext(ctx, "docker", "run",
    "--rm",
    "-v", targetDir+":/target:ro,z",
    "-v", outputDir+":/output:z",
    dockerImage,
    "--target", "/target",
    "--output", "/output/report.json",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if !isExitError(err, &exitErr) {
			return nil, fmt.Errorf("running docker scan: %w\noutput: %s", err, output)
		}
		if exitErr.ExitCode() >= 2 {
			return nil, fmt.Errorf("scanner exited with error code %d\noutput: %s",
				exitErr.ExitCode(), output)
		}
	}

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("scan timed out after %s", scanTimeout)
	}

	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("reading report.json: %w", err)
	}

	var report ScanReport
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		return nil, fmt.Errorf("parsing report.json: %w", err)
	}

	return &report, nil
}

func isExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}
