package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cOmrade3267/authgraph/internal/report"
)

const dockerImage = "sentrygrep-scanner"
const scanTimeout = 3 * time.Minute

func RunDockerScan(targetDir string) (*report.ScanReport, error) {
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

	var reportData report.ScanReport
	if err := json.Unmarshal(reportBytes, &reportData); err != nil {
		return nil, fmt.Errorf("parsing report.json: %w", err)
	}

	enrichFindings(targetDir, &reportData)

	return &reportData, nil
}

func enrichFindings(targetDir string, reportData *report.ScanReport) {
	for i := range reportData.Findings {
		f := &reportData.Findings[i]

		relPath := strings.TrimPrefix(f.Location.File, "/target/")
		hostPath := filepath.Join(targetDir, relPath)

		funcName := findEnclosingFunction(hostPath, f.Location.Line)

		var hashInput string
		if funcName != "" {
			f.Location.Function = &funcName
			hashInput = fmt.Sprintf("%s|%s|%s", f.RuleID, f.Location.File, funcName)
		} else {
			log.Printf("WARNING: Could not resolve enclosing function for finding in %s:%d. Falling back to line-based finding_id hash.", f.Location.File, f.Location.Line)
			hashInput = fmt.Sprintf("%s|%s|%d", f.RuleID, f.Location.File, f.Location.Line)
		}

		hash := sha256.Sum256([]byte(hashInput))
		f.FindingID = hex.EncodeToString(hash[:])[:16]
	}
}

func findEnclosingFunction(filepath string, line int) string {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filepath, nil, 0)
	if err != nil {
		return ""
	}
	var funcName string
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		if fd, ok := n.(*ast.FuncDecl); ok {
			startLine := fset.Position(fd.Pos()).Line
			endLine := fset.Position(fd.End()).Line
			if line >= startLine && line <= endLine {
				funcName = fd.Name.Name
				return false
			}
		}
		return true
	})
	return funcName
}

func isExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}
