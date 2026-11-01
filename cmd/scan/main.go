package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cOmrade3267/authgraph/internal/sandbox"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <directory>\n", os.Args[0])
		os.Exit(2)
	}

	targetDir, err := filepath.Abs(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: resolving absolute path: %v\n", err)
		os.Exit(2)
	}

	report, err := sandbox.RunDockerScan(targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: running scan: %v\n", err)
		os.Exit(2)
	}

	for _, f := range report.Findings {
		fn := "-"
		if f.Location.Function != nil && *f.Location.Function != "" {
			fn = *f.Location.Function
		}
		fmt.Printf("%s %s %s:%d fn=%s id=%s\n",
			f.Severity,
			f.CWE,
			f.Location.File,
			f.Location.Line,
			fn,
			f.FindingID,
		)
		for _, ref := range f.References {
			fmt.Printf("  %s\n", ref)
		}
	}

	if len(report.Findings) > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}
