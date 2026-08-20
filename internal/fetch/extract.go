package fetch

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractTarball unpacks a gzipped tar stream (as returned by GitHub's
// tarball endpoint) into destDir, stripping GitHub's wrapping top-level
// "owner-repo-abc1234/" directory.
func ExtractTarball(src io.Reader, destDir string) error {
	gzr, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}

		parts := strings.SplitN(header.Name, "/", 2)
		if len(parts) < 2 {
			continue
		}
		relPath := parts[1]
		if relPath == "" {
			continue
		}

		targetPath := filepath.Join(destDir, relPath)

		if !strings.HasPrefix(targetPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry escapes destination: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("creating dir %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("creating parent dir for %s: %w", targetPath, err)
			}
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return fmt.Errorf("creating file %s: %w", targetPath, err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("writing file %s: %w", targetPath, err)
			}
			outFile.Close()
		}
	}

	return nil
}

// SplitFullName splits GitHub's "owner/repo" format into its two parts.
func SplitFullName(fullName string) (owner, repo string) {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
