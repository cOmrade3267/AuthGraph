package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func getWebhookSecret() string {
	return os.Getenv("GITHUB_WEBHOOK_SECRET")
}

func verifySignature(payloadBody []byte, signatureHeader string, secret string) bool {
	if signatureHeader == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payloadBody)
	expectedMAC := mac.Sum(nil)
	expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)
	return hmac.Equal([]byte(expectedSignature), []byte(signatureHeader))
}

// PullRequestEvent represents the subset of GitHub's pull_request webhook
// payload that we actually care about. GitHub sends MANY more fields —
// we only need to declare the ones we're going to use. Go's JSON decoder
// simply ignores fields in the JSON that aren't in our struct.
//
// NOTE: only one declaration of this struct should exist in the package.
// (An earlier draft had this declared twice — that's a compile error:
// "PullRequestEvent redeclared in this block".)
type PullRequestEvent struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Head struct {
			SHA string `json:"sha"` // the exact commit we need to scan
			Ref string `json:"ref"` // the branch name
		} `json:"head"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"` // e.g. "octocat/hello-world"
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

// shouldTriggerScan decides whether this specific action warrants running
// SentryGrep. We only care about NEW code appearing on a PR.
func shouldTriggerScan(action string) bool {
	return action == "opened" || action == "synchronize" || action == "reopened"
}

const privateKeyPath = "secrets/sentrygrepdev.2026-07-05.private-key.pem"

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	payloadBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	signatureHeader := r.Header.Get("X-Hub-Signature-256")
	secret := getWebhookSecret()

	if !verifySignature(payloadBody, signatureHeader, secret) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")

	// We only know how to handle pull_request events right now.
	if eventType != "pull_request" {
		log.Printf("Ignoring event type: %s", eventType)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status": "ignored", "reason": "not a pull_request event"}`)
		return
	}

	var event PullRequestEvent
	if err := json.Unmarshal(payloadBody, &event); err != nil {
		log.Printf("Failed to parse payload: %v", err)
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	log.Printf("PR event: repo=%s pr=#%d action=%s commit=%s",
		event.Repository.FullName, event.Number, event.Action, event.PullRequest.Head.SHA)

	if !shouldTriggerScan(event.Action) {
		log.Printf("Ignoring action: %s (not opened/synchronize/reopened)", event.Action)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status": "ignored", "reason": "action does not require scan"}`)
		return
	}

	// --- Auth chain: App JWT -> installation token ---
	appJWT, err := generateAppJWT(privateKeyPath)
	if err != nil {
		log.Printf("Failed to generate app JWT: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	installToken, err := getInstallationToken(appJWT, event.Installation.ID)
	if err != nil {
		log.Printf("Failed to get installation token: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("Got installation token (expires %s) for %s PR #%d",
		installToken.ExpiresAt, event.Repository.FullName, event.Number)

	// --- Fetch + extract PR code at head SHA ---
	tmpDir, err := os.MkdirTemp("", "sentrygrep-scan-*")
	if err != nil {
		log.Printf("Failed to create temp dir: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir) // always clean up, even on error paths below

	owner, repo := splitFullName(event.Repository.FullName)
	if owner == "" || repo == "" {
		log.Printf("Could not parse owner/repo from %s", event.Repository.FullName)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	tarballBody, err := fetchTarball(installToken.Token, owner, repo, event.PullRequest.Head.SHA)
	if err != nil {
		log.Printf("Failed to fetch tarball: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	defer tarballBody.Close()

	if err := extractTarball(tarballBody, tmpDir); err != nil {
		log.Printf("Failed to extract tarball: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	checkRunID, err := createCheckRun(installToken.Token, owner, repo, event.PullRequest.Head.SHA)
	if err != nil {
		log.Printf("Failed to create check run: %v", err)
	}

	report, err := runDockerScan(tmpDir)
	if err != nil {
		log.Printf("Scan failed for %s: %v", event.Repository.FullName, err)
		http.Error(w, fmt.Sprintf("Scan failed: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Scan complete: %d findings (by severity: %v)",
		report.TotalFindings, report.BySeverity)

	if checkRunID != 0 {
		if err := completeCheckRun(installToken.Token, owner, repo, checkRunID, report); err != nil {
			log.Printf("Failed to complete check run: %v", err)
		} else {
			log.Printf("Completed check run for %s PR #%d", event.Repository.FullName, event.Number)
		}
	}

	commentText := formatReportAsComment(report)
	if err := postPRComment(installToken.Token, owner, repo, event.Number, commentText); err != nil {
		log.Printf("Failed to post PR comment: %v", err)
	} else {
		log.Printf("Posted scan results to %s PR #%d", event.Repository.FullName, event.Number)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(report)
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, `{"status": "SentryGrep bot is running"}`)
}

func main() {
	http.HandleFunc("/webhook", webhookHandler)
	http.HandleFunc("/", healthCheckHandler)

	port := "16666"
	log.Printf("SentryGrep bot listening on port %s...", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}