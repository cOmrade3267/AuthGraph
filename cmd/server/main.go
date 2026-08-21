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

	"github.com/cOmrade3267/authgraph/internal/auth"
	"github.com/cOmrade3267/authgraph/internal/fetch"
	"github.com/cOmrade3267/authgraph/internal/ghapi"
	"github.com/cOmrade3267/authgraph/internal/sandbox"
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
// payload that we actually care about.
type PullRequestEvent struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Head struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

func shouldTriggerScan(action string) bool {
	return action == "opened" || action == "synchronize" || action == "reopened"
}

// TODO: update once AuthGraph's own GitHub App is registered (Phase 2) —
// this still points at SentryGrep's key. Do not run this against real
// webhook traffic until this path (and the App ID in internal/auth/auth.go)
// are updated to AuthGraph's own values.
const privateKeyPath = "secrets/authgraph-dev.2026-08-20.private-key.pem"

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
	appJWT, err := auth.GenerateAppJWT(privateKeyPath)
	if err != nil {
		log.Printf("Failed to generate app JWT: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	installToken, err := auth.GetInstallationToken(appJWT, event.Installation.ID)
	if err != nil {
		log.Printf("Failed to get installation token: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("Got installation token (expires %s) for %s PR #%d",
		installToken.ExpiresAt, event.Repository.FullName, event.Number)

	// --- Fetch + extract PR code at head SHA ---
	tmpDir, err := os.MkdirTemp("", "authgraph-scan-*")
	if err != nil {
		log.Printf("Failed to create temp dir: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir)

	owner, repo := fetch.SplitFullName(event.Repository.FullName)
	if owner == "" || repo == "" {
		log.Printf("Could not parse owner/repo from %s", event.Repository.FullName)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	tarballBody, err := fetch.FetchTarball(installToken.Token, owner, repo, event.PullRequest.Head.SHA)
	if err != nil {
		log.Printf("Failed to fetch tarball: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	defer tarballBody.Close()

	if err := fetch.ExtractTarball(tarballBody, tmpDir); err != nil {
		log.Printf("Failed to extract tarball: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	checkRunID, err := ghapi.CreateCheckRun(installToken.Token, owner, repo, event.PullRequest.Head.SHA)
	if err != nil {
		log.Printf("Failed to create check run: %v", err)
	}

	report, err := sandbox.RunDockerScan(tmpDir)
	if err != nil {
		log.Printf("Scan failed for %s: %v", event.Repository.FullName, err)
		http.Error(w, fmt.Sprintf("Scan failed: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Scan complete: %d findings (by severity: %v)",
		report.TotalFindings, report.BySeverity)

	if checkRunID != 0 {
		if err := ghapi.CompleteCheckRun(installToken.Token, owner, repo, checkRunID, report); err != nil {
			log.Printf("Failed to complete check run: %v", err)
		} else {
			log.Printf("Completed check run for %s PR #%d", event.Repository.FullName, event.Number)
		}
	}

	commentText := ghapi.FormatReportAsComment(report)
	if err := ghapi.PostPRComment(installToken.Token, owner, repo, event.Number, commentText); err != nil {
		log.Printf("Failed to post PR comment: %v", err)
	} else {
		log.Printf("Posted scan results to %s PR #%d", event.Repository.FullName, event.Number)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(report)
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, `{"status": "AuthGraph bot is running"}`)
}

func main() {
	http.HandleFunc("/webhook", webhookHandler)
	http.HandleFunc("/", healthCheckHandler)

	port := "16666"
	log.Printf("AuthGraph bot listening on port %s...", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
