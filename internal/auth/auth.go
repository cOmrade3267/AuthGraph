package auth

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GitHub Apps authenticate using a JWT (JSON Web Token) signed with the
// app's private key. GitHub verifies this JWT using the PUBLIC key it
// already has on file for your app — this proves the request genuinely
// comes from you, without ever sending your private key over the network.

const githubAppID = "4668574" // AuthGraph's App ID — update if you registered a new App

// loadPrivateKey reads the .pem file and parses it into an RSA private key
// object that the JWT library can use to sign tokens.
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing RSA key: %w", err)
	}

	return key, nil
}

// GenerateAppJWT creates a short-lived JWT that identifies THIS APP
// (not any specific installation) to GitHub's API. Used for exactly one
// purpose: exchanging it for an installation-specific access token.
func GenerateAppJWT(privateKeyPath string) (string, error) {
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return "", err
	}

	now := time.Now()

	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
		Issuer:    githubAppID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	return signedToken, nil
}

// InstallationTokenResponse is GitHub's response body from the
// installation access token exchange endpoint.
type InstallationTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetInstallationToken exchanges the App JWT for a token scoped to a
// specific installation.
func GetInstallationToken(appJWT string, installationID int64) (*InstallationTokenResponse, error) {
	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}

	var tokenResp InstallationTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &tokenResp, nil
}
