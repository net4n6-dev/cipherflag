package venafi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

// Client is a Venafi TPP REST API client that handles OAuth token refresh
// and certificate import operations.
type Client struct {
	sdkBaseURL  string
	authBaseURL string
	clientID    string
	refreshTok  string

	httpClient *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

// NewClient creates a new Venafi TPP client.
func NewClient(sdkBaseURL, authBaseURL, clientID, refreshToken string) *Client {
	return &Client{
		sdkBaseURL:  sdkBaseURL,
		authBaseURL: authBaseURL,
		clientID:    clientID,
		refreshTok:  refreshToken,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

// importRequest is the body sent to the certificate import endpoint.
type importRequest struct {
	CertificateData string `json:"CertificateData"`
	PolicyDN        string `json:"PolicyDN"`
}

// ImportCertificate imports a certificate into Venafi TPP under the given policy folder.
func (c *Client) ImportCertificate(ctx context.Context, cert *model.Certificate, policyFolder string) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return fmt.Errorf("venafi: obtaining token: %w", err)
	}

	body := importRequest{
		CertificateData: cert.RawPEM,
		PolicyDN:        policyFolder,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("venafi: marshalling import request: %w", err)
	}

	url := c.sdkBaseURL + "/certificates/import"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("venafi: creating import request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("venafi: import request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("venafi: import returned status %d", resp.StatusCode)
	}

	return nil
}

// tokenResponse represents the OAuth token response from Venafi TPP.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expires      int64  `json:"expires"`
}

// getToken returns a valid access token, refreshing it if necessary.
func (c *Client) getToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid (with 60-second buffer).
	if c.accessToken != "" && time.Now().Before(c.expiresAt.Add(-60*time.Second)) {
		return c.accessToken, nil
	}

	body := map[string]string{
		"client_id":     c.clientID,
		"refresh_token": c.refreshTok,
		"grant_type":    "refresh_token",
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("venafi: marshalling token request: %w", err)
	}

	url := c.authBaseURL + "/authorize/oauth"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("venafi: creating token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("venafi: token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("venafi: token request returned status %d", resp.StatusCode)
	}

	var tokResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		return "", fmt.Errorf("venafi: decoding token response: %w", err)
	}

	c.accessToken = tokResp.AccessToken
	c.refreshTok = tokResp.RefreshToken
	c.expiresAt = time.Now().Add(time.Duration(tokResp.Expires) * time.Second)

	return c.accessToken, nil
}
