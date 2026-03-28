package venafi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CloudClient is a Venafi Cloud (TLS Protect Cloud) REST API client.
type CloudClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewCloudClient creates a new Venafi Cloud client.
// region should be "us" or "eu".
func NewCloudClient(region, apiKey string) *CloudClient {
	baseURL := "https://api.venafi.cloud"
	if strings.EqualFold(region, "eu") {
		baseURL = "https://api.venafi.eu"
	}
	return &CloudClient{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

type cloudImportRequest struct {
	Certificates []cloudCertEntry `json:"certificates"`
}

type cloudCertEntry struct {
	Certificate          string              `json:"certificate"`
	APIClientInformation *cloudAPIClientInfo `json:"apiClientInformation,omitempty"`
}

type cloudAPIClientInfo struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

type cloudImportResponse struct {
	CertificateInformations []cloudCertInfo `json:"certificateInformations"`
	Statistics              cloudStats      `json:"statistics"`
}

type cloudCertInfo struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
}

type cloudStats struct {
	Imported int `json:"imported"`
	Existed  int `json:"existed"`
	Ignored  int `json:"ignored"`
	Failed   int `json:"failed"`
}

// ImportCertificates imports a batch of certificates into Venafi Cloud.
func (c *CloudClient) ImportCertificates(ctx context.Context, certs []CertImport) (*ImportResult, error) {
	entries := make([]cloudCertEntry, 0, len(certs))
	for _, cert := range certs {
		pemClean := stripPEMHeaders(cert.PEM)
		entry := cloudCertEntry{
			Certificate: pemClean,
		}
		if cert.ServerIP != "" || cert.ServerName != "" {
			identifier := cert.ServerName
			if identifier == "" {
				identifier = cert.ServerIP
			}
			entry.APIClientInformation = &cloudAPIClientInfo{
				Type:       "CipherFlag",
				Identifier: identifier,
			}
		}
		entries = append(entries, entry)
	}

	reqBody := cloudImportRequest{Certificates: entries}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("venafi cloud: marshalling import request: %w", err)
	}

	url := c.baseURL + "/outagedetection/v1/certificates"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("venafi cloud: creating import request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("tppl-api-key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("venafi cloud: import request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("venafi cloud: invalid API key (401 Unauthorized)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("venafi cloud: import returned status %d", resp.StatusCode)
	}

	var cloudResp cloudImportResponse
	if err := json.NewDecoder(resp.Body).Decode(&cloudResp); err != nil {
		return nil, fmt.Errorf("venafi cloud: decoding import response: %w", err)
	}

	return &ImportResult{
		Imported: cloudResp.Statistics.Imported,
		Existed:  cloudResp.Statistics.Existed,
		Failed:   cloudResp.Statistics.Failed,
	}, nil
}

// ValidateConnection checks that the API key is valid by making a lightweight API call.
func (c *CloudClient) ValidateConnection(ctx context.Context) error {
	url := c.baseURL + "/outagedetection/v1/certificates?limit=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("venafi cloud: creating validation request: %w", err)
	}

	req.Header.Set("tppl-api-key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("venafi cloud: connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("venafi cloud: invalid API key")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("venafi cloud: validation returned status %d", resp.StatusCode)
	}

	return nil
}

// stripPEMHeaders removes PEM header/footer lines and newlines,
// returning just the base64-encoded certificate data.
func stripPEMHeaders(pem string) string {
	lines := strings.Split(pem, "\n")
	var b64Lines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		b64Lines = append(b64Lines, line)
	}
	result := strings.Join(b64Lines, "")
	if _, err := base64.StdEncoding.DecodeString(result); err != nil {
		return base64.StdEncoding.EncodeToString([]byte(pem))
	}
	return result
}
