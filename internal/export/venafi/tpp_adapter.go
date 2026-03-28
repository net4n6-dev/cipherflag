package venafi

import (
	"context"
	"encoding/base64"
	"fmt"
)

// TPPAdapter wraps the existing TPP Client to implement VenafiClient.
type TPPAdapter struct {
	client *Client
	folder string
}

// NewTPPAdapter creates a VenafiClient adapter for TPP.
func NewTPPAdapter(client *Client, folder string) *TPPAdapter {
	return &TPPAdapter{client: client, folder: folder}
}

// ImportCertificates imports certificates into TPP via the Discovery/Import endpoint.
func (a *TPPAdapter) ImportCertificates(ctx context.Context, certs []CertImport) (*ImportResult, error) {
	request := &DiscoveryImportRequest{
		ZoneName:  a.folder,
		Endpoints: make([]DiscoveryEndpoint, 0, len(certs)),
	}

	for _, cert := range certs {
		encoded := base64.StdEncoding.EncodeToString([]byte(cert.PEM))

		endpoint := DiscoveryEndpoint{
			Certificates: []DiscoveryCert{
				{
					Certificate: encoded,
					Fingerprint: cert.Fingerprint,
				},
			},
		}

		if cert.ServerIP != "" || cert.ServerName != "" {
			endpoint.Host = cert.ServerName
			if endpoint.Host == "" {
				endpoint.Host = cert.ServerIP
			}
			endpoint.IP = cert.ServerIP
			endpoint.Port = cert.ServerPort
			if cert.TLSVersion != "" {
				endpoint.Protocols = []DiscoveryProto{
					{
						Certificates: []string{cert.Fingerprint},
						Protocol:     cert.TLSVersion,
					},
				}
			}
		}

		request.Endpoints = append(request.Endpoints, endpoint)
	}

	resp, err := a.client.ImportDiscovery(ctx, request)
	if err != nil {
		return nil, err
	}

	return &ImportResult{
		Imported: resp.CreatedCertificates,
		Updated:  resp.UpdatedCertificates,
		Warnings: resp.Warnings,
	}, nil
}

// ValidateConnection checks that TPP credentials are valid by attempting a token refresh.
func (a *TPPAdapter) ValidateConnection(ctx context.Context) error {
	_, err := a.client.getToken(ctx)
	if err != nil {
		return fmt.Errorf("venafi tpp: %w", err)
	}
	return nil
}
