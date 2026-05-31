package venafi

import "context"

// VenafiClient is the interface for importing certificates into Venafi (Cloud or TPP).
type VenafiClient interface {
	// ImportCertificates imports a batch of certificates. Returns aggregate results.
	ImportCertificates(ctx context.Context, certs []CertImport) (*ImportResult, error)
	// ValidateConnection checks that credentials are valid.
	ValidateConnection(ctx context.Context) error
}

// CertImport holds a certificate and optional endpoint metadata for import.
type CertImport struct {
	PEM         string
	Fingerprint string
	ServerName  string
	ServerIP    string
	ServerPort  int
	TLSVersion  string
}

// ImportResult holds the outcome of a batch import operation.
type ImportResult struct {
	Imported int
	Updated  int
	Existed  int
	Failed   int
	Warnings []string
}
