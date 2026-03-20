package export

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

var csvHeaders = []string{
	"Fingerprint SHA256",
	"Subject CN",
	"Subject Organization",
	"Subject Full DN",
	"Issuer CN",
	"Issuer Organization",
	"Issuer Full DN",
	"Serial Number",
	"Not Before",
	"Not After",
	"Key Algorithm",
	"Key Size Bits",
	"Signature Algorithm",
	"Subject Alt Names",
	"Is CA",
	"Discovery Source",
	"First Seen",
	"Last Seen",
}

// WriteCSV writes certificates as CSV rows to the given writer.
// Dates are formatted as RFC 3339, SANs are joined with "; ".
func WriteCSV(w io.Writer, certs []*model.Certificate) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write(csvHeaders); err != nil {
		return err
	}

	for _, c := range certs {
		isCA := "false"
		if c.IsCA {
			isCA = "true"
		}

		row := []string{
			c.FingerprintSHA256,
			c.Subject.CommonName,
			c.Subject.Organization,
			c.Subject.Full,
			c.Issuer.CommonName,
			c.Issuer.Organization,
			c.Issuer.Full,
			c.SerialNumber,
			c.NotBefore.Format("2006-01-02T15:04:05Z07:00"),
			c.NotAfter.Format("2006-01-02T15:04:05Z07:00"),
			string(c.KeyAlgorithm),
			strconv.Itoa(c.KeySizeBits),
			string(c.SignatureAlgorithm),
			strings.Join(c.SubjectAltNames, "; "),
			isCA,
			string(c.SourceDiscovery),
			c.FirstSeen.Format("2006-01-02T15:04:05Z07:00"),
			c.LastSeen.Format("2006-01-02T15:04:05Z07:00"),
		}

		if err := cw.Write(row); err != nil {
			return err
		}
	}

	return cw.Error()
}
