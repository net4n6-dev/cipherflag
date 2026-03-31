package export

import (
	"encoding/json"
	"io"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// ExportPayload is the top-level JSON envelope for certificate exports.
type ExportPayload struct {
	ExportedAt   time.Time            `json:"exported_at"`
	Count        int                  `json:"count"`
	Certificates []*model.Certificate `json:"certificates"`
}

// WriteJSON encodes certificates as indented JSON to the given writer.
func WriteJSON(w io.Writer, certs []*model.Certificate) error {
	payload := ExportPayload{
		ExportedAt:   time.Now().UTC(),
		Count:        len(certs),
		Certificates: certs,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
