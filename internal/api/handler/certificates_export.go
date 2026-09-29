// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handler

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// exportPageSize is how many certificates one page of an export asks the
// store for. SearchCertificates caps a page at 500 and turns anything larger
// into 50, so this is that cap. A variable so tests can lower it.
var exportPageSize = 500

// exportWriteWindow is how long the server may take to write each page. The
// server's own WriteTimeout runs from the request headers, so a long export
// would be cut off; the deadline is pushed out before every page instead.
const exportWriteWindow = 30 * time.Second

var exportColumns = []string{
	"fingerprint_sha256", "subject_cn", "subject_org", "issuer_cn", "issuer_org",
	"serial_number", "not_before", "not_after", "days_until_expiry",
	"key_algorithm", "key_size_bits", "signature_algorithm", "subject_alt_names",
	"is_ca", "grade", "source", "first_seen", "last_seen",
}

// certExportRow is one certificate as exported, in CSV column order.
type certExportRow struct {
	FingerprintSHA256  string   `json:"fingerprint_sha256"`
	SubjectCN          string   `json:"subject_cn"`
	SubjectOrg         string   `json:"subject_org"`
	IssuerCN           string   `json:"issuer_cn"`
	IssuerOrg          string   `json:"issuer_org"`
	SerialNumber       string   `json:"serial_number"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	DaysUntilExpiry    int      `json:"days_until_expiry"`
	KeyAlgorithm       string   `json:"key_algorithm"`
	KeySizeBits        int      `json:"key_size_bits"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	SubjectAltNames    []string `json:"subject_alt_names"`
	IsCA               bool     `json:"is_ca"`
	Grade              string   `json:"grade"`
	Source             string   `json:"source"`
	FirstSeen          string   `json:"first_seen"`
	LastSeen           string   `json:"last_seen"`
}

func newCertExportRow(c *model.Certificate, grade string) certExportRow {
	sans := c.SubjectAltNames
	if sans == nil {
		sans = []string{}
	}
	return certExportRow{
		FingerprintSHA256:  c.FingerprintSHA256,
		SubjectCN:          c.Subject.CommonName,
		SubjectOrg:         c.Subject.Organization,
		IssuerCN:           c.Issuer.CommonName,
		IssuerOrg:          c.Issuer.Organization,
		SerialNumber:       c.SerialNumber,
		NotBefore:          c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           c.NotAfter.UTC().Format(time.RFC3339),
		DaysUntilExpiry:    c.DaysUntilExpiry(),
		KeyAlgorithm:       string(c.KeyAlgorithm),
		KeySizeBits:        c.KeySizeBits,
		SignatureAlgorithm: string(c.SignatureAlgorithm),
		SubjectAltNames:    sans,
		IsCA:               c.IsCA,
		Grade:              grade,
		Source:             string(c.SourceDiscovery),
		FirstSeen:          c.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:           c.LastSeen.UTC().Format(time.RFC3339),
	}
}

// csvCell neutralizes a value a spreadsheet would run as a formula: a cell
// that starts with = + - @ tab or carriage return gets a leading quote.
func csvCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// joinSANs neutralizes each name on its own before joining with ;, because a
// spreadsheet in a ; locale splits the cell and would run a later name.
func joinSANs(sans []string) string {
	safe := make([]string, len(sans))
	for i, s := range sans {
		safe[i] = csvCell(s)
	}
	return strings.Join(safe, ";")
}

func (r certExportRow) csvRecord() []string {
	return []string{
		csvCell(r.FingerprintSHA256), csvCell(r.SubjectCN), csvCell(r.SubjectOrg),
		csvCell(r.IssuerCN), csvCell(r.IssuerOrg), csvCell(r.SerialNumber),
		r.NotBefore, r.NotAfter, strconv.Itoa(r.DaysUntilExpiry),
		csvCell(r.KeyAlgorithm), strconv.Itoa(r.KeySizeBits), csvCell(r.SignatureAlgorithm),
		joinSANs(r.SubjectAltNames),
		strconv.FormatBool(r.IsCA), csvCell(r.Grade), csvCell(r.Source),
		r.FirstSeen, r.LastSeen,
	}
}

// Export streams every certificate matching the list filters as CSV (the
// default) or JSON. It walks the store a page at a time so memory stays flat.
// page and page_size in the request are ignored. Once the first page has been
// written a later failure cannot change the status, so the failure is logged
// and the connection is aborted (http.ErrAbortHandler): the client sees a
// failed transfer, not a short file that looks complete.
func (h *CertHandler) Export(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		writeError(w, http.StatusBadRequest, "format must be csv or json")
		return
	}

	q := certSearchQueryFromRequest(r)
	q.Page = 1
	q.PageSize = exportPageSize

	rc := http.NewResponseController(w)
	extendDeadline := func() {
		// A writer without deadline support (a test recorder) returns
		// http.ErrNotSupported, which is fine to ignore.
		_ = rc.SetWriteDeadline(time.Now().Add(exportWriteWindow))
	}

	// Fetch the first page before writing anything so a failure is a clean 500.
	extendDeadline()
	res, err := h.store.SearchCertificates(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Content-Disposition", `attachment; filename="certificates.`+format+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}

	cw := csv.NewWriter(w)
	if format == "csv" {
		_ = cw.Write(exportColumns)
	} else {
		_, _ = w.Write([]byte("["))
	}

	written := 0
	for {
		for i := range res.Certificates {
			row := newCertExportRow(&res.Certificates[i], res.Grades[res.Certificates[i].FingerprintSHA256])
			if format == "csv" {
				_ = cw.Write(row.csvRecord())
			} else {
				b, err := json.Marshal(row)
				if err != nil {
					log.Error().Err(err).Msg("certificate export failed part way")
					panic(http.ErrAbortHandler)
				}
				if written > 0 {
					_, _ = w.Write([]byte(","))
				}
				_, _ = w.Write(b)
			}
			written++
		}
		if format == "csv" {
			cw.Flush()
		}
		flush()

		pageSize := exportPageSize
		if res.PageSize > 0 {
			pageSize = res.PageSize
		}
		if len(res.Certificates) < pageSize || r.Context().Err() != nil {
			break
		}
		q.Page++
		extendDeadline()
		res, err = h.store.SearchCertificates(r.Context(), q)
		if err != nil {
			if r.Context().Err() != nil {
				// The client went away, so the store gave up with a canceled
				// context. Nothing is left to abort and nothing failed.
				log.Debug().Err(err).Int("page", q.Page).Msg("certificate export stopped, client went away")
				return
			}
			log.Error().Err(err).Int("page", q.Page).Int("written", written).
				Msg("certificate export failed part way")
			// Drop the connection without the terminating chunk so the client
			// sees a failed download, not a short file that looks complete.
			panic(http.ErrAbortHandler)
		}
	}

	if r.Context().Err() != nil {
		return
	}
	if format == "json" {
		_, _ = w.Write([]byte("]\n"))
	}
	flush()
}
