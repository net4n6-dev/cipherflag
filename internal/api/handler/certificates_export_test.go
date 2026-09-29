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
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

const wantExportHeader = "fingerprint_sha256,subject_cn,subject_org,issuer_cn,issuer_org,serial_number,not_before,not_after,days_until_expiry,key_algorithm,key_size_bits,signature_algorithm,subject_alt_names,is_ca,grade,source,first_seen,last_seen"

// fakeExportStore serves a slice of certificates by page and records the
// queries it saw.
type fakeExportStore struct {
	store.CertStore
	certs  []model.Certificate
	grades map[string]string

	queries   []store.CertSearchQuery
	failOn    int // page number that returns an error, 0 for none
	cancelOn  int // page number whose fetch cancels the request context and fails with context.Canceled
	cancel    context.CancelFunc
	delay     time.Duration
	serveSize int         // when > 0 the store serves and reports this page size instead of the requested one
	onPage    func(p int) // called after a page is served
	pages     []int
}

func (f *fakeExportStore) SearchCertificates(_ context.Context, q store.CertSearchQuery) (*store.CertSearchResult, error) {
	f.queries = append(f.queries, q)
	f.pages = append(f.pages, q.Page)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.serveSize > 0 {
		q.PageSize = f.serveSize
	}
	if f.cancelOn != 0 && q.Page == f.cancelOn {
		f.cancel()
		return nil, context.Canceled
	}
	if f.failOn != 0 && q.Page == f.failOn {
		return nil, errors.New("boom")
	}
	start := (q.Page - 1) * q.PageSize
	end := start + q.PageSize
	if start > len(f.certs) {
		start = len(f.certs)
	}
	if end > len(f.certs) {
		end = len(f.certs)
	}
	res := &store.CertSearchResult{
		Certificates: f.certs[start:end], Grades: f.grades,
		Total: len(f.certs), Page: q.Page, PageSize: q.PageSize,
	}
	if f.onPage != nil {
		f.onPage(q.Page)
	}
	return res, nil
}

func exportCert(fp, cn string) model.Certificate {
	return model.Certificate{
		FingerprintSHA256:  fp,
		Subject:            model.DistinguishedName{CommonName: cn, Organization: "Acme"},
		Issuer:             model.DistinguishedName{CommonName: "Acme CA", Organization: "Acme Inc"},
		SerialNumber:       "0A1B",
		NotBefore:          time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:           time.Now().UTC().Add(100 * 24 * time.Hour).Truncate(time.Second),
		KeyAlgorithm:       "RSA",
		KeySizeBits:        2048,
		SignatureAlgorithm: "SHA256-RSA",
		SubjectAltNames:    []string{"a.test", "b.test"},
		IsCA:               true,
		SourceDiscovery:    "zeek",
		FirstSeen:          time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:           time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	}
}

func doExport(t *testing.T, st store.CertStore, target string) *httptest.ResponseRecorder {
	t.Helper()
	return doExportReq(st, httptest.NewRequest(http.MethodGet, target, nil))
}

func doExportReq(st store.CertStore, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	NewCertHandler(st).Export(rec, req)
	return rec
}

func setExportPageSize(t *testing.T, n int) {
	t.Helper()
	old := exportPageSize
	exportPageSize = n
	t.Cleanup(func() { exportPageSize = old })
}

func TestExport_CSVIsTheDefault(t *testing.T) {
	c := exportCert("fp1", "one.test")
	st := &fakeExportStore{certs: []model.Certificate{c, exportCert("fp2", "two.test")}, grades: map[string]string{"fp1": "B"}}
	rec := doExport(t, st, "/api/v1/export/certificates")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="certificates.csv"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	recs, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("records = %d, want 3", len(recs))
	}
	if got := strings.Join(recs[0], ","); got != wantExportHeader {
		t.Errorf("header = %q", got)
	}
	row := recs[1]
	days, err := strconv.Atoi(row[8])
	if err != nil || days < 98 || days > 100 {
		t.Errorf("days_until_expiry = %q", row[8])
	}
	row[8] = "N"
	want := []string{"fp1", "one.test", "Acme", "Acme CA", "Acme Inc", "0A1B",
		"2026-01-02T03:04:05Z", c.NotAfter.Format(time.RFC3339), "N", "RSA", "2048", "SHA256-RSA",
		"a.test;b.test", "true", "B", "zeek", "2026-02-01T00:00:00Z", "2026-03-01T00:00:00Z"}
	if strings.Join(row, "|") != strings.Join(want, "|") {
		t.Errorf("row = %q\nwant  %q", row, want)
	}
	if recs[2][14] != "" {
		t.Errorf("grade for an ungraded cert = %q, want empty", recs[2][14])
	}
}

func TestExport_JSONIsAnArrayOfTheSameFields(t *testing.T) {
	st := &fakeExportStore{certs: []model.Certificate{exportCert("fp1", "one.test")}, grades: map[string]string{"fp1": "A"}}
	rec := doExport(t, st, "/api/v1/export/certificates?format=json")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="certificates.json"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not a JSON array: %v\n%s", err, rec.Body.String())
	}
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	o := out[0]
	if len(o) != 18 {
		t.Errorf("fields = %d, want 18: %v", len(o), o)
	}
	for _, k := range strings.Split(wantExportHeader, ",") {
		if _, ok := o[k]; !ok {
			t.Errorf("missing field %q", k)
		}
	}
	if sans, ok := o["subject_alt_names"].([]any); !ok || len(sans) != 2 {
		t.Errorf("subject_alt_names = %#v", o["subject_alt_names"])
	}
	if n, ok := o["key_size_bits"].(float64); !ok || n != 2048 {
		t.Errorf("key_size_bits = %#v", o["key_size_bits"])
	}
	if b, ok := o["is_ca"].(bool); !ok || !b {
		t.Errorf("is_ca = %#v", o["is_ca"])
	}
	if o["grade"] != "A" || o["subject_cn"] != "one.test" {
		t.Errorf("grade/subject_cn = %v/%v", o["grade"], o["subject_cn"])
	}

	empty := doExport(t, &fakeExportStore{}, "/api/v1/export/certificates?format=json")
	if strings.TrimSpace(empty.Body.String()) != "[]" {
		t.Errorf("empty export = %q, want []", empty.Body.String())
	}
}

func TestExport_UnknownFormatIs400(t *testing.T) {
	rec := doExport(t, &fakeExportStore{}, "/api/v1/export/certificates?format=xml")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestExport_PassesTheListFilters(t *testing.T) {
	st := &fakeExportStore{}
	target := "/api/v1/export/certificates?search=a&grade=D,F&source=zeek&issuer_cn=X&key_algorithm=RSA" +
		"&is_ca=true&expired=true&expiring_within_days=30&sort_by=cn&sort_dir=desc&page=7&page_size=3"
	doExport(t, st, target)

	if len(st.queries) != 1 {
		t.Fatalf("store calls = %d", len(st.queries))
	}
	got := st.queries[0]
	if got.Page != 1 || got.PageSize != exportPageSize {
		t.Errorf("page/size = %d/%d, want 1/%d", got.Page, got.PageSize, exportPageSize)
	}
	if got.Search != "a" || got.Grade != "D,F" || got.Source != "zeek" || got.IssuerCN != "X" ||
		got.KeyAlgorithm != "RSA" || got.SortBy != "cn" || got.SortDir != "desc" {
		t.Errorf("query = %+v", got)
	}
	if got.IsCA == nil || !*got.IsCA || got.Expired == nil || !*got.Expired ||
		got.ExpiringWithinDays == nil || *got.ExpiringWithinDays != 30 {
		t.Errorf("pointer filters = %+v", got)
	}
}

func TestExport_WalksEveryPage(t *testing.T) {
	setExportPageSize(t, 2)
	var certs []model.Certificate
	for i := 1; i <= 5; i++ {
		certs = append(certs, exportCert(fmt.Sprintf("fp%d", i), fmt.Sprintf("c%d.test", i)))
	}
	st := &fakeExportStore{certs: certs}
	rec := doExport(t, st, "/api/v1/export/certificates")

	recs, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 6 {
		t.Fatalf("records = %d, want header + 5", len(recs))
	}
	for i := 1; i <= 5; i++ {
		if recs[i][0] != fmt.Sprintf("fp%d", i) {
			t.Errorf("record %d = %q", i, recs[i][0])
		}
	}
	if fmt.Sprint(st.pages) != "[1 2 3]" {
		t.Errorf("pages = %v, want [1 2 3]", st.pages)
	}
}

func TestExport_StopsOnAnEmptyPage(t *testing.T) {
	setExportPageSize(t, 2)
	st := &fakeExportStore{certs: []model.Certificate{exportCert("fp1", "a"), exportCert("fp2", "b")}}
	rec := doExport(t, st, "/api/v1/export/certificates?format=json")

	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 2 {
		t.Fatalf("body = %q (%v)", rec.Body.String(), err)
	}
	if fmt.Sprint(st.pages) != "[1 2]" {
		t.Errorf("pages = %v, want [1 2]", st.pages)
	}
}

func TestExport_CSVCellsCannotBecomeFormulas(t *testing.T) {
	names := []string{`=HYPERLINK("http://example.invalid","x")`, "+1", "-1", "@SUM(1)", "\tsneaky", "\rsneaky", "plain.test"}
	var certs []model.Certificate
	for i, n := range names {
		c := exportCert(fmt.Sprintf("fp%d", i), n)
		c.Subject.Organization = n
		c.Issuer.CommonName = n
		c.SubjectAltNames = []string{"a.test", n}
		certs = append(certs, c)
	}
	st := &fakeExportStore{certs: certs}

	recs, err := csv.NewReader(doExport(t, st, "/api/v1/export/certificates").Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	last := len(names) - 1
	for i, n := range names {
		want := n
		if i < last {
			want = "'" + n
		}
		// subject_cn, subject_org, issuer_cn
		for _, col := range []int{1, 2, 3} {
			if got := recs[i+1][col]; got != want {
				t.Errorf("column %s: %q exported as %q, want %q", exportColumns[col], n, got, want)
			}
		}
		// Every SAN is neutralized on its own, so a spreadsheet that splits on
		// ; (some locales) still sees a quoted cell.
		wantSANs := "a.test;" + want
		if got := recs[i+1][12]; got != wantSANs {
			t.Errorf("subject_alt_names for %q = %q, want %q", n, got, wantSANs)
		}
	}
	if got := recs[1][12]; !strings.Contains(got, ";'=HYPERLINK") {
		t.Errorf("SAN cell = %q, want it to contain ;'=HYPERLINK", got)
	}
	if recs[last+1][4] != "Acme Inc" {
		t.Errorf("ordinary cell changed: %q", recs[last+1][4])
	}

	var out []map[string]any
	if err := json.Unmarshal(doExport(t, st, "/api/v1/export/certificates?format=json").Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for i, n := range names {
		if out[i]["subject_cn"] != n {
			t.Errorf("json subject_cn %q altered to %q", n, out[i]["subject_cn"])
		}
		if sans := out[i]["subject_alt_names"].([]any); sans[1] != n {
			t.Errorf("json SAN %q altered to %q", n, sans[1])
		}
	}
}

// exportPageSize must not exceed what SearchCertificates honors: it silently
// turns a larger page into 50, which would make every page look short.
func TestExport_PageSizeIsWithinTheStoreCap(t *testing.T) {
	if exportPageSize > 500 {
		t.Fatalf("exportPageSize = %d, SearchCertificates caps a page at 500 and turns larger into 50", exportPageSize)
	}
}

// The walk ends on a short page measured against the size the store actually
// used, not the size that was asked for.
func TestExport_UsesThePageSizeTheStoreReports(t *testing.T) {
	setExportPageSize(t, 5)
	var certs []model.Certificate
	for i := 1; i <= 5; i++ {
		certs = append(certs, exportCert(fmt.Sprintf("fp%d", i), "c.test"))
	}
	st := &fakeExportStore{certs: certs, serveSize: 2}
	recs, err := csv.NewReader(doExport(t, st, "/api/v1/export/certificates").Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 6 {
		t.Fatalf("records = %d, want header + 5 (pages seen %v)", len(recs), st.pages)
	}
}

// doExportAbort runs Export directly and returns what it panicked with.
func doExportAbort(st store.CertStore, target string) (rec *httptest.ResponseRecorder, recovered any) {
	rec = httptest.NewRecorder()
	defer func() { recovered = recover() }()
	NewCertHandler(st).Export(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec, nil
}

// captureLog swaps the global zerolog logger for one writing to buf.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = old })
	return &buf
}

func TestExport_AFailureAfterTheFirstPageDoesNotLookComplete(t *testing.T) {
	setExportPageSize(t, 2)
	var certs []model.Certificate
	for i := 1; i <= 5; i++ {
		certs = append(certs, exportCert(fmt.Sprintf("fp%d", i), fmt.Sprintf("c%d.test", i)))
	}

	t.Run("csv", func(t *testing.T) {
		buf := captureLog(t)
		st := &fakeExportStore{certs: certs, failOn: 2}
		rec, recovered := doExportAbort(st, "/api/v1/export/certificates")
		if recovered != http.ErrAbortHandler {
			t.Fatalf("recovered = %v, want http.ErrAbortHandler so the connection is dropped", recovered)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		recs, err := csv.NewReader(rec.Body).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) != 3 || recs[2][0] != "fp2" {
			t.Errorf("records = %d, want header + page 1 only: %q", len(recs), recs)
		}
		if fmt.Sprint(st.pages) != "[1 2]" {
			t.Errorf("pages = %v", st.pages)
		}
		if !strings.Contains(buf.String(), "certificate export failed part way") || !strings.Contains(buf.String(), "boom") {
			t.Errorf("failure not logged: %q", buf.String())
		}
	})

	t.Run("json", func(t *testing.T) {
		buf := captureLog(t)
		st := &fakeExportStore{certs: certs, failOn: 2}
		rec, recovered := doExportAbort(st, "/api/v1/export/certificates?format=json")
		if recovered != http.ErrAbortHandler {
			t.Fatalf("recovered = %v, want http.ErrAbortHandler", recovered)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		body := strings.TrimSpace(rec.Body.String())
		if strings.HasSuffix(body, "]") {
			t.Errorf("truncated JSON export ends with ]: %q", body)
		}
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err == nil {
			t.Errorf("truncated JSON export parsed cleanly")
		}
		if !strings.Contains(buf.String(), "certificate export failed part way") {
			t.Errorf("failure not logged: %q", buf.String())
		}
	})

	t.Run("first page is a clean 500", func(t *testing.T) {
		st := &fakeExportStore{certs: certs, failOn: 1}
		rec := doExport(t, st, "/api/v1/export/certificates")
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", rec.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" {
			t.Errorf("body = %q", rec.Body.String())
		}
		if cd := rec.Header().Get("Content-Disposition"); cd != "" {
			t.Errorf("error response carries Content-Disposition %q", cd)
		}
	})
}

func TestExport_StopsWhenTheClientGoesAway(t *testing.T) {
	setExportPageSize(t, 2)
	var certs []model.Certificate
	for i := 1; i <= 6; i++ {
		certs = append(certs, exportCert(fmt.Sprintf("fp%d", i), "c.test"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &fakeExportStore{certs: certs, onPage: func(p int) {
		if p == 1 {
			cancel()
		}
	}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/certificates", nil).WithContext(ctx)
	doExportReq(st, req)

	if fmt.Sprint(st.pages) != "[1]" {
		t.Errorf("pages = %v, want [1]: the walk must stop once the client is gone", st.pages)
	}
}

func certsN(n int) []model.Certificate {
	var certs []model.Certificate
	for i := 1; i <= n; i++ {
		certs = append(certs, exportCert(fmt.Sprintf("fp%d", i), "c.test"))
	}
	return certs
}

// Through a real server, a failure after the first page must reach the client
// as a broken transfer, not as a body that ends cleanly.
func TestExport_AMidWalkFailureBreaksTheTransfer(t *testing.T) {
	setExportPageSize(t, 2)
	captureLog(t)
	for _, format := range []string{"csv", "json"} {
		t.Run(format, func(t *testing.T) {
			st := &fakeExportStore{certs: certsN(5), failOn: 2}
			mux := chi.NewRouter()
			mux.Use(chimw.Recoverer)
			mux.Get("/export", NewCertHandler(st).Export)
			srv := httptest.NewServer(mux)
			defer srv.Close()

			resp, err := http.Get(srv.URL + "/export?format=" + format)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				t.Fatalf("body read ended cleanly (%d bytes), want a transfer error", len(body))
			}
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("err = %v, want unexpected EOF", err)
			}
		})
	}
}

// The server's write timeout is measured from the request headers. A long
// export must keep extending it, one window per page.
func TestExport_ExtendsTheWriteDeadlinePerPage(t *testing.T) {
	setExportPageSize(t, 2)
	st := &fakeExportStore{certs: certsN(12), delay: 120 * time.Millisecond}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(NewCertHandler(st).Export))
	srv.Config.WriteTimeout = 300 * time.Millisecond
	srv.Start()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "?format=json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v (the export was cut off by the write timeout)", err)
	}
	var out []map[string]any
	if err := json.Unmarshal(body, &out); err != nil || len(out) != 12 {
		t.Fatalf("got %d rows, err %v", len(out), err)
	}
}

// When the client has gone away the store fails with context canceled. That is
// not an export failure: nothing to abort, and nothing to log as an error.
func TestExport_ClientDisconnectDuringAFetchIsNotAFailure(t *testing.T) {
	setExportPageSize(t, 2)
	buf := captureLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &fakeExportStore{certs: certsN(6), cancelOn: 2, cancel: cancel}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/certificates", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Export panicked with %v on a client disconnect", r)
			}
		}()
		NewCertHandler(st).Export(rec, req)
	}()

	if strings.Contains(buf.String(), "certificate export failed part way") || strings.Contains(buf.String(), `"level":"error"`) {
		t.Errorf("a client disconnect was logged as a failure: %q", buf.String())
	}
}
