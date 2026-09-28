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

package zeekfile

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// CE 2.0.0 dropped the Zeek log poller, so from 2.0.0 to 2.3.0 CE read no
// Zeek logs at all although the sensor, its config and the docs were all
// still there. These tests pin the restored poller against real Zeek 9
// logs (internal/ingest/zeek/testdata/zeek9).

const fixtureDir = "../zeek/testdata/zeek9"

func fixture(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join(fixtureDir, name))
	require.NoError(t, err)
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	require.NoError(t, sc.Err())
	return out
}

// fakeStore keeps the cursor, the certificates the fake ingester stored,
// and the observations recorded, plus the order of ingests and
// observations.
type fakeStore struct {
	mu     sync.Mutex
	state  map[string]string
	certs  map[string]bool
	obs    []*model.CertificateObservation
	events []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{state: map[string]string{}, certs: map[string]bool{}}
}

func (s *fakeStore) GetIngestionState(_ context.Context, name string) (*model.IngestionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.state[name]
	if !ok {
		return nil, nil
	}
	return &model.IngestionState{SourceName: name, Cursor: c}, nil
}

func (s *fakeStore) SetIngestionState(_ context.Context, st *model.IngestionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state[st.SourceName] = st.Cursor
	return nil
}

func (s *fakeStore) GetCertificate(_ context.Context, fp string) (*model.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.certs[fp] {
		return nil, nil
	}
	return &model.Certificate{FingerprintSHA256: fp}, nil
}

func (s *fakeStore) RecordObservation(_ context.Context, o *model.CertificateObservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.certs[o.CertFingerprint] {
		return fmt.Errorf("observations.cert_fingerprint references no certificate: %s", o.CertFingerprint)
	}
	s.obs = append(s.obs, o)
	s.events = append(s.events, "observation")
	return nil
}

// fakeIngester records every certificate discovery and stores it in the
// fake store, as the real pipeline would. fail makes the next call fail.
type fakeIngester struct {
	st    *fakeStore
	certs []ingestedCert
	fail  int
	// reject names fingerprints ingest skips without an error, as it does
	// for a fingerprint that contradicts its PEM (dedup.ErrPEMMismatch).
	reject map[string]bool
}

type ingestedCert struct {
	source string
	disc   ingestCertFields
}

type ingestCertFields struct {
	fingerprint, pem, subjectCN string
	skipHost                    bool
}

func (f *fakeIngester) Ingest(_ context.Context, r *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	if f.fail > 0 {
		f.fail--
		return nil, errors.New("ingest unavailable")
	}
	f.st.mu.Lock()
	defer f.st.mu.Unlock()
	summary := &ingest.IngestionSummary{}
	for _, d := range r.Certificates {
		if f.reject[d.FingerprintSHA256] {
			continue
		}
		summary.IngestedAssets = append(summary.IngestedAssets,
			ingest.IngestedAsset{AssetType: "certificate", AssetID: d.FingerprintSHA256, IsNew: true})
		f.certs = append(f.certs, ingestedCert{source: r.Source, disc: ingestCertFields{
			fingerprint: d.FingerprintSHA256, pem: d.RawPEM, subjectCN: d.SubjectCN, skipHost: r.SkipHostResolution,
		}})
		f.st.certs[d.FingerprintSHA256] = true
		f.st.events = append(f.st.events, "certificate")
	}
	return summary, nil
}

func newTestPoller(t *testing.T, dir string, batch int) (*Poller, *fakeStore, *fakeIngester) {
	t.Helper()
	st := newFakeStore()
	ing := &fakeIngester{st: st}
	return New(Config{LogDir: dir, Interval: time.Hour, BatchLines: batch}, st, ing), st, ing
}

func writeLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
}

func appendText(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = f.WriteString(text)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

func fingerprints(ing *fakeIngester) []string {
	var out []string
	for _, c := range ing.certs {
		out = append(out, c.disc.fingerprint)
	}
	return out
}

// x509Line is a minimal x509.log record without the certificate itself.
func x509Line(fp string) string {
	return `{"ts":1790614100.2,"fingerprint":"` + fp + `","certificate.subject":"CN=` + fp + `.test","certificate.issuer":"CN=Issuer"}`
}

func TestPollOnce_IngestsCertificatesThenObservations(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "ssl.log"), fixture(t, "ssl.log")...)
	writeLines(t, filepath.Join(dir, "x509.log"), fixture(t, "x509.log")...)
	p, st, ing := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))

	require.Len(t, ing.certs, 2, "the server and CA certificates")
	for _, c := range ing.certs {
		require.Equal(t, string(model.SourceZeekPassive), c.source)
		require.True(t, c.disc.skipHost, "a network sensor's certificates belong to no single host")
		require.Contains(t, c.disc.pem, "BEGIN CERTIFICATE", "the certificate itself is sent, so it is stored in full")
		require.Empty(t, c.disc.subjectCN, "with the PEM, x509.log's fields are not overlaid on the parsed certificate")
	}
	// Two TLS 1.2 connections, each with a two-certificate chain; the TLS 1.3
	// connection's chain is encrypted and yields none.
	require.Len(t, st.obs, 4)
	names := map[string]int{}
	for _, o := range st.obs {
		require.Equal(t, 4443, o.ServerPort)
		require.Equal(t, model.SourceZeekPassive, o.Source)
		names[o.ServerName]++
	}
	require.Equal(t, map[string]int{"tls.zeek-fixture.test": 2, "alt.zeek-fixture.test": 2}, names)
	require.Equal(t, []string{"certificate", "certificate", "observation", "observation", "observation", "observation"}, st.events,
		"certificates are stored before the observations that reference them")
}

// A sensor without the log-certs-base64 policy logs no certificate; the
// record's own fields are sent instead.
func TestPollOnce_X509WithoutTheCertificateSendsItsFields(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"))
	p, _, ing := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, ing.certs, 1)
	require.Equal(t, "aa11", ing.certs[0].disc.fingerprint)
	require.Equal(t, "aa11.test", ing.certs[0].disc.subjectCN)
	require.Empty(t, ing.certs[0].disc.pem)
}

// observations reference certificates by foreign key.
func TestPollOnce_SkipsObservationsOfUnknownCertificates(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "ssl.log"), fixture(t, "ssl.log")...)
	p, st, _ := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Empty(t, st.obs)
}

func TestPollOnce_ResumesFromItsCursor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x509.log")
	writeLines(t, path, x509Line("aa11"))
	p, st, ing := newTestPoller(t, dir, 0)
	require.NoError(t, p.PollOnce(context.Background()))

	// A restart: a new poller with the same store reads nothing twice.
	ing2 := &fakeIngester{st: st}
	p2 := New(Config{LogDir: dir, Interval: time.Hour}, st, ing2)
	require.NoError(t, p2.PollOnce(context.Background()))
	require.Empty(t, ing2.certs)

	appendText(t, path, x509Line("bb22")+"\n")
	require.NoError(t, p2.PollOnce(context.Background()))
	require.Equal(t, []string{"bb22"}, fingerprints(ing2))
	require.Equal(t, []string{"aa11"}, fingerprints(ing))
}

// Zeek may be half-way through writing a line when the poller reads. The
// old poller consumed the fragment, failed to parse it and moved past it,
// losing the record.
func TestPollOnce_ReadsOnlyCompleteLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x509.log")
	full, partial := x509Line("aa11"), x509Line("bb22")
	require.NoError(t, os.WriteFile(path, []byte(full+"\n"+partial[:20]), 0o644))
	p, _, ing := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"aa11"}, fingerprints(ing))

	appendText(t, path, partial[20:]+"\n")
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"aa11", "bb22"}, fingerprints(ing))
}

// Zeek rotates its logs hourly by renaming the live file. The old poller
// tracked offsets by file name, so the lines written between its last read
// and the rotation were lost, and the new live file was not read until it
// grew past the old offset.
func TestPollOnce_FollowsRotation(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "x509.log")
	writeLines(t, live, x509Line("aa11"))
	p, _, ing := newTestPoller(t, dir, 0)
	require.NoError(t, p.PollOnce(context.Background()))

	appendText(t, live, x509Line("bb22")+"\n")
	require.NoError(t, os.Rename(live, filepath.Join(dir, "x509.2026-09-28-17-00-00.log")))
	writeLines(t, live, x509Line("cc33"))

	require.NoError(t, p.PollOnce(context.Background()))
	require.ElementsMatch(t, []string{"aa11", "bb22", "cc33"}, fingerprints(ing), "each line exactly once")
}

func TestPollOnce_RestartsATruncatedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x509.log")
	writeLines(t, path, x509Line("aa11"), x509Line("bb22"))
	p, _, ing := newTestPoller(t, dir, 0)
	require.NoError(t, p.PollOnce(context.Background()))

	writeLines(t, path, x509Line("cc33"))
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"aa11", "bb22", "cc33"}, fingerprints(ing))
}

// The sensor processes a dropped PCAP into log_dir/<job>/ and writes .done
// when Zeek has finished; before that the job's logs are incomplete.
func TestPollOnce_ReadsAPCAPJobOnceItIsDone(t *testing.T) {
	dir := t.TempDir()
	job := filepath.Join(dir, "job-1")
	writeLines(t, filepath.Join(job, "x509.2026-09-28-16-48-20.log"), fixture(t, "x509.log")...)
	writeLines(t, filepath.Join(job, "ssl.2026-09-28-16-48-20.log"), fixture(t, "ssl.log")...)
	p, st, ing := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Empty(t, ing.certs, "an unfinished job is not read")

	require.NoError(t, os.WriteFile(filepath.Join(job, ".done"), nil, 0o644))
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, ing.certs, 2)
	require.Len(t, st.obs, 4)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, ing.certs, 2, "a finished job is read once")
}

// The cursor keeps one entry per log file it has read; rotated files that
// are deleted must drop out of it or it grows by one entry an hour.
func TestPollOnce_ForgetsFilesThatAreGone(t *testing.T) {
	dir := t.TempDir()
	rotated := filepath.Join(dir, "x509.2026-09-28-16-00-00.log")
	writeLines(t, rotated, x509Line("aa11"))
	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("bb22"))
	p, st, _ := newTestPoller(t, dir, 0)
	require.NoError(t, p.PollOnce(context.Background()))

	entries := func() int {
		var c map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(st.state[p.sourceName()]), &c))
		return len(c)
	}
	require.Equal(t, 2, entries())

	require.NoError(t, os.Remove(rotated))
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, 1, entries())
}

// The cursor moves only past lines that were ingested; a failed batch is
// read again on the next poll.
func TestPollOnce_DoesNotAdvancePastAFailedBatch(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"), x509Line("bb22"))
	p, _, ing := newTestPoller(t, dir, 1)
	ing.fail = 0

	// The first batch (one line) succeeds, the second fails.
	failSecond := &secondCallFails{fakeIngester: ing}
	p.ing = failSecond
	require.Error(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"aa11"}, fingerprints(ing))

	p.ing = ing
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"aa11", "bb22"}, fingerprints(ing), "the failed line is read again, the ingested one is not")
}

type secondCallFails struct {
	*fakeIngester
	calls int
}

func (s *secondCallFails) Ingest(ctx context.Context, r *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	s.calls++
	if s.calls == 2 {
		return nil, errors.New("ingest unavailable")
	}
	return s.fakeIngester.Ingest(ctx, r)
}

// Ingest skips a certificate whose fingerprint contradicts its PEM without
// returning an error, so the poller must not take it for stored: the
// session that references it would fail its foreign key on every poll, hold
// the ssl cursor in place, and (as PollOnce stopped at the first error)
// starve every file after it.
func TestPollOnce_SkipsSessionsOfACertificateIngestRefused(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), fixture(t, "x509.log")...)
	writeLines(t, filepath.Join(dir, "ssl.log"), fixture(t, "ssl.log")...)
	p, st, ing := newTestPoller(t, dir, 0)
	ing.reject = map[string]bool{"b5341cf253692da10c93f8197a443817861e06f58bd6c691ab25a9709f25043c": true}

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 2, "the two sessions' CA-certificate observations; the refused server certificate's are skipped")
	for _, o := range st.obs {
		require.Equal(t, "a343cadac5724c91ba6893f38386151f997918309d0fcd308eba63c80292ae40", o.CertFingerprint)
	}

	// The ssl cursor advanced past the batch, so the next poll is quiet.
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 2)
}

// A file that cannot be read must not keep the files after it from being read.
func TestPollOnce_ReadsTheRestWhenOneFileCannotBeOpened(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file permissions do not stop root")
	}
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), fixture(t, "x509.log")...)
	// Rotated files sort before the live one.
	locked := filepath.Join(dir, "ssl.2026-09-28-11-00-00.log")
	writeLines(t, locked, fixture(t, "ssl.log")...)
	require.NoError(t, os.Chmod(locked, 0o000))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
	writeLines(t, filepath.Join(dir, "ssl.log"), fixture(t, "ssl.log")...)
	p, st, _ := newTestPoller(t, dir, 0)

	err := p.PollOnce(context.Background())
	require.Error(t, err, "the unreadable file is still reported")
	require.Contains(t, err.Error(), "ssl.2026-09-28-11-00-00.log")
	require.Len(t, st.obs, 4, "the live ssl.log after it was read")
}

// Continuing past a failed file must not lose sessions: if an x509 file
// failed, the ssl files are left for the next poll, or their sessions would
// count as unknown-certificate and their cursor would move past them.
func TestPollOnce_LeavesSSLAloneWhenX509Failed(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), fixture(t, "x509.log")...)
	writeLines(t, filepath.Join(dir, "ssl.log"), fixture(t, "ssl.log")...)
	p, st, ing := newTestPoller(t, dir, 0)
	ing.fail = 1

	require.Error(t, p.PollOnce(context.Background()))
	require.Empty(t, st.obs)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 4, "the sessions are recorded once the certificates are")
}
