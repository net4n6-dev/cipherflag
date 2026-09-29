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
	"encoding/base64"
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
	// seen holds the sessions already stored, as the real store's unique index does.
	seen map[string]bool
	// batchCalls counts BatchRecordObservations calls.
	batchCalls int
	// failBatch makes the next BatchRecordObservations calls fail, counting down.
	failBatch int
}

func (s *fakeStore) BatchRecordObservations(ctx context.Context, obs []*model.CertificateObservation) error {
	s.mu.Lock()
	s.batchCalls++
	if s.failBatch > 0 {
		s.failBatch--
		s.mu.Unlock()
		return fmt.Errorf("batch write failed")
	}
	for _, o := range obs {
		if !s.certs[o.CertFingerprint] {
			s.mu.Unlock()
			return fmt.Errorf("observations.cert_fingerprint references no certificate: %s", o.CertFingerprint)
		}
	}
	s.mu.Unlock()
	for _, o := range obs {
		if err := s.RecordObservation(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

func newFakeStore() *fakeStore {
	return &fakeStore{state: map[string]string{}, certs: map[string]bool{}, seen: map[string]bool{}}
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
	key := fmt.Sprintf("%s|%s|%d|%s|%s|%d", o.CertFingerprint, o.Source, o.ObservedAt.UnixNano(), o.ClientIP, o.ServerIP, o.ServerPort)
	if s.seen[key] {
		return nil
	}
	s.seen[key] = true
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

// sslLine is an ssl.log record for a TLS 1.2 session whose chain is fp.
func sslLine(uid, fp string) string {
	return `{"ts":1790614100.25,"uid":"` + uid + `","id.orig_h":"10.0.0.9","id.orig_p":50000,"id.resp_h":"10.0.0.5","id.resp_p":443,` +
		`"version":"TLSv12","cipher":"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","server_name":"c.test","cert_chain_fps":["` + fp + `"]}`
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

// A multi-capture job directory is named after the capture file, so its name
// can hold glob metacharacters. Names are literal: a bracketed name is still
// read, and a wildcard name does not pull in another job's logs.
func TestPollOnce_JobDirectoryNamesAreLiteral(t *testing.T) {
	dir := t.TempDir()
	bracket := filepath.Join(dir, "job--cap[1].pcap")
	writeLines(t, filepath.Join(bracket, "x509.log"), fixture(t, "x509.log")...)
	writeLines(t, filepath.Join(bracket, "ssl.log"), fixture(t, "ssl.log")...)
	require.NoError(t, os.WriteFile(filepath.Join(bracket, ".done"), nil, 0o644))

	star := filepath.Join(dir, "q*")
	writeLines(t, filepath.Join(star, "x509.log"), x509Line("cc33"))
	require.NoError(t, os.WriteFile(filepath.Join(star, ".done"), nil, 0o644))
	unfinished := filepath.Join(dir, "qz")
	writeLines(t, filepath.Join(unfinished, "x509.log"), x509Line("dd44"))

	p, _, ing := newTestPoller(t, dir, 0)
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, ing.certs, 3, "two from the bracketed job, one from q*, none from the unfinished qz")
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
// returning an error, so the poller must not take it for stored. Sessions
// that reference it are parked like any unknown certificate's, and dropped
// after their retries; they never fail the batch or hold the ssl cursor.
func TestPollOnce_SkipsSessionsOfACertificateIngestRefused(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), fixture(t, "x509.log")...)
	writeLines(t, filepath.Join(dir, "ssl.log"), fixture(t, "ssl.log")...)
	p, st, ing := newTestPoller(t, dir, 0)
	ing.reject = map[string]bool{"b5341cf253692da10c93f8197a443817861e06f58bd6c691ab25a9709f25043c": true}

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 2, "the two sessions' CA-certificate observations are recorded at once")
	for _, o := range st.obs {
		require.Equal(t, "a343cadac5724c91ba6893f38386151f997918309d0fcd308eba63c80292ae40", o.CertFingerprint)
	}
	require.Len(t, p.pending, 2, "the refused certificate's observations are parked")

	// They wait, then are dropped.
	for range maxHeldPolls {
		require.NoError(t, p.PollOnce(context.Background()))
		require.Len(t, st.obs, 2)
	}
	require.Empty(t, p.pending)

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

// A poll reads at most maxReadPerFile from one file. Sessions reference
// certificates, so while an x509 file has more left than that cap allowed,
// the ssl files must wait: read now, their sessions would count as unknown
// and the ssl cursor would move past them for good.
func TestPollOnce_HoldsSSLWhileAnX509BacklogRemains(t *testing.T) {
	// Padded so two x509 lines are longer than the ssl line the cap must let through.
	pad := strings.Repeat("x", 400)
	x509 := func(fp string) string { return strings.TrimSuffix(x509Line(fp), "}") + `,"pad":"` + pad + `"}` }
	line := x509("aa11")
	old := maxReadPerFile
	maxReadPerFile = int64(2*(len(line)+1) + 5) // two whole lines and a bit of the third
	t.Cleanup(func() { maxReadPerFile = old })

	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), x509("aa11"), x509("bb22"), x509("cc33"))
	writeLines(t, filepath.Join(dir, "ssl.log"),
		`{"ts":1790614100.25,"uid":"C1","id.orig_h":"10.0.0.9","id.orig_p":50000,"id.resp_h":"10.0.0.5","id.resp_p":443,`+
			`"version":"TLSv12","cipher":"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","server_name":"c.test","cert_chain_fps":["cc33"]}`)
	p, st, ing := newTestPoller(t, dir, 0)

	// Poll 1 reads two of the three certificates; the session of the third
	// is not read yet.
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"aa11", "bb22"}, fingerprints(ing))
	require.Empty(t, st.obs)

	// Poll 2 reads the last certificate, then the session that references it.
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"aa11", "bb22", "cc33"}, fingerprints(ing))
	require.Len(t, st.obs, 1, "the session was held, not dropped")
	require.Equal(t, "cc33", st.obs[0].CertFingerprint)
}

// x509LineWithCert is an x509.log record carrying the certificate itself as
// base64 DER, as a sensor with the log-certs-base64 policy writes it.
func x509LineWithCert(fp string, der []byte) string {
	return strings.TrimSuffix(x509Line(fp), "}") + `,"cert":"` + base64.StdEncoding.EncodeToString(der) + `"}`
}

// Zeek (OpenSSL) logs certificates Go's parser rejects. The 2.3.1 poller sent
// only the PEM for a certificate it had, so ingest stored a blank row (empty
// subject, zero not_after, no algorithms) that stayed "incomplete" forever.
// When the PEM does not parse, x509.log's own fields are all there is.
func TestPollOnce_UnparseableCertificateFallsBackToX509Fields(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), x509LineWithCert("aa11", []byte("not a certificate")))
	p, _, ing := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, ing.certs, 1)
	require.Equal(t, "aa11", ing.certs[0].disc.fingerprint)
	require.Equal(t, "aa11.test", ing.certs[0].disc.subjectCN, "x509.log's fields are sent when the PEM cannot be parsed")
	require.Empty(t, ing.certs[0].disc.pem, "a PEM Go cannot parse is not stored as the raw certificate")
}

// A line that does not end within maxReadPerFile can never complete inside
// one poll's read, so it was treated as "incomplete, retry next poll"
// forever: the offset stayed put and every line behind it was lost.
func TestPollOnce_SkipsALineLongerThanTheReadCap(t *testing.T) {
	old := maxReadPerFile
	maxReadPerFile = 300
	t.Cleanup(func() { maxReadPerFile = old })

	long := strings.TrimSuffix(x509Line("aa11"), "}") + `,"pad":"` + strings.Repeat("x", 600) + `"}`
	require.Greater(t, int64(len(long)), maxReadPerFile)
	require.Less(t, int64(len(x509Line("bb22"))+1), maxReadPerFile)
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), long, x509Line("bb22"))
	p, _, ing := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Empty(t, fingerprints(ing), "the over-long line is skipped, not ingested")
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"bb22"}, fingerprints(ing), "the line behind it is read")
}

// A comment line ahead of the over-long line adds to the bytes read but not to
// the batch; the long line must still be skipped.
func TestPollOnce_SkipsALongLineBehindACommentLine(t *testing.T) {
	old := maxReadPerFile
	maxReadPerFile = 300
	t.Cleanup(func() { maxReadPerFile = old })

	long := strings.TrimSuffix(x509Line("aa11"), "}") + `,"pad":"` + strings.Repeat("x", 600) + `"}`
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), "# comment", long, x509Line("bb22"))
	p, _, ing := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Empty(t, fingerprints(ing), "the over-long line is skipped, not ingested")
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"bb22"}, fingerprints(ing), "the line behind it is read")
}

// Zeek renames a log during rotation first to an intermediate dashed name that
// the poller's patterns do not match, then to the dotted rotated name. For a
// poll the file is absent and its cursor entry is forgotten; the file is then
// read again from the start. Lines are neither lost nor doubled, because the
// store is idempotent.
func TestPollOnce_ReadsAFileRotatedThroughAnIntermediateName(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"), x509Line("bb22"))
	writeLines(t, filepath.Join(dir, "ssl.log"), sslLineAt("C1", "aa11", 1790614101), sslLineAt("C2", "bb22", 1790614102))
	p, st, ing := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"aa11", "bb22"}, fingerprints(ing))
	require.Len(t, st.obs, 2)

	require.NoError(t, os.Rename(filepath.Join(dir, "x509.log"), filepath.Join(dir, "x509-26-09-28_17.00.00.log")))
	require.NoError(t, os.Rename(filepath.Join(dir, "ssl.log"), filepath.Join(dir, "ssl-26-09-28_17.00.00.log")))
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 2)

	require.NoError(t, os.Rename(filepath.Join(dir, "x509-26-09-28_17.00.00.log"), filepath.Join(dir, "x509.2026-09-28-17-00-00.log")))
	require.NoError(t, os.Rename(filepath.Join(dir, "ssl-26-09-28_17.00.00.log"), filepath.Join(dir, "ssl.2026-09-28-17-00-00.log")))
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 2, "the re-read sessions are the same rows")
	require.ElementsMatch(t, []string{"aa11", "bb22"}, uniqueStrings(fingerprints(ing)), "every certificate is still there")
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 2)
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// A long line Zeek is still writing has no newline yet; it must be left for
// a later poll, not skipped.
func TestPollOnce_DoesNotSkipALongLineStillBeingWritten(t *testing.T) {
	old := maxReadPerFile
	maxReadPerFile = 300
	t.Cleanup(func() { maxReadPerFile = old })

	long := strings.TrimSuffix(x509Line("aa11"), "}") + `,"pad":"` + strings.Repeat("x", 600) + `"}`
	dir := t.TempDir()
	path := filepath.Join(dir, "x509.log")
	require.NoError(t, os.WriteFile(path, []byte(long), 0o644)) // no trailing newline
	p, _, ing := newTestPoller(t, dir, 0)

	for range 2 {
		require.NoError(t, p.PollOnce(context.Background()))
		require.Empty(t, fingerprints(ing))
	}
	// The line completes, and a short one follows.
	appendText(t, path, "\n"+x509Line("bb22")+"\n")
	require.NoError(t, p.PollOnce(context.Background())) // skips the long line
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"bb22"}, fingerprints(ing))
}

// A line that fits inside the cap exactly, newline included, is a complete
// line, not an oversized one.
func TestPollOnce_ReadsALineThatFillsTheCapExactly(t *testing.T) {
	line := x509Line("aa11")
	old := maxReadPerFile
	maxReadPerFile = int64(len(line) + 1)
	t.Cleanup(func() { maxReadPerFile = old })

	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), line)
	p, _, ing := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"aa11"}, fingerprints(ing))
}

// editCursor rewrites the cursor the poller saved, to stage a state a real
// filesystem produces only when it reuses an inode.
func editCursor(t *testing.T, p *Poller, st *fakeStore, edit func(e cursorEntry) cursorEntry) {
	t.Helper()
	var c map[string]cursorEntry
	require.NoError(t, json.Unmarshal([]byte(st.state[p.sourceName()]), &c))
	for id, e := range c {
		c[id] = edit(e)
	}
	b, err := json.Marshal(c)
	require.NoError(t, err)
	st.state[p.sourceName()] = string(b)
}

// A rotated log keeps its name for good. The same device and inode under any
// other path is therefore a new file that reused the inode (ext4 and overlay2
// reuse freed inodes quickly; the docs tell operators to delete rotated logs),
// and must be read from the start, not from the stale offset.
func TestPollOnce_RestartsAFileWhoseRotatedNameNowHoldsAnotherPath(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "x509.log")
	writeLines(t, live, x509Line("aa11"), x509Line("bb22"), x509Line("cc33"))
	p, st, ing := newTestPoller(t, dir, 0)
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, ing.certs, 3)

	// The cursor says this id was last seen as a rotated file; it is now
	// found at the live path.
	editCursor(t, p, st, func(e cursorEntry) cursorEntry {
		e.Path = filepath.Join(dir, "x509.2026-09-28-10-00-00.log")
		return e
	})
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, ing.certs, 6, "read again from the start: it is a new file")
}

// The cursor only ever rests just after a newline. If the byte before it is
// anything else, the file is not the one the cursor was for.
func TestPollOnce_RestartsWhenTheCursorIsNotOnALineBoundary(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "x509.log")
	writeLines(t, live, x509Line("aa11"), x509Line("bb22"))
	p, st, ing := newTestPoller(t, dir, 0)
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, ing.certs, 2)

	editCursor(t, p, st, func(e cursorEntry) cursorEntry {
		e.Offset = 10 // inside the first line
		return e
	})
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"aa11", "bb22", "aa11", "bb22"}, fingerprints(ing),
		"read from the start, not from the middle of a line")
}

// The normal rotation path must be untouched: the same id under a new
// rotated name continues from its offset.
func TestPollOnce_ContinuesARotatedFileUnderItsNewName(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "x509.log")
	writeLines(t, live, x509Line("aa11"))
	p, _, ing := newTestPoller(t, dir, 0)
	require.NoError(t, p.PollOnce(context.Background()))

	appendText(t, live, x509Line("bb22")+"\n")
	require.NoError(t, os.Rename(live, filepath.Join(dir, "x509.2026-09-28-17-00-00.log")))
	require.NoError(t, p.PollOnce(context.Background()))
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, []string{"aa11", "bb22"}, fingerprints(ing), "each line exactly once")
}

// sslLineAt is sslLine with its own timestamp, so sessions are distinct to
// the store's unique index.
func sslLineAt(uid, fp string, ts float64) string {
	return strings.Replace(sslLine(uid, fp), `"ts":1790614100.25`, fmt.Sprintf(`"ts":%.2f`, ts), 1)
}

// Zeek's x509 and ssl writers are separate threads, so a session's ssl line
// can reach the disk before its certificate's x509 line. Such a session is
// parked and recorded when its certificate arrives.
func TestPollOnce_ASessionWhoseCertificateArrivesLateIsRecorded(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "ssl.log"), sslLine("C1", "aa11"))
	p, st, _ := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Empty(t, st.obs, "no certificate yet")

	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"))
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 1)
	require.Equal(t, "aa11", st.obs[0].CertFingerprint)
}

// A session whose certificate never arrives is dropped after maxHeldPolls
// retries, and nothing behind it is delayed meanwhile.
func TestPollOnce_DropsASessionWhoseCertificateNeverArrives(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"))
	writeLines(t, filepath.Join(dir, "ssl.log"), sslLineAt("C1", "zz99", 1790614101), sslLineAt("C2", "aa11", 1790614102))
	p, st, _ := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 1, "the known session is recorded at once")
	for i := 2; i <= 1+maxHeldPolls; i++ {
		require.NoError(t, p.PollOnce(context.Background()))
		require.Len(t, st.obs, 1, "poll %d", i)
		if i < 1+maxHeldPolls {
			require.Len(t, p.pending, 1, "still retained after retry %d", i-1)
		}
	}
	require.Empty(t, p.pending, "dropped after its retries")

	// Covers the far side of the boundary: arrival at retry maxHeldPolls+1.
	appendText(t, filepath.Join(dir, "x509.log"), x509Line("zz99")+"\n")
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 1, "too late")
}

// Covers the near side of the boundary: a certificate stored in time for the
// last retry (the poll parked + maxHeldPolls) still records the session.
func TestPollOnce_ACertificateArrivingAtTheThirdRetryIsRecorded(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "ssl.log"), sslLine("C1", "aa11"))
	p, st, _ := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background())) // parked
	for i := 1; i < maxHeldPolls; i++ {
		require.NoError(t, p.PollOnce(context.Background()))
		require.Len(t, p.pending, 1, "retry %d", i)
	}
	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"))
	require.NoError(t, p.PollOnce(context.Background())) // the last retry
	require.Len(t, st.obs, 1)
	require.Empty(t, p.pending)
}

// A failed retry write leaves the parked observations for the next poll.
func TestPollOnce_AFailedRetryLeavesTheParkedObservationsAlone(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "ssl.log"),
		sslLineAt("C1", "aa11", 1790614101), sslLineAt("C2", "aa11", 1790614102), sslLineAt("C3", "aa11", 1790614103))
	p, st, _ := newTestPoller(t, dir, 0)
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, p.pending, 3)

	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"))
	st.failBatch = 1
	require.Error(t, p.PollOnce(context.Background()))
	require.Len(t, p.pending, 3)
	require.Empty(t, st.obs)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 3)
	require.Empty(t, p.pending)
}

func TestPollOnce_ParkedSessionIsRecordedWhenItsCertificateArrivesWithinTheBudget(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "ssl.log"), sslLine("C1", "aa11"))
	p, st, _ := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.NoError(t, p.PollOnce(context.Background()))
	require.Empty(t, st.obs)

	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"))
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 1, "recorded on the poll its certificate arrived")
	require.Empty(t, p.pending)
}

// A different never-stored certificate on every 50th line must not slow the
// log down: nothing waits behind a parked session.
func TestPollOnce_ManyDistinctMissingCertificatesDoNotThrottle(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"))
	var lines []string
	for i := range 2000 {
		fp := "aa11"
		if i%50 == 49 {
			fp = fmt.Sprintf("zz%04d", i)
		}
		lines = append(lines, sslLineAt(fmt.Sprintf("C%d", i), fp, 1790614100+float64(i)))
	}
	writeLines(t, filepath.Join(dir, "ssl.log"), lines...)
	p, st, _ := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 1960)
	require.Len(t, p.pending, 40)
}

func TestPollOnce_PendingIsBounded(t *testing.T) {
	old := maxPendingObs
	maxPendingObs = 3
	t.Cleanup(func() { maxPendingObs = old })

	dir := t.TempDir()
	var lines []string
	for i := range 10 {
		lines = append(lines, sslLineAt(fmt.Sprintf("C%d", i), fmt.Sprintf("zz%02d", i), 1790614100+float64(i)))
	}
	writeLines(t, filepath.Join(dir, "ssl.log"), lines...)
	p, _, _ := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, p.pending, 3)
	var got []string
	for _, o := range p.pending {
		got = append(got, o.obs.CertFingerprint)
	}
	require.Equal(t, []string{"zz07", "zz08", "zz09"}, got, "the oldest were evicted")
}

// A finished PCAP job's x509 log is complete, so an unknown certificate
// there is permanently unknown and is not parked.
func TestPollOnce_DoesNotParkInAFinishedPCAPJob(t *testing.T) {
	dir := t.TempDir()
	job := filepath.Join(dir, "job1")
	writeLines(t, filepath.Join(job, "x509.log"), x509Line("aa11"))
	writeLines(t, filepath.Join(job, "ssl.log"), sslLineAt("C1", "aa11", 1790614101), sslLineAt("C2", "zz99", 1790614102))
	require.NoError(t, os.WriteFile(filepath.Join(job, ".done"), nil, 0o644))
	p, st, _ := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 1)
	require.Empty(t, p.pending)
}

// While an x509 file fails, parked sessions are not retried and their
// retries are not used up.
func TestPollOnce_DoesNotSpendTheBudgetWhileX509IsFailing(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "ssl.log"), sslLine("C1", "aa11"))
	p, st, ing := newTestPoller(t, dir, 0)
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, p.pending, 1)

	// bb22's x509 line fails to ingest on six polls, twice the budget.
	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("bb22"))
	ing.fail = 2 * maxHeldPolls
	for i := range 2 * maxHeldPolls {
		require.Error(t, p.PollOnce(context.Background()))
		require.Len(t, p.pending, 1, "failing poll %d", i+1)
	}
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, p.pending, 1, "still waiting")

	appendText(t, filepath.Join(dir, "x509.log"), x509Line("aa11")+"\n")
	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, st.obs, 1)
	require.Equal(t, "aa11", st.obs[0].CertFingerprint)
}

// A batch of ssl lines is recorded with one call, not one per observation.
func TestPollOnce_RecordsASessionBatchInOneCall(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"))
	writeLines(t, filepath.Join(dir, "ssl.log"), sslLine("C1", "aa11"), sslLine("C2", "aa11"), sslLine("C3", "aa11"))
	p, st, _ := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, 1, st.batchCalls, "one round trip for the whole batch")
	require.Len(t, st.obs, 1, "the three identical sessions are one row, as in the store")
}

// The retry of parked observations is one batched write, not one per row.
func TestPollOnce_RetryWritesParkedObservationsInOneCall(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "ssl.log"),
		sslLineAt("C1", "aa11", 1790614101), sslLineAt("C2", "aa11", 1790614102), sslLineAt("C3", "aa11", 1790614103))
	p, st, _ := newTestPoller(t, dir, 0)

	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, 0, st.batchCalls, "nothing was known, nothing was written")
	require.Len(t, p.pending, 3)

	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"))
	require.NoError(t, p.PollOnce(context.Background()))
	require.Equal(t, 1, st.batchCalls, "the retry is one batch call")
	require.Len(t, st.obs, 3)
	require.Empty(t, p.pending)
}

// A batch that fails must not leave half of its work behind: observations
// parked earlier in the same batch are parked only once the batch has been
// written, so a re-read of the batch cannot park them twice.
func TestPollOnce_AFailedSessionBatchParksNothing(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "x509.log"), x509Line("aa11"))
	writeLines(t, filepath.Join(dir, "ssl.log"), sslLineAt("C1", "zz99", 1790614101), sslLineAt("C2", "aa11", 1790614102))
	p, st, _ := newTestPoller(t, dir, 0)
	st.failBatch = 1

	require.Error(t, p.PollOnce(context.Background()))
	require.Empty(t, p.pending, "nothing parked by a failed batch")

	require.NoError(t, p.PollOnce(context.Background()))
	require.Len(t, p.pending, 1, "zz99 parked exactly once")
	require.Len(t, st.obs, 1)
	require.Equal(t, "aa11", st.obs[0].CertFingerprint)
}
