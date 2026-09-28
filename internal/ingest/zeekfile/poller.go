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

// Package zeekfile ingests the JSON logs a Zeek sensor writes to a
// directory: certificates from x509.log and the TLS sessions that served
// them from ssl.log.
//
// It reads the live logs at the top of the directory, the files Zeek's
// rotation renames them to (x509.<timestamp>.log), and the logs of each
// offline PCAP job in <dir>/<job>/ once the sensor has marked the job
// .done. Files are tracked by identity (device and inode), not name, so a
// rotated log is finished from where the poller left off, and only
// complete lines are consumed, so a line Zeek is still writing is read on
// the next poll. The cursor (one entry per file) is kept as JSON in
// ingestion_state and saved after every batch; entries for files that no
// longer exist are dropped.
package zeekfile

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/ingest/zeek"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// Store is what the poller needs from the store.
type Store interface {
	GetIngestionState(ctx context.Context, sourceName string) (*model.IngestionState, error)
	SetIngestionState(ctx context.Context, state *model.IngestionState) error
	GetCertificate(ctx context.Context, fingerprint string) (*model.Certificate, error)
	RecordObservation(ctx context.Context, obs *model.CertificateObservation) error
}

// CertIngester is the part of ingest.UnifiedIngester the poller uses.
type CertIngester interface {
	Ingest(ctx context.Context, result *ingest.DiscoveryResult) (*ingest.IngestionSummary, error)
}

// Config configures a Poller. Interval defaults to 30s and BatchLines to
// 500.
type Config struct {
	LogDir     string
	Interval   time.Duration
	BatchLines int
}

const (
	defaultInterval   = 30 * time.Second
	defaultBatchLines = 500
	doneMarker        = ".done"
)

// maxReadPerFile bounds what one poll reads from one file, so a large
// backlog is worked through over several polls. A variable so tests can
// lower it.
var maxReadPerFile int64 = 16 << 20

// logKinds are the logs read, in order: certificates before the sessions
// that reference them (observations have a foreign key to certificates).
var logKinds = []string{"x509", "ssl"}

// Poller reads a Zeek log directory.
type Poller struct {
	cfg Config
	st  Store
	ing CertIngester
	// dirMissing is set while LogDir does not exist, so that is logged once
	// rather than on every poll.
	dirMissing bool
}

// New returns a Poller for cfg.LogDir.
func New(cfg Config, st Store, ing CertIngester) *Poller {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.BatchLines <= 0 {
		cfg.BatchLines = defaultBatchLines
	}
	return &Poller{cfg: cfg, st: st, ing: ing}
}

func (p *Poller) sourceName() string { return "zeek_file:" + p.cfg.LogDir }

// Run polls immediately and then every Interval until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(p.cfg.Interval)
	defer t.Stop()
	for {
		if err := p.PollOnce(ctx); err != nil && ctx.Err() == nil {
			log.Error().Err(err).Str("log_dir", p.cfg.LogDir).Msg("zeek: poll failed; retrying next interval")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// cursorEntry is how far one file has been read.
type cursorEntry struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
}

type logFile struct {
	kind, path, id string
	size           int64
}

// pollStats counts one poll's work, for the log line.
type pollStats struct {
	certificates, observations, unknownCerts, badLines int
}

// PollOnce reads everything new in the log directory.
func (p *Poller) PollOnce(ctx context.Context) error {
	cursor, err := p.loadCursor(ctx)
	if err != nil {
		return err
	}
	files, err := p.listFiles()
	if err != nil {
		return err
	}
	present := make(map[string]bool, len(files))
	for _, f := range files {
		present[f.id] = true
	}
	for id := range cursor {
		if !present[id] {
			delete(cursor, id)
		}
	}

	var stats pollStats
	known := map[string]bool{}
	// A file that fails is reported after the others have been read, so one
	// bad file does not starve the files behind it. Its cursor stays where its
	// last good batch left it. If an x509 file failed, the ssl files wait for
	// the next poll: their sessions reference certificates that may be
	// missing, and reading them now would count those sessions as unknown and
	// move the cursor past them.
	var firstErr error
	x509Failed := false
	// x509Behind is set when an x509 file has more to read than this poll's
	// cap allowed. The ssl files wait for the next poll for the same reason as
	// after a failure.
	x509Behind := false
	for _, f := range files {
		if f.kind == "ssl" && (x509Failed || x509Behind) {
			continue
		}
		hitLimit, err := p.readFile(ctx, f, cursor, known, &stats)
		if f.kind == "x509" && hitLimit {
			x509Behind = true
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			} else {
				log.Warn().Err(err).Str("file", f.path).Msg("zeek: reading log failed")
			}
			if f.kind == "x509" {
				x509Failed = true
			}
		}
	}
	if err := p.saveCursor(ctx, cursor); err != nil {
		if firstErr != nil {
			log.Warn().Err(err).Msg("zeek: saving cursor after a failed poll")
			return firstErr
		}
		return err
	}
	if stats != (pollStats{}) {
		log.Info().Str("log_dir", p.cfg.LogDir).
			Int("certificates", stats.certificates).Int("observations", stats.observations).
			Int("observations_unknown_cert", stats.unknownCerts).Int("unparseable_lines", stats.badLines).
			Msg("zeek: ingested logs")
	}
	return firstErr
}

// listFiles returns the logs to read: the top of the directory, then each
// finished PCAP job, x509 before ssl throughout, and within a directory
// rotated files (older) before the live one.
func (p *Poller) listFiles() ([]logFile, error) {
	dirs := []string{p.cfg.LogDir}
	entries, err := os.ReadDir(p.cfg.LogDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if !p.dirMissing {
				log.Warn().Str("log_dir", p.cfg.LogDir).
					Msg("zeek: log_dir does not exist; no Zeek logs will be read until a sensor writes there")
				p.dirMissing = true
			}
			return nil, nil
		}
		return nil, fmt.Errorf("read zeek log dir: %w", err)
	}
	p.dirMissing = false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		job := filepath.Join(p.cfg.LogDir, e.Name())
		if _, err := os.Stat(filepath.Join(job, doneMarker)); err == nil {
			dirs = append(dirs, job)
		}
	}

	var files []logFile
	for _, kind := range logKinds {
		for _, dir := range dirs {
			var paths []string
			for _, pattern := range []string{kind + ".*.log", kind + ".log"} {
				m, err := filepath.Glob(filepath.Join(dir, pattern))
				if err != nil {
					return nil, err
				}
				sort.Strings(m)
				paths = append(paths, m...)
			}
			for _, path := range paths {
				fi, err := os.Stat(path)
				if err != nil || !fi.Mode().IsRegular() {
					continue
				}
				id := fileID(fi)
				if id == "" {
					id = "path:" + path
				}
				files = append(files, logFile{kind: kind, path: path, id: id, size: fi.Size()})
			}
		}
	}
	return files, nil
}

// readFile ingests f's complete lines from its cursor on, one batch at a
// time, saving the cursor after each. hitLimit reports that the read stopped
// at maxReadPerFile, so more of the file may be left.
func (p *Poller) readFile(ctx context.Context, f logFile, cursor map[string]cursorEntry, known map[string]bool, stats *pollStats) (hitLimit bool, err error) {
	offset := cursor[f.id].Offset
	if f.size < offset {
		// Truncated in place, or a new file that reused the inode.
		offset = 0
	}
	cursor[f.id] = cursorEntry{Path: f.path, Offset: offset}
	if f.size == offset {
		return false, nil
	}

	fh, err := os.Open(f.path)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", f.path, err)
	}
	defer fh.Close()
	if _, err := fh.Seek(offset, io.SeekStart); err != nil {
		return false, fmt.Errorf("seek %s: %w", f.path, err)
	}
	limited := &io.LimitedReader{R: fh, N: maxReadPerFile}
	r := bufio.NewReader(limited)
	defer func() { hitLimit = limited.N == 0 }()

	var batch [][]byte
	var batchBytes int64
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := p.process(ctx, f.kind, batch, known, stats); err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		offset += batchBytes
		cursor[f.id] = cursorEntry{Path: f.path, Offset: offset}
		batch, batchBytes = nil, 0
		return p.saveCursor(ctx, cursor)
	}
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			// io.EOF: line, if any, is incomplete (or cut by the read limit)
			// and is left for the next poll.
			if !errors.Is(err, io.EOF) {
				return false, fmt.Errorf("read %s: %w", f.path, err)
			}
			return false, flush()
		}
		batchBytes += int64(len(line))
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 && trimmed[0] != '#' {
			batch = append(batch, trimmed)
		}
		if len(batch) >= p.cfg.BatchLines {
			if err := flush(); err != nil {
				return false, err
			}
		}
	}
}

func (p *Poller) process(ctx context.Context, kind string, lines [][]byte, known map[string]bool, stats *pollStats) error {
	switch kind {
	case "x509":
		return p.processX509(ctx, lines, known, stats)
	case "ssl":
		return p.processSSL(ctx, lines, known, stats)
	}
	return nil
}

func (p *Poller) processX509(ctx context.Context, lines [][]byte, known map[string]bool, stats *pollStats) error {
	var discs []dedup.CertDiscovery
	for _, line := range lines {
		rec, err := zeek.ParseX509Record(line)
		if err != nil {
			stats.badLines++
			continue
		}
		if rec.Fingerprint == "" {
			continue
		}
		discs = append(discs, certDiscovery(rec))
	}
	if len(discs) == 0 {
		return nil
	}
	summary, err := p.ing.Ingest(ctx, &ingest.DiscoveryResult{
		Source:             string(model.SourceZeekPassive),
		SkipHostResolution: true,
		Timestamp:          time.Now().UTC(),
		Certificates:       discs,
	})
	if err != nil {
		return fmt.Errorf("ingest certificates: %w", err)
	}
	// Ingest skips, without an error, a certificate whose fingerprint
	// contradicts its PEM, so only what it reports as stored is known. The
	// rest (and anything its observation cache skipped as already stored) is
	// looked up in the store when a session references it.
	for _, a := range summary.IngestedAssets {
		if a.AssetType == "certificate" {
			known[a.AssetID] = true
		}
	}
	stats.certificates += len(discs)
	return nil
}

// certDiscovery is the discovery for one x509.log record. With the
// certificate itself (log-certs-base64), ingest parses it and stores every
// field, so x509.log's own fields are not sent: they would override the
// parsed values in their Zeek spelling (upper-case serial, OpenSSL
// algorithm names). Without it, the record's fields are all there is.
func certDiscovery(rec *zeek.X509Record) dedup.CertDiscovery {
	fp := strings.ToLower(rec.Fingerprint)
	if rec.CertPEM != "" {
		return dedup.CertDiscovery{FingerprintSHA256: fp, RawPEM: rec.CertPEM}
	}
	c := zeek.MapX509ToCertificate(rec)
	return dedup.CertDiscovery{
		FingerprintSHA256:  fp,
		SubjectCN:          c.Subject.CommonName,
		IssuerCN:           c.Issuer.CommonName,
		SerialNumber:       c.SerialNumber,
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		KeyAlgorithm:       string(c.KeyAlgorithm),
		KeySizeBits:        c.KeySizeBits,
		SignatureAlgorithm: string(c.SignatureAlgorithm),
		SubjectAltNames:    c.SubjectAltNames,
		IsCA:               c.IsCA,
	}
}

// processSSL records which server served which certificate. A session
// whose certificate is not stored is skipped (observations have a foreign
// key to certificates); x509 logs are read first, so that is a certificate
// Zeek logged without its x509 record reaching this poller.
func (p *Poller) processSSL(ctx context.Context, lines [][]byte, known map[string]bool, stats *pollStats) error {
	for _, line := range lines {
		rec, err := zeek.ParseSSLRecord(line)
		if err != nil {
			stats.badLines++
			continue
		}
		for _, o := range zeek.MapSSLToObservations(rec) {
			o.CertFingerprint = strings.ToLower(o.CertFingerprint)
			ok, err := p.certKnown(ctx, o.CertFingerprint, known)
			if err != nil {
				return err
			}
			if !ok {
				stats.unknownCerts++
				continue
			}
			if err := p.st.RecordObservation(ctx, o); err != nil {
				return fmt.Errorf("record observation: %w", err)
			}
			stats.observations++
		}
	}
	return nil
}

func (p *Poller) certKnown(ctx context.Context, fp string, known map[string]bool) (bool, error) {
	if ok, seen := known[fp]; seen {
		return ok, nil
	}
	c, err := p.st.GetCertificate(ctx, fp)
	if err != nil {
		return false, fmt.Errorf("look up certificate %s: %w", fp, err)
	}
	known[fp] = c != nil
	return c != nil, nil
}

func (p *Poller) loadCursor(ctx context.Context) (map[string]cursorEntry, error) {
	cursor := map[string]cursorEntry{}
	state, err := p.st.GetIngestionState(ctx, p.sourceName())
	if err != nil {
		return nil, fmt.Errorf("load zeek cursor: %w", err)
	}
	if state == nil || state.Cursor == "" {
		return cursor, nil
	}
	if err := json.Unmarshal([]byte(state.Cursor), &cursor); err != nil {
		// Unreadable (a hand edit, or the pre-2.0 poller's plain offset):
		// start over rather than stop; ingest is idempotent.
		log.Warn().Err(err).Str("log_dir", p.cfg.LogDir).Msg("zeek: cursor unreadable; reading the logs from the start")
		return map[string]cursorEntry{}, nil
	}
	return cursor, nil
}

func (p *Poller) saveCursor(ctx context.Context, cursor map[string]cursorEntry) error {
	b, err := json.Marshal(cursor)
	if err != nil {
		return err
	}
	if err := p.st.SetIngestionState(ctx, &model.IngestionState{SourceName: p.sourceName(), Cursor: string(b)}); err != nil {
		return fmt.Errorf("save zeek cursor: %w", err)
	}
	return nil
}
