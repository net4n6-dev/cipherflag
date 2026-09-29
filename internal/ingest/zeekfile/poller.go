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
// longer exist are dropped. An ssl session whose certificate is not stored
// yet is parked and retried after each of the next three polls, and dropped
// if the certificate still has not arrived; the cursor never waits for it.
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

	"github.com/net4n6-dev/cipherflag/internal/certparse"
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
	BatchRecordObservations(ctx context.Context, obs []*model.CertificateObservation) error
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

// maxHeldPolls is how many polls after the one that read it an observation
// whose certificate is not stored yet is retried before it is dropped. Zeek's
// x509 and ssl writers flush on their own beat (about a second apart), so a
// certificate that is going to arrive does within a poll or two.
const maxHeldPolls = 3

// pendingObs is an observation parked until its certificate is stored.
type pendingObs struct {
	obs      *model.CertificateObservation
	parkedAt int
}

// maxPendingObs bounds the parked observations (memory). When it is full the
// oldest are dropped and counted as unknown-certificate sessions. A variable
// so tests can lower it.
var maxPendingObs = 50000

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
	// pending holds observations whose certificate was not stored when their
	// session was read, and pollSeq numbers the polls. In memory only (lost
	// on restart), and PollOnce is not called concurrently.
	pending []pendingObs
	pollSeq int
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
	// job is set for a log under a finished PCAP job directory.
	job bool
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

	p.pollSeq++
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
	// Parked observations are retried once the x509 files are read, so a
	// certificate that arrived this poll is stored. Not while an x509 file is
	// failing or behind: the certificate may be in what was not read, so no
	// poll is spent on them.
	if x509Failed || x509Behind {
		for i := range p.pending {
			if p.pending[i].parkedAt < p.pollSeq {
				p.pending[i].parkedAt++
			}
		}
	} else if err := p.retryPending(ctx, known, &stats); err != nil {
		if firstErr == nil {
			firstErr = err
		} else {
			log.Warn().Err(err).Msg("zeek: retrying parked observations failed")
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
			// Match names inside the directory rather than globbing the
			// full path: a job directory is named after a capture file and
			// may hold glob metacharacters.
			names, err := os.ReadDir(dir)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return nil, err
			}
			var paths []string
			for _, pattern := range []string{kind + ".*.log", kind + ".log"} {
				var m []string
				for _, n := range names {
					ok, err := filepath.Match(pattern, n.Name())
					if err != nil {
						return nil, err
					}
					if ok {
						m = append(m, filepath.Join(dir, n.Name()))
					}
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
				files = append(files, logFile{kind: kind, path: path, id: id, size: fi.Size(), job: dir != p.cfg.LogDir})
			}
		}
	}
	return files, nil
}

// rotatedName reports whether path is a rotated log of kind (x509.<stamp>.log)
// rather than the live one (x509.log).
func rotatedName(kind, path string) bool {
	base := filepath.Base(path)
	return base != kind+".log" && strings.HasPrefix(base, kind+".") && strings.HasSuffix(base, ".log")
}

// followsNewline reports whether the byte before offset is a newline.
func followsNewline(fh *os.File, offset int64) bool {
	var b [1]byte
	_, err := fh.ReadAt(b[:], offset-1)
	return err == nil && b[0] == '\n'
}

// readFile ingests f's complete lines from its cursor on, one batch at a
// time, saving the cursor after each. hitLimit reports that the read stopped
// at maxReadPerFile, so more of the file may be left.
func (p *Poller) readFile(ctx context.Context, f logFile, cursor map[string]cursorEntry, known map[string]bool, stats *pollStats) (hitLimit bool, err error) {
	entry := cursor[f.id]
	offset := entry.Offset
	// A reused inode whose new file is exactly the stale size is caught only
	// by the rotated-name rule; the line-boundary check below runs only when
	// there is something to read (size beyond offset).
	switch {
	case f.size < offset:
		// Truncated in place, or a new file that reused the inode.
		offset = 0
	case offset > 0 && rotatedName(f.kind, entry.Path) && entry.Path != f.path:
		// A rotated file keeps its name for good, so this id under another
		// path is a new file that reused the inode.
		offset = 0
	}
	start := offset
	cursor[f.id] = cursorEntry{Path: f.path, Offset: offset}
	if f.size == offset {
		return false, nil
	}

	fh, err := os.Open(f.path)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", f.path, err)
	}
	defer fh.Close()
	if offset > 0 && !followsNewline(fh, offset) {
		// The cursor only ever rests after a newline, so this is not the
		// file it was written for (an inode reused by a new file at least
		// as large as the old offset).
		log.Warn().Str("file", f.path).Int64("offset", offset).
			Msg("zeek: cursor is not on a line boundary; reading the file from the start")
		offset, start = 0, 0
		cursor[f.id] = cursorEntry{Path: f.path}
	}
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
		if err := p.process(ctx, f.kind, batch, known, stats, !f.job); err != nil {
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
			if limited.N == 0 && offset == start && len(batch) == 0 {
				// A whole read cap and no complete data line (comment and
				// blank lines before it do not count, so batchBytes is not
				// tested): the line is longer than the cap and can never
				// complete inside a poll. The capped read began at offset,
				// so the scan for its newline starts at offset+maxReadPerFile.
				return false, p.skipOversizedLine(ctx, f, fh, cursor, offset, stats)
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

// skipOversizedLine moves the cursor past a line that did not end within
// maxReadPerFile bytes. If its newline is not there yet (Zeek is still
// writing it) the cursor is left alone and the next poll tries again.
func (p *Poller) skipOversizedLine(ctx context.Context, f logFile, fh *os.File, cursor map[string]cursorEntry, offset int64, stats *pollStats) error {
	next, found, err := nextLineStart(fh, offset+maxReadPerFile)
	if err != nil {
		return fmt.Errorf("skip long line in %s: %w", f.path, err)
	}
	if !found {
		return nil
	}
	log.Warn().Str("file", f.path).Int64("offset", offset).Int64("bytes", next-offset).
		Msg("zeek: skipped a line longer than the read cap")
	stats.badLines++
	cursor[f.id] = cursorEntry{Path: f.path, Offset: next}
	return p.saveCursor(ctx, cursor)
}

// nextLineStart returns the offset just past the first newline at or after
// from, or found == false if the file ends first.
func nextLineStart(fh *os.File, from int64) (next int64, found bool, err error) {
	if _, err := fh.Seek(from, io.SeekStart); err != nil {
		return 0, false, err
	}
	buf := make([]byte, 64<<10)
	pos := from
	for {
		n, rerr := fh.Read(buf)
		if i := bytes.IndexByte(buf[:n], '\n'); i >= 0 {
			return pos + int64(i) + 1, true, nil
		}
		pos += int64(n)
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return pos, false, nil
			}
			return 0, false, rerr
		}
	}
}

// process handles one batch of lines. park says an ssl session whose
// certificate is not stored yet may be parked for a later poll.
func (p *Poller) process(ctx context.Context, kind string, lines [][]byte, known map[string]bool, stats *pollStats, park bool) error {
	switch kind {
	case "x509":
		return p.processX509(ctx, lines, known, stats)
	case "ssl":
		return p.processSSL(ctx, lines, known, stats, park)
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

// certDiscovery is the discovery for one x509.log record. With a certificate
// Go can parse (log-certs-base64), ingest parses it and stores every field,
// so x509.log's own fields are not sent: they would override the parsed
// values in their Zeek spelling (upper-case serial, OpenSSL algorithm
// names). Without one, or with one Go's parser rejects (OpenSSL accepts
// certificates Go does not: a negative serial, a malformed extension), the
// record's fields are all there is, and the unusable PEM is not sent.
func certDiscovery(rec *zeek.X509Record) dedup.CertDiscovery {
	fp := strings.ToLower(rec.Fingerprint)
	if rec.CertPEM != "" {
		if _, err := certparse.ParsePEM([]byte(rec.CertPEM)); err == nil {
			return dedup.CertDiscovery{FingerprintSHA256: fp, RawPEM: rec.CertPEM}
		}
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
// references its certificates by foreign key, and x509 logs are read first,
// but Zeek's x509 and ssl writers flush on their own beat, so a certificate
// may simply not have reached the disk yet. While park, such an observation
// is parked and retried by retryPending; nothing waits for it. Otherwise it is
// dropped and counted. The known observations of the batch are written with
// one call, and the unknown ones are parked only once that call has succeeded.
func (p *Poller) processSSL(ctx context.Context, lines [][]byte, known map[string]bool, stats *pollStats, park bool) error {
	var write, parked []*model.CertificateObservation
	unknown := 0
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
			switch {
			case ok:
				write = append(write, o)
			case park:
				parked = append(parked, o)
			default:
				unknown++
			}
		}
	}
	if len(write) > 0 {
		if err := p.st.BatchRecordObservations(ctx, write); err != nil {
			return fmt.Errorf("record observations: %w", err)
		}
		stats.observations += len(write)
	}
	stats.unknownCerts += unknown
	for _, o := range parked {
		if len(p.pending) >= maxPendingObs {
			p.pending = p.pending[1:]
			stats.unknownCerts++
		}
		p.pending = append(p.pending, pendingObs{obs: o, parkedAt: p.pollSeq})
	}
	return nil
}

// retryPending writes the parked observations whose certificate is stored by
// now, in one batched call, and drops those parked for maxHeldPolls polls.
// Observations parked in this poll are left alone. If the lookup or the write
// fails, the parked list is left as it was.
func (p *Poller) retryPending(ctx context.Context, known map[string]bool, stats *pollStats) error {
	keep := make([]pendingObs, 0, len(p.pending))
	var write []*model.CertificateObservation
	dropped := 0
	for _, po := range p.pending {
		if po.parkedAt >= p.pollSeq {
			keep = append(keep, po)
			continue
		}
		ok, err := p.certKnown(ctx, po.obs.CertFingerprint, known)
		if err != nil {
			return fmt.Errorf("retry parked observations: %w", err)
		}
		switch {
		case ok:
			write = append(write, po.obs)
		case p.pollSeq-po.parkedAt >= maxHeldPolls:
			dropped++
		default:
			keep = append(keep, po)
		}
	}
	if len(write) > 0 {
		if err := p.st.BatchRecordObservations(ctx, write); err != nil {
			return fmt.Errorf("record observations: %w", err)
		}
		stats.observations += len(write)
	}
	p.pending = keep
	stats.unknownCerts += dropped
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
