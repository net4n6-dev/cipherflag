package ingest

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/analysis"
	"github.com/net4n6-dev/cipherflag/internal/ingest/zeek"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// ReadLogEntries reads log lines from path starting at the given byte offset.
// It skips empty lines and comment lines (starting with '#'). Each returned
// entry is an independent copy of the line bytes. The new file offset is
// returned so the caller can resume from where it left off.
// If the file does not exist, (nil, 0, nil) is returned.
func ReadLogEntries(path string, offset int64) ([][]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("open log file %s: %w", path, err)
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, 0, fmt.Errorf("seek in %s: %w", path, err)
		}
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1 MB buffer

	var entries [][]byte
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		entry := make([]byte, len(line))
		copy(entry, line)
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("scan %s: %w", path, err)
	}

	// Determine the new offset.
	newOffset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, 0, fmt.Errorf("tell %s: %w", path, err)
	}

	return entries, newOffset, nil
}

// Poller watches a Zeek log directory for new x509 and ssl log entries and
// ingests them into the certificate store.
type Poller struct {
	logDir   string
	store    store.CertStore
	interval time.Duration
}

// NewPoller creates a new Poller that watches logDir at the given interval.
func NewPoller(logDir string, st store.CertStore, interval time.Duration) *Poller {
	return &Poller{
		logDir:   logDir,
		store:    st,
		interval: interval,
	}
}

// Run starts the polling loop. It performs one immediate poll, then polls on
// every tick until the context is cancelled.
func (p *Poller) Run(ctx context.Context) {
	p.poll(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("poller stopped")
			return
		case <-ticker.C:
			p.poll(ctx)
		}
	}
}

func (p *Poller) poll(ctx context.Context) {
	p.pollLogFile(ctx, "x509")
	p.pollLogFile(ctx, "ssl")
}

func (p *Poller) pollLogFile(ctx context.Context, logType string) {
	pattern := filepath.Join(p.logDir, logType+".log")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Error().Err(err).Str("pattern", pattern).Msg("glob failed")
		return
	}

	for _, path := range matches {
		sourceName := "zeek_file:" + path

		var offset int64
		state, err := p.store.GetIngestionState(ctx, sourceName)
		if err != nil {
			log.Error().Err(err).Str("source", sourceName).Msg("failed to get ingestion state")
			continue
		}
		if state != nil {
			offset, _ = strconv.ParseInt(state.Cursor, 10, 64)
		}

		entries, newOffset, err := ReadLogEntries(path, offset)
		if err != nil {
			log.Error().Err(err).Str("path", path).Msg("failed to read log entries")
			continue
		}

		if len(entries) == 0 {
			continue
		}

		switch logType {
		case "x509":
			p.ProcessX509Entries(ctx, entries)
		case "ssl":
			p.ProcessSSLEntries(ctx, entries)
		}

		// Persist the new cursor.
		if err := p.store.SetIngestionState(ctx, &model.IngestionState{
			SourceName: sourceName,
			Cursor:     strconv.FormatInt(newOffset, 10),
		}); err != nil {
			log.Error().Err(err).Str("source", sourceName).Msg("failed to save ingestion state")
		}

		log.Debug().
			Str("path", path).
			Int("entries", len(entries)).
			Int64("offset", newOffset).
			Msg("polled log file")
	}
}

// ProcessX509Entries parses Zeek x509 log entries, upserts certificates, and
// scores each one.
func (p *Poller) ProcessX509Entries(ctx context.Context, entries [][]byte) {
	var certs []*model.Certificate

	for _, raw := range entries {
		rec, err := zeek.ParseX509Record(raw)
		if err != nil {
			log.Warn().Err(err).Msg("failed to parse x509 record")
			continue
		}
		if rec.Fingerprint == "" {
			continue
		}

		cert := zeek.MapX509ToCertificate(rec)
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return
	}

	if err := p.store.BatchUpsertCertificates(ctx, certs); err != nil {
		log.Error().Err(err).Int("count", len(certs)).Msg("failed to batch upsert certificates")
		return
	}

	// Score each certificate and save the health report.
	for _, cert := range certs {
		report := analysis.ScoreCertificate(cert)
		if err := p.store.SaveHealthReport(ctx, report); err != nil {
			log.Warn().Err(err).Str("fp", cert.FingerprintSHA256).Msg("failed to save health report")
		}
	}

	log.Info().Int("count", len(certs)).Msg("ingested x509 certificates")
}

// ProcessSSLEntries parses Zeek ssl log entries and records observations. It
// pre-filters observations to only include those referencing certificates that
// already exist in the store (preventing FK violations).
func (p *Poller) ProcessSSLEntries(ctx context.Context, entries [][]byte) {
	var observations []*model.CertificateObservation

	for _, raw := range entries {
		rec, err := zeek.ParseSSLRecord(raw)
		if err != nil {
			log.Warn().Err(err).Msg("failed to parse ssl record")
			continue
		}

		obs := zeek.MapSSLToObservations(rec)

		// Pre-filter: only keep observations for certs that exist.
		for _, o := range obs {
			existing, err := p.store.GetCertificate(ctx, o.CertFingerprint)
			if err != nil {
				log.Warn().Err(err).Str("fp", o.CertFingerprint).Msg("failed to check cert existence")
				continue
			}
			if existing != nil {
				observations = append(observations, o)
			}
		}
	}

	if len(observations) == 0 {
		return
	}

	if err := p.store.BatchRecordObservations(ctx, observations); err != nil {
		log.Error().Err(err).Int("count", len(observations)).Msg("failed to batch record observations")
		return
	}

	log.Info().Int("count", len(observations)).Msg("recorded ssl observations")
}
