package ingest

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/ingest/zeek"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// FindCompletedPCAPJobs scans logDir for subdirectories that contain a ".done"
// sentinel file, indicating that Zeek has finished processing that PCAP.
// It returns a list of job IDs (the directory names).
func FindCompletedPCAPJobs(logDir string) []string {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		log.Warn().Err(err).Str("dir", logDir).Msg("failed to read pcap log directory")
		return nil
	}

	var completed []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sentinel := filepath.Join(logDir, e.Name(), ".done")
		if _, err := os.Stat(sentinel); err == nil {
			completed = append(completed, e.Name())
		}
	}
	return completed
}

// PCAPJobManager polls for completed PCAP processing jobs and ingests the
// resulting Zeek logs.
type PCAPJobManager struct {
	logDir string
	store  store.CertStore
	poller *Poller
}

// NewPCAPJobManager creates a new PCAPJobManager.
func NewPCAPJobManager(logDir string, st store.CertStore, poller *Poller) *PCAPJobManager {
	return &PCAPJobManager{
		logDir: logDir,
		store:  st,
		poller: poller,
	}
}

// Run starts the PCAP job check loop, polling every 5 seconds until the
// context is cancelled.
func (m *PCAPJobManager) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("pcap job manager stopped")
			return
		case <-ticker.C:
			m.checkJobs(ctx)
		}
	}
}

func (m *PCAPJobManager) checkJobs(ctx context.Context) {
	completedIDs := FindCompletedPCAPJobs(m.logDir)

	for _, jobID := range completedIDs {
		job, err := m.store.GetPCAPJob(ctx, jobID)
		if err != nil {
			log.Error().Err(err).Str("job_id", jobID).Msg("failed to get pcap job")
			continue
		}
		if job == nil {
			continue
		}
		if job.Status == "complete" || job.Status == "failed" {
			continue
		}

		// Mark as processing.
		job.Status = "processing"
		if err := m.store.UpdatePCAPJob(ctx, job); err != nil {
			log.Error().Err(err).Str("job_id", jobID).Msg("failed to update pcap job status")
			continue
		}

		jobLogDir := filepath.Join(m.logDir, jobID)
		found, newCerts := m.ingestJobLogs(ctx, jobLogDir)

		now := time.Now()
		job.Status = "complete"
		job.CertsFound = found
		job.CertsNew = newCerts
		job.CompletedAt = &now

		if err := m.store.UpdatePCAPJob(ctx, job); err != nil {
			log.Error().Err(err).Str("job_id", jobID).Msg("failed to update pcap job on completion")
			continue
		}

		log.Info().
			Str("job_id", jobID).
			Int("certs_found", found).
			Int("certs_new", newCerts).
			Msg("pcap job completed")
	}
}

func (m *PCAPJobManager) ingestJobLogs(ctx context.Context, jobLogDir string) (found, newCerts int) {
	// Process x509.log
	x509Path := filepath.Join(jobLogDir, "x509.log")
	x509Entries, _, err := ReadLogEntries(x509Path, 0)
	if err != nil {
		log.Error().Err(err).Str("path", x509Path).Msg("failed to read x509 log from pcap job")
		return 0, 0
	}

	found = len(x509Entries)

	// Count new certs by checking existence before ingestion.
	for _, raw := range x509Entries {
		rec, err := zeek.ParseX509Record(raw)
		if err != nil || rec.Fingerprint == "" {
			continue
		}
		existing, err := m.store.GetCertificate(ctx, rec.Fingerprint)
		if err == nil && existing == nil {
			newCerts++
		}
	}

	if len(x509Entries) > 0 {
		m.poller.ProcessX509Entries(ctx, x509Entries)
	}

	// Process ssl.log if present.
	sslPath := filepath.Join(jobLogDir, "ssl.log")
	sslEntries, _, err := ReadLogEntries(sslPath, 0)
	if err != nil {
		log.Warn().Err(err).Str("path", sslPath).Msg("failed to read ssl log from pcap job")
		return found, newCerts
	}
	if len(sslEntries) > 0 {
		m.poller.ProcessSSLEntries(ctx, sslEntries)
	}

	return found, newCerts
}
