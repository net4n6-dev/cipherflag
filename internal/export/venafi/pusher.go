package venafi

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/cyberflag-ai/cipherflag/internal/model"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

const pushBatchSize = 100

// Pusher periodically pushes new certificates to Venafi (Cloud or TPP).
type Pusher struct {
	client   VenafiClient
	store    store.CertStore
	interval time.Duration
	logger   zerolog.Logger
}

// NewPusher creates a new Venafi push scheduler.
func NewPusher(client VenafiClient, st store.CertStore, interval time.Duration) *Pusher {
	return &Pusher{
		client:   client,
		store:    st,
		interval: interval,
		logger:   zerolog.New(zerolog.NewConsoleWriter()).With().Str("component", "venafi-pusher").Timestamp().Logger(),
	}
}

// Run starts the push loop. Blocks until ctx is cancelled.
func (p *Pusher) Run(ctx context.Context) {
	p.logger.Info().Dur("interval", p.interval).Msg("venafi push scheduler started")

	p.runCycle(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.logger.Info().Msg("venafi push scheduler stopped")
			return
		case <-ticker.C:
			p.runCycle(ctx)
		}
	}
}

func (p *Pusher) runCycle(ctx context.Context) {
	total := 0
	for {
		certs, err := p.store.GetCertsForVenafiPush(ctx, p.interval, pushBatchSize)
		if err != nil {
			p.logger.Error().Err(err).Msg("failed to query certs for push")
			return
		}
		if len(certs) == 0 {
			break
		}

		pushed, err := p.pushBatch(ctx, certs)
		total += pushed
		if err != nil {
			p.logger.Error().Err(err).Int("batch_size", len(certs)).Msg("batch push failed")
			fps := fingerprints(certs)
			if markErr := p.store.MarkVenafiPushFailure(ctx, fps); markErr != nil {
				p.logger.Error().Err(markErr).Msg("failed to mark push failures")
			}
			return
		}

		if len(certs) < pushBatchSize {
			break
		}
	}

	if total > 0 {
		p.logger.Info().Int("pushed", total).Msg("venafi push cycle complete")
	}
}

func (p *Pusher) pushBatch(ctx context.Context, certs []model.Certificate) (int, error) {
	fps := fingerprints(certs)

	observations, err := p.store.GetLatestObservationsForCerts(ctx, fps)
	if err != nil {
		p.logger.Warn().Err(err).Msg("failed to get observations, pushing without endpoint metadata")
		observations = map[string]*model.CertificateObservation{}
	}

	imports := buildCertImports(certs, observations)

	result, err := p.client.ImportCertificates(ctx, imports)
	if err != nil {
		return 0, err
	}

	for _, w := range result.Warnings {
		p.logger.Warn().Str("warning", w).Msg("venafi import warning")
	}

	if markErr := p.store.MarkVenafiPushSuccess(ctx, fps); markErr != nil {
		p.logger.Error().Err(markErr).Msg("failed to mark push success")
	}

	p.logger.Debug().
		Int("imported", result.Imported).
		Int("updated", result.Updated).
		Int("existed", result.Existed).
		Int("failed", result.Failed).
		Msg("batch pushed to venafi")

	return len(certs), nil
}

func buildCertImports(certs []model.Certificate, observations map[string]*model.CertificateObservation) []CertImport {
	imports := make([]CertImport, 0, len(certs))
	for _, cert := range certs {
		ci := CertImport{
			PEM:         cert.RawPEM,
			Fingerprint: cert.FingerprintSHA256,
		}
		if obs, ok := observations[cert.FingerprintSHA256]; ok {
			ci.ServerName = obs.ServerName
			ci.ServerIP = obs.ServerIP
			ci.ServerPort = obs.ServerPort
			ci.TLSVersion = string(obs.NegotiatedVersion)
		}
		imports = append(imports, ci)
	}
	return imports
}

func fingerprints(certs []model.Certificate) []string {
	fps := make([]string, len(certs))
	for i, c := range certs {
		fps[i] = c.FingerprintSHA256
	}
	return fps
}
