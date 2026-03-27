package venafi

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/rs/zerolog"

	"github.com/cyberflag-ai/cipherflag/internal/model"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

const pushBatchSize = 100

// Pusher periodically pushes new certificates to Venafi TPP.
type Pusher struct {
	client   *Client
	store    store.CertStore
	folder   string
	interval time.Duration
	logger   zerolog.Logger
}

// NewPusher creates a new Venafi push scheduler.
func NewPusher(client *Client, st store.CertStore, folder string, interval time.Duration) *Pusher {
	return &Pusher{
		client:   client,
		store:    st,
		folder:   folder,
		interval: interval,
		logger:   zerolog.New(zerolog.NewConsoleWriter()).With().Str("component", "venafi-pusher").Timestamp().Logger(),
	}
}

// Run starts the push loop. Blocks until ctx is cancelled.
func (p *Pusher) Run(ctx context.Context) {
	p.logger.Info().Dur("interval", p.interval).Msg("venafi push scheduler started")

	// Run immediately on start, then on interval
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
			fps := make([]string, len(certs))
			for i, c := range certs {
				fps[i] = c.FingerprintSHA256
			}
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
	fps := make([]string, len(certs))
	for i, c := range certs {
		fps[i] = c.FingerprintSHA256
	}

	observations, err := p.store.GetLatestObservationsForCerts(ctx, fps)
	if err != nil {
		p.logger.Warn().Err(err).Msg("failed to get observations, pushing without endpoint metadata")
		observations = map[string]*model.CertificateObservation{}
	}

	request := p.buildDiscoveryPayload(certs, observations)

	resp, err := p.client.ImportDiscovery(ctx, request)
	if err != nil {
		return 0, err
	}

	for _, w := range resp.Warnings {
		p.logger.Warn().Str("warning", w).Msg("venafi import warning")
	}

	if markErr := p.store.MarkVenafiPushSuccess(ctx, fps); markErr != nil {
		p.logger.Error().Err(markErr).Msg("failed to mark push success")
	}

	p.logger.Debug().
		Int("created_certs", resp.CreatedCertificates).
		Int("updated_certs", resp.UpdatedCertificates).
		Int("created_instances", resp.CreatedInstances).
		Int("warnings", len(resp.Warnings)).
		Msg("batch pushed to venafi")

	return len(certs), nil
}

func (p *Pusher) buildDiscoveryPayload(certs []model.Certificate, observations map[string]*model.CertificateObservation) *DiscoveryImportRequest {
	request := &DiscoveryImportRequest{
		ZoneName:  p.folder,
		Endpoints: make([]DiscoveryEndpoint, 0, len(certs)),
	}

	for _, cert := range certs {
		encoded := base64.StdEncoding.EncodeToString([]byte(cert.RawPEM))

		endpoint := DiscoveryEndpoint{
			Certificates: []DiscoveryCert{
				{
					Certificate: encoded,
					Fingerprint: cert.FingerprintSHA256,
				},
			},
		}

		if obs, ok := observations[cert.FingerprintSHA256]; ok {
			endpoint.Host = obs.ServerName
			if endpoint.Host == "" {
				endpoint.Host = obs.ServerIP
			}
			endpoint.IP = obs.ServerIP
			endpoint.Port = obs.ServerPort
			endpoint.Protocols = []DiscoveryProto{
				{
					Certificates: []string{cert.FingerprintSHA256},
					Protocol:     string(obs.NegotiatedVersion),
				},
			}
		}

		request.Endpoints = append(request.Endpoints, endpoint)
	}

	return request
}
