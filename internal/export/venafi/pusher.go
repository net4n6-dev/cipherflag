package venafi

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

const pushBatchSize = 100

// defaultPollInterval is the minimum tick interval used when push is disabled
// or when PushIntervalMinutes is zero/unset.
const defaultPollInterval = 5 * time.Minute

// Pusher periodically pushes new certificates to Venafi (Cloud or TPP).
// It reads configuration live each cycle via a LiveConfig, so changes applied
// via LiveConfig.Set take effect without a restart.
//
// The pusher is always-on (started unconditionally at boot) so that
// enable/disable and credential changes hot-reload without a process restart.
// Each cycle it checks LiveConfig.Enabled and skips if false.
type Pusher struct {
	live   *LiveConfig
	store  store.CertStore
	logger zerolog.Logger

	// buildClient overrides client construction in tests; nil → BuildClient.
	// This lets unit tests inject a fake client without making real network
	// calls to api.venafi.cloud or a TPP instance.
	buildClient func(config.VenafiExportConfig) (VenafiClient, error)
}

// NewPusher creates a new Venafi push scheduler driven by the live config.
func NewPusher(live *LiveConfig, st store.CertStore) *Pusher {
	return &Pusher{
		live:   live,
		store:  st,
		logger: zerolog.New(zerolog.NewConsoleWriter()).With().Str("component", "venafi-pusher").Timestamp().Logger(),
	}
}

// Run starts the push loop. Blocks until ctx is cancelled. The pusher is
// always running; it self-gates on LiveConfig.Enabled each iteration.
func (p *Pusher) Run(ctx context.Context) {
	p.logger.Info().Msg("venafi push scheduler started (hot-reload mode)")

	// Immediate first cycle.
	p.runCycleFromLive(ctx)

	effectiveInterval := p.tickInterval()
	ticker := time.NewTicker(effectiveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.logger.Info().Msg("venafi push scheduler stopped")
			return
		case <-ticker.C:
			p.runCycleFromLive(ctx)
			// Re-arm ticker if the effective interval has changed (operator
			// updated push_interval_minutes via the API while running).
			if next := p.tickInterval(); next != effectiveInterval {
				ticker.Reset(next)
				effectiveInterval = next
			}
		}
	}
}

// tickInterval returns the current push interval, floored at defaultPollInterval.
func (p *Pusher) tickInterval() time.Duration {
	v := p.live.Snapshot()
	d := time.Duration(v.PushIntervalMinutes) * time.Minute
	if d < defaultPollInterval {
		return defaultPollInterval
	}
	return d
}

// clientFor constructs a VenafiClient from the given config, using the
// injected buildClient factory when set (tests), or the package BuildClient
// otherwise.
func (p *Pusher) clientFor(v config.VenafiExportConfig) (VenafiClient, error) {
	if p.buildClient != nil {
		return p.buildClient(v)
	}
	return BuildClient(v)
}

// runCycleFromLive reads the live config, gates on Enabled, builds a client,
// and delegates to runCycle. This is the hot-reload entrypoint called by Run.
func (p *Pusher) runCycleFromLive(ctx context.Context) {
	v := p.live.Snapshot()
	if !v.Enabled {
		return
	}

	client, err := p.clientFor(v)
	if err != nil {
		p.logger.Error().Err(err).Msg("venafi: skipping push cycle — could not build client")
		return
	}

	interval := time.Duration(v.PushIntervalMinutes) * time.Minute
	if interval < defaultPollInterval {
		interval = defaultPollInterval
	}

	p.runCycle(ctx, client, interval)
}

// runCycle executes one push iteration using the provided client and lookback interval.
func (p *Pusher) runCycle(ctx context.Context, client VenafiClient, interval time.Duration) {
	total := 0
	for {
		certs, err := p.store.GetCertsForVenafiPush(ctx, interval, pushBatchSize)
		if err != nil {
			p.logger.Error().Err(err).Msg("failed to query certs for push")
			return
		}
		if len(certs) == 0 {
			break
		}

		pushed, err := p.pushBatch(ctx, client, certs)
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

func (p *Pusher) pushBatch(ctx context.Context, client VenafiClient, certs []model.Certificate) (int, error) {
	fps := fingerprints(certs)

	observations, err := p.store.GetLatestObservationsForCerts(ctx, fps)
	if err != nil {
		p.logger.Warn().Err(err).Msg("failed to get observations, pushing without endpoint metadata")
		observations = map[string]*model.CertificateObservation{}
	}

	imports := buildCertImports(certs, observations)

	result, err := client.ImportCertificates(ctx, imports)
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
