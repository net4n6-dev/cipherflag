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

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/analysis/scoring"
	"github.com/net4n6-dev/cipherflag/internal/api"
	"github.com/net4n6-dev/cipherflag/internal/auth"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
	"github.com/net4n6-dev/cipherflag/internal/export/venafi"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/defender"
	"github.com/net4n6-dev/cipherflag/internal/ingest/observcache"
	"github.com/net4n6-dev/cipherflag/internal/ingest/sentinelone"
	"github.com/net4n6-dev/cipherflag/internal/ingest/tanium"
	"github.com/net4n6-dev/cipherflag/internal/scanner/cachegc"
	scanscheduler "github.com/net4n6-dev/cipherflag/internal/scanner/scheduler"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// Version is the CipherFlag CE release version. Set at build time via
// -ldflags "-X main.Version=2.0.0"; defaults to the in-source constant
// for development builds.
const Version = "2.0.0"

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	if len(os.Args) < 2 {
		fmt.Println("CipherFlag CE", Version)
		fmt.Println("Usage: cipherflag <command> [options]")
		fmt.Println("Commands: serve, migrate, seed, setup,")
		fmt.Println("          declared-cas, application-metadata, ownership,")
		fmt.Println("          scan-truststore,")
		fmt.Println("          generate-signing-key, sign-cbom, verify-cbom,")
		fmt.Println("          version")
		os.Exit(1)
	}

	if os.Args[1] == "setup" {
		runSetup()
		return
	}

	// Subcommands that do not require config / DB.
	switch os.Args[1] {
	case "version":
		fmt.Println("CipherFlag CE", Version)
		return
	case "generate-signing-key":
		cliGenerateSigningKey(context.Background())
		return
	case "sign-cbom":
		cliSignCBOM(context.Background())
		return
	case "verify-cbom":
		cliVerifyCBOM(context.Background())
		return
	}

	configPath := "config/cipherflag.toml"
	if envPath := os.Getenv("CIPHERFLAG_CONFIG"); envPath != "" {
		configPath = envPath
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	ctx := context.Background()

	switch os.Args[1] {
	case "serve":
		runServe(ctx, cfg, configPath)
	case "migrate":
		runMigrate(ctx, cfg)
	case "seed":
		runSeed(ctx, cfg)
	case "declared-cas":
		runDeclaredCAs(ctx, cfg)
	case "application-metadata":
		runApplicationMetadata(ctx, cfg)
	case "ownership":
		runOwnership(ctx, cfg)
	case "scan-truststore":
		runScanTruststore(ctx, cfg, os.Args[2:])
		return
	default:
		log.Fatal().Str("command", os.Args[1]).Msg("unknown command")
	}
}

func runServe(ctx context.Context, cfg *config.Config, configPath string) {
	st, err := store.NewPostgresStore(ctx, cfg.Storage.PostgresURL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer st.Close()

	// Auto-migrate on start
	if err := st.Migrate(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to run migrations")
	}

	// Build the intake observation cache. Shared across CE ingest paths.
	// If dedup is disabled in config, New returns a no-op cache that
	// produces byte-identical behaviour to pre-cache ingestion.
	shortestPollInterval := computeShortestPollInterval(cfg)
	attritionThreshold := observcache.ShortestAttritionThreshold(cfg.Attrition, shortestPollInterval)
	sharedCache := observcache.New(cfg.Intake.Dedup, attritionThreshold)
	log.Info().
		Bool("enabled", cfg.Intake.Dedup.Enabled).
		Int("ttl_seconds", cfg.Intake.Dedup.TTLSeconds).
		Int("max_entries", cfg.Intake.Dedup.MaxEntries).
		Dur("attrition_threshold", attritionThreshold).
		Msg("intake observation cache configured")

	var scorer scoring.Scorer = scoring.NewNoopScorer()

	// Layer 5.1: CBOM runtime — built before scorer so the callback
	// can reference it.
	var cbomRuntime *cbom.Runtime
	if cfg.CBOM.Enabled {
		cbomRuntime = cbom.NewRuntime(st, &cfg.CBOM)
		log.Info().
			Int("scopes", len(cfg.CBOM.Scopes)).
			Bool("event_push", cfg.CBOM.EventPushEnabled).
			Msg("cbom runtime constructed")
	}

	if cfg.Analysis.ScorerEnabled {
		scorerOpts := []scoring.DispatcherOption{}
		if cbomRuntime != nil && cfg.CBOM.EventPushEnabled {
			scorerOpts = append(scorerOpts, scoring.WithScoredCallback(cbomRuntime.NotifyAssetScored))
		}
		scorer = scoring.NewDispatcher(st, scorerOpts...)
		log.Info().Msg("scoring enabled (dispatcher constructed)")

		sweepCtx, sweepCancel := context.WithCancel(ctx)
		defer sweepCancel()
		interval := time.Duration(cfg.Analysis.RecheckIntervalHours) * time.Hour
		sweeper := scoring.NewSweeper(st, scorer, interval, cfg.Analysis.RuleSweepBatchSize)
		go sweeper.Run(sweepCtx)
		log.Info().
			Dur("interval", interval).
			Int("batch_size", cfg.Analysis.RuleSweepBatchSize).
			Msg("scoring sweeper started")
	}

	// Layer 6.1b-4: scan scheduler goroutine.
	{
		schedCtx, schedCancel := context.WithCancel(ctx)
		defer schedCancel()
		sched := &scanscheduler.Scheduler{Store: st}
		go sched.Run(schedCtx)
		log.Info().Msg("scan scheduler running")
	}

	// Layer 6.1b-4: cache GC goroutine. RuleVersion matches the scanner's
	// active rule version; PromptContentHash is unused in CE (no LLM path).
	{
		cacheGCCtx, cacheGCCancel := context.WithCancel(ctx)
		defer cacheGCCancel()
		gc := &cachegc.Sweeper{Store: st, RuleVersion: "v3", PromptContentHash: ""}
		go gc.Run(cacheGCCtx)
		log.Info().Msg("cache GC running")
	}

	// Start CBOM runtime goroutines (after scorer is wired).
	if cbomRuntime != nil {
		cbomCtx, cbomCancel := context.WithCancel(ctx)
		defer cbomCancel()
		cbomRuntime.Start(cbomCtx)
		log.Info().
			Dur("push_interval", cfg.CBOM.PushInterval).
			Dur("min_emit_interval", cfg.CBOM.MinEmitInterval).
			Msg("cbom runtime started")
	}

	// Venafi push scheduler (Layer 3 export connector).
	// Disabled by default; enabled via cfg.Export.Venafi.Enabled.
	venafiInterval := time.Duration(cfg.Export.Venafi.PushIntervalMinutes) * time.Minute
	if cfg.Export.Venafi.Enabled {
		pushCtx, pushCancel := context.WithCancel(ctx)
		defer pushCancel()

		var venafiClient venafi.VenafiClient

		if cfg.Export.Venafi.Platform == "cloud" {
			venafiClient = venafi.NewCloudClient(cfg.Export.Venafi.Region, cfg.Export.Venafi.APIKey)
			log.Info().
				Str("platform", "cloud").
				Str("region", cfg.Export.Venafi.Region).
				Msg("venafi cloud client configured")
		} else {
			sdkBase, authBase := venafi.NormalizeTPPBaseURLs(cfg.Export.Venafi.BaseURL)
			tppClient := venafi.NewClient(sdkBase, authBase, cfg.Export.Venafi.ClientID, cfg.Export.Venafi.RefreshToken)
			venafiClient = venafi.NewTPPAdapter(tppClient, cfg.Export.Venafi.Folder)
			log.Info().
				Str("platform", "tpp").
				Str("base_url", cfg.Export.Venafi.BaseURL).
				Msg("venafi tpp client configured")
		}

		pusher := venafi.NewPusher(venafiClient, st, venafiInterval)
		go pusher.Run(pushCtx)
	}

	// CE-flavor: the Zeek log-file ingest poller
	// (internal/ingest/poller.go) and the legacy PCAP job manager
	// (internal/ingest/pcap.go) were excluded from the Phase 1 manifest.
	// CE captures certificate / SSH / library / config evidence through
	// the osquery webhook + native scanners + git repo scanner. Zeek log
	// ingest can be re-enabled in a follow-up minor; the unified ingester
	// + scorer wiring below stays generic enough to accept it.

	// Microsoft Defender for Endpoint connector (off by default).
	if cfg.Sources.Defender.Enabled {
		dfClient, err := defender.NewClient(defender.Config{
			TenantID:     cfg.Sources.Defender.TenantID,
			ClientID:     cfg.Sources.Defender.ClientID,
			ClientSecret: cfg.Sources.Defender.ClientSecret,
			APIBaseURL:   cfg.Sources.Defender.APIBaseURL,
			HTTPTimeout:  time.Duration(cfg.Sources.Defender.HTTPTimeoutSeconds) * time.Second,
		})
		if err != nil {
			log.Fatal().Err(err).Msg("failed to init defender client")
		}
		defer dfClient.Close()
		dfIngester := ingest.NewUnifiedIngester(st, ingest.WithObservationCache(sharedCache), ingest.WithScorer(scorer))
		dfPoller := defender.NewPoller(dfClient, dfIngester, st, cfg.Sources.Defender)
		go dfPoller.Run(ctx)
		log.Info().Str("tenant_id", cfg.Sources.Defender.TenantID).Msg("defender poller started")
	}

	// SentinelOne endpoint connector (off by default).
	if cfg.Sources.SentinelOne.Enabled {
		s1Ctx, s1Cancel := context.WithCancel(ctx)
		defer s1Cancel()

		s1Client, err := sentinelone.NewClient(sentinelone.Config{
			APIToken:    cfg.Sources.SentinelOne.APIToken,
			ConsoleURL:  cfg.Sources.SentinelOne.ConsoleURL,
			HTTPTimeout: time.Duration(cfg.Sources.SentinelOne.HTTPTimeoutSeconds) * time.Second,
		})
		if err != nil {
			log.Fatal().Err(err).Msg("failed to init sentinelone client")
		}
		defer s1Client.Close()

		s1Ingester := ingest.NewUnifiedIngester(st, ingest.WithObservationCache(sharedCache), ingest.WithScorer(scorer))
		s1Poller, err := sentinelone.NewPoller(s1Client, s1Ingester, st, cfg.Sources.SentinelOne)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to init sentinelone poller")
		}
		go s1Poller.Run(s1Ctx)
		log.Info().Str("console_url", cfg.Sources.SentinelOne.ConsoleURL).Msg("sentinelone poller started")
	}

	jwtSecret := auth.GenerateSecret(cfg.Storage.PostgresURL)
	router := api.NewRouter(st, cfg, configPath, cfg.Server.FrontendURL, jwtSecret, sharedCache, scorer)

	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		log.Info().Msg("shutting down...")
		shutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Info().Str("addr", cfg.Server.Listen).Str("version", Version).Msg("CipherFlag CE API server starting")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal().Err(err).Msg("server error")
	}
}

func runMigrate(ctx context.Context, cfg *config.Config) {
	st, err := store.NewPostgresStore(ctx, cfg.Storage.PostgresURL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer st.Close()

	if err := st.Migrate(ctx); err != nil {
		log.Fatal().Err(err).Msg("migration failed")
	}
	log.Info().Msg("migrations applied successfully")
}

func runSeed(ctx context.Context, cfg *config.Config) {
	st, err := store.NewPostgresStore(ctx, cfg.Storage.PostgresURL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer st.Close()

	if err := st.Migrate(ctx); err != nil {
		log.Fatal().Err(err).Msg("migration failed")
	}

	if err := seedData(ctx, st); err != nil {
		log.Fatal().Err(err).Msg("seeding failed")
	}
	log.Info().Msg("seed data loaded successfully")
}

// runSetup prints a CE-flavor startup banner. The EE interactive
// setup wizard (which configures Venafi push, AI license, endpoint
// adapters, etc.) is not present in CE. CE setup is config-file driven:
// edit config/cipherflag.toml then run `cipherflag migrate && cipherflag serve`.
func runSetup() {
	fmt.Println("CipherFlag CE", Version)
	fmt.Println()
	fmt.Println("CE setup is configuration-driven. Quick-start:")
	fmt.Println()
	fmt.Println("  1. Copy config/cipherflag.toml.example to config/cipherflag.toml")
	fmt.Println("  2. Set [storage] postgres_url to your Postgres DSN")
	fmt.Println("  3. Run: cipherflag migrate")
	fmt.Println("  4. Run: cipherflag serve")
	fmt.Println()
	fmt.Println("For the docker-compose-based smoke deploy:")
	fmt.Println()
	fmt.Println("  docker-compose up -d")
	fmt.Println()
	fmt.Println("See README.md and CHANGELOG.md for the full v2.0 feature set.")
}

// seedData is a CE-flavor placeholder. The EE seed/ package (synthetic
// hosts, scan jobs, ai_ledger, teams, blast-radius fixtures) is not
// included in CE — those tables back EE-only features. Operators
// populate the CE database through real ingest paths (osquery webhook,
// Zeek logs, native scanners, git repo scanner).
func seedData(_ context.Context, _ *store.PostgresStore) error {
	log.Info().Msg("seedData: CE has no built-in seed dataset; use the live ingest paths (osquery, Zeek, scanners) to populate.")
	return nil
}

// computeShortestPollInterval returns the smallest poll interval across
// enabled CE-bound ingest sources. Used to derive cycle-based attrition
// thresholds. Zero means no source is enabled — cycle-based thresholds
// are skipped.
func computeShortestPollInterval(cfg *config.Config) time.Duration {
	shortest := time.Duration(0)
	maybe := func(seconds int) {
		if seconds <= 0 {
			return
		}
		d := time.Duration(seconds) * time.Second
		if shortest == 0 || d < shortest {
			shortest = d
		}
	}
	if cfg.Sources.ZeekFile.Enabled {
		maybe(cfg.Sources.ZeekFile.PollIntervalSeconds)
	}
	return shortest
}
