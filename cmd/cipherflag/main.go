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

	"github.com/net4n6-dev/cipherflag/internal/api"
	"github.com/net4n6-dev/cipherflag/internal/auth"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/venafi"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	if len(os.Args) < 2 {
		fmt.Println("Usage: cipherflag <command> [options]")
		fmt.Println("Commands: serve, migrate, seed, setup")
		os.Exit(1)
	}

	if os.Args[1] == "setup" {
		runSetup()
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

	if cfg.Sources.ZeekFile.Enabled {
		pollerCtx, pollerCancel := context.WithCancel(ctx)
		defer pollerCancel()
		poller := ingest.NewPoller(
			cfg.Sources.ZeekFile.LogDir,
			st,
			time.Duration(cfg.Sources.ZeekFile.PollIntervalSeconds)*time.Second,
		)
		go poller.Run(pollerCtx)
		log.Info().Str("dir", cfg.Sources.ZeekFile.LogDir).Msg("zeek log poller started")

		pcapMgr := ingest.NewPCAPJobManager(cfg.Sources.ZeekFile.LogDir, st, poller)
		go pcapMgr.Run(pollerCtx)
	}

	// Venafi push scheduler
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
			authBase := cfg.Export.Venafi.BaseURL
			sdkBase := cfg.Export.Venafi.BaseURL
			if len(authBase) > 6 && authBase[len(authBase)-6:] == "vedsdk" {
				authBase = authBase[:len(authBase)-6] + "vedauth"
			} else {
				sdkBase = authBase + "/vedsdk"
				authBase = authBase + "/vedauth"
			}
			tppClient := venafi.NewClient(sdkBase, authBase, cfg.Export.Venafi.ClientID, cfg.Export.Venafi.RefreshToken)
			venafiClient = venafi.NewTPPAdapter(tppClient, cfg.Export.Venafi.Folder)
			log.Info().
				Str("platform", "tpp").
				Str("base_url", cfg.Export.Venafi.BaseURL).
				Msg("venafi tpp client configured")
		}

		pusher := venafi.NewPusher(venafiClient, st, venafiInterval)
		go pusher.Run(pushCtx)
		log.Info().
			Int("interval_min", cfg.Export.Venafi.PushIntervalMinutes).
			Msg("venafi push scheduler started")
	}

	jwtSecret := auth.GenerateSecret(cfg.Storage.PostgresURL)
	router := api.NewRouter(st, cfg, configPath, cfg.Server.FrontendURL, cfg.PCAP.InputDir, cfg.PCAP.MaxFileSizeMB, jwtSecret)

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
		srv.Shutdown(shutCtx)
	}()

	log.Info().Str("addr", cfg.Server.Listen).Msg("CipherFlag API server starting")
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
