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

	"github.com/cyberflag-ai/cipherflag/internal/api"
	"github.com/cyberflag-ai/cipherflag/internal/config"
	"github.com/cyberflag-ai/cipherflag/internal/ingest"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	if len(os.Args) < 2 {
		fmt.Println("Usage: cipherflag <command> [options]")
		fmt.Println("Commands: serve, migrate, seed")
		os.Exit(1)
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
		runServe(ctx, cfg)
	case "migrate":
		runMigrate(ctx, cfg)
	case "seed":
		runSeed(ctx, cfg)
	default:
		log.Fatal().Str("command", os.Args[1]).Msg("unknown command")
	}
}

func runServe(ctx context.Context, cfg *config.Config) {
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

	router := api.NewRouter(st, cfg.Server.FrontendURL, cfg.PCAP.InputDir, cfg.PCAP.MaxFileSizeMB)

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
