package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/internal/app"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/logging"
)

var (
	configPath  = flag.String("config", "", "Path to config file")
	verbose     = flag.Bool("verbose", false, "Enable verbose logging")
	oneShot     = flag.Bool("one-shot", false, "Run once and exit")
	showVersion = flag.Bool("version", false, "Show version and exit")
)

// Version information (set during build)
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		fmt.Printf("Drift Detector version %s\n", Version)
		fmt.Printf("Build time: %s\n", BuildTime)
		fmt.Printf("Git commit: %s\n", GitCommit)
		os.Exit(0)
	}

	// Configure initial logging
	logLevel := logging.InfoLevel
	if *verbose {
		logLevel = logging.DebugLevel
	}

	logger := logging.New(logging.Config{
		Level:  logLevel,
		Output: os.Stdout,
	})
	logging.SetGlobalLogger(logger)

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Fatal(err, "Failed to load configuration")
	}

	// Override config with command line flags
	if *verbose {
		cfg.Logging.Level = "debug"
	}

	if *oneShot {
		cfg.Scheduler.Enabled = false
	}

	// Create application
	app, err := app.NewApp(cfg)
	if err != nil {
		logger.Fatal(err, "Failed to create application")
	}

	// Run in one-shot mode
	if *oneShot {
		logger.Info("Running in one-shot mode")
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		
		drifts, err := app.RunManualDriftDetection(ctx)
		if err != nil {
			logger.Fatal(err, "Manual drift detection failed")
		}
		
		logger.Info("Detected %d drifts", len(drifts))
		
		for i, drift := range drifts {
			logger.Info("Drift %d: %s %s (%s) - %s",
				i+1, drift.ResourceType, drift.ResourceName, drift.ResourceID, drift.DriftType)
		}
		
		os.Exit(0)
	}

	// Start application
	if err := app.Start(); err != nil {
		logger.Fatal(err, "Application failed")
	}
}