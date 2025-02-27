package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/internal/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/api/rest"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/detector"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database connection
	db, err := database.New(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize the drift detector
	driftDetector := detector.New(cfg.Detection, db)

	// Start the background drift detection service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go driftDetector.Start(ctx)

	// Initialize API server
	apiServer := rest.NewServer(cfg.API, db, driftDetector)

	// Start the HTTP server
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.API.Port),
		Handler: apiServer.Router(),
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting API server on port %d", cfg.API.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Set up graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}

	log.Println("Server stopped gracefully")
}