package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/cloud"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/drift"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/iac"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/llm"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/logging"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/remediation"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/scheduler"
)

// App represents the drift detector application
type App struct {
	config            *config.Config
	logger            *logging.Logger
	stateParser       *iac.TerraformStateParser
	cloudQuerier      *cloud.AWSQuerier
	driftDetector     *drift.DriftDetector
	llmClient         *llm.Client
	llmIntegrator     *llm.Integrator
	remediationTrigger *remediation.RemediationTrigger
	scheduler         *scheduler.Scheduler
	workingDir        string
	driftDetections   map[string][]drift.DriftReport
	mutex             sync.RWMutex
	shutdown          chan struct{}
}

// NewApp creates a new drift detector application
func NewApp(cfg *config.Config) (*App, error) {
	// Set up logger
	logConfig := logging.DefaultConfig()
	logConfig.Level = logging.LogLevel(cfg.Logging.Level)
	logConfig.JSONFormat = cfg.Logging.JSONFormat
	
	// Set up file logging if specified
	if cfg.Logging.FilePath != "" {
		file, err := os.OpenFile(cfg.Logging.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		logConfig.Output = file
	}
	
	logger := logging.New(logConfig)
	logging.SetGlobalLogger(logger)
	
	appLogger := logger.WithField("component", "app")
	
	// Create working directory
	workingDir, err := os.MkdirTemp("", "drift-detector-")
	if err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}
	
	// Create components
	stateParser := iac.NewTerraformStateParser()
	
	// Create AWS querier
	cloudQuerier, err := cloud.NewAWSQuerier(&cfg.AWS)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS querier: %w", err)
	}
	
	// Create drift detector
	driftDetector := drift.NewDriftDetector(cfg, stateParser, cloudQuerier)
	
	// Create LLM client
	llmClient, err := llm.NewClient(&cfg.LLM)
	if err != nil {
		return nil, fmt.Errorf("failed to create LLM client: %w", err)
	}
	
	// Create LLM integrator
	llmIntegrator := llm.NewIntegrator(llmClient)
	
	// Create remediation trigger
	remediationTrigger := remediation.NewRemediationTrigger(&cfg.Remediation, workingDir)
	
	// Create scheduler
	scheduler, err := scheduler.NewScheduler(&cfg.Scheduler)
	if err != nil {
		return nil, fmt.Errorf("failed to create scheduler: %w", err)
	}
	
	app := &App{
		config:            cfg,
		logger:            appLogger,
		stateParser:       stateParser,
		cloudQuerier:      cloudQuerier,
		driftDetector:     driftDetector,
		llmClient:         llmClient,
		llmIntegrator:     llmIntegrator,
		remediationTrigger: remediationTrigger,
		scheduler:         scheduler,
		workingDir:        workingDir,
		driftDetections:   make(map[string][]drift.DriftReport),
		shutdown:          make(chan struct{}),
	}
	
	return app, nil
}

// Start starts the drift detector application
func (a *App) Start() error {
	a.logger.Info("Starting drift detector application")
	
	// Set up scheduler jobs
	if a.config.Scheduler.Enabled {
		err := a.setupScheduler()
		if err != nil {
			return fmt.Errorf("failed to set up scheduler: %w", err)
		}
		
		// Start scheduler
		a.scheduler.Start()
	}
	
	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		sig := <-sigCh
		a.logger.Info("Received signal %s, shutting down", sig)
		a.Stop()
	}()
	
	// Run initial drift detection if configured
	if !a.config.Scheduler.Enabled {
		a.logger.Info("Scheduler disabled, running one-time drift detection")
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		
		if err := a.runDriftDetection(ctx); err != nil {
			a.logger.Error(err, "Drift detection failed")
		}
	}
	
	// Wait for shutdown signal
	<-a.shutdown
	
	return nil
}

// Stop stops the drift detector application
func (a *App) Stop() {
	a.logger.Info("Stopping drift detector application")
	
	// Stop scheduler
	if a.scheduler != nil {
		a.scheduler.Stop()
	}
	
	// Clean up working directory
	if a.workingDir != "" {
		os.RemoveAll(a.workingDir)
	}
	
	// Signal shutdown
	close(a.shutdown)
}

// setupScheduler sets up the scheduler jobs
func (a *App) setupScheduler() error {
	// Add drift detection job
	err := a.scheduler.AddJob(
		"drift-detection",
		"Drift Detection",
		"Detects infrastructure drift by comparing Terraform state with actual cloud resources",
		a.config.Scheduler.CronSpec,
		a.runDriftDetection,
	)
	if err != nil {
		return fmt.Errorf("failed to add drift detection job: %w", err)
	}
	
	return nil
}

// runDriftDetection runs the drift detection process
func (a *App) runDriftDetection(ctx context.Context) error {
	a.logger.Info("Running drift detection")
	
	// Get current timestamp for this run
	timestamp := time.Now().Format("20060102-150405")
	
	// Detect drift
	drifts, err := a.driftDetector.DetectDrift(ctx)
	if err != nil {
		return fmt.Errorf("drift detection failed: %w", err)
	}
	
	a.logger.Info("Detected %d drifts", len(drifts))
	
	// Store drift reports
	a.mutex.Lock()
	a.driftDetections[timestamp] = drifts
	a.mutex.Unlock()
	
	// If no drifts found, we're done
	if len(drifts) == 0 {
		a.logger.Info("No infrastructure drift detected")
		return nil
	}
	
	// Save drift reports to file
	if err := a.saveDriftReports(timestamp, drifts); err != nil {
		a.logger.Error(err, "Failed to save drift reports")
	}
	
	// Process each drift with LLM for remediation planning
	if a.config.Remediation.Enabled {
		a.processDriftsWithLLM(ctx, drifts)
	}
	
	return nil
}

// saveDriftReports saves drift reports to a file
func (a *App) saveDriftReports(timestamp string, drifts []drift.DriftReport) error {
	// Create reports directory if it doesn't exist
	reportsDir := filepath.Join(a.workingDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}
	
	// Create report file
	reportPath := filepath.Join(reportsDir, fmt.Sprintf("drift-report-%s.json", timestamp))
	reportJSON, err := drift.SerializeDriftReports(drifts)
	if err != nil {
		return fmt.Errorf("failed to serialize drift reports: %w", err)
	}
	
	// Write report to file
	if err := os.WriteFile(reportPath, reportJSON, 0644); err != nil {
		return fmt.Errorf("failed to write drift report: %w", err)
	}
	
	a.logger.Info("Saved drift report to %s", reportPath)
	
	return nil
}

// processDriftsWithLLM processes drifts with LLM for remediation planning
func (a *App) processDriftsWithLLM(ctx context.Context, drifts []drift.DriftReport) {
	a.logger.Info("Processing %d drifts with LLM", len(drifts))
	
	// Process each drift concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrency
	
	for _, driftReport := range drifts {
		wg.Add(1)
		
		go func(driftItem drift.DriftReport) {
			defer wg.Done()
			
			// Acquire semaphore token
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Skip low severity drifts if configured
			if driftItem.Severity == drift.SeverityLow && !a.config.Remediation.Enabled {
				a.logger.Info("Skipping low severity drift for %s (%s)", 
					driftItem.ResourceName, driftItem.ResourceID)
				return
			}
			
			// Get context for the LLM
			stateContext := map[string]interface{}{
				"resource_type": driftItem.ResourceType,
				"resource_id":   driftItem.ResourceID,
				// Add more context as needed
			}
			
			cloudContext := map[string]interface{}{
				"region": a.config.AWS.Region,
				// Add more context as needed
			}
			
			// Generate remediation plan using LLM
			a.logger.Info("Generating remediation plan for %s (%s)", 
			driftItem.ResourceName, driftItem.ResourceID)
			
			plan, err := a.llmIntegrator.AnalyzeDrift(ctx, driftItem, stateContext, cloudContext)
			if err != nil {
				a.logger.Error(err, "Failed to analyze drift with LLM for %s", driftItem.ResourceID)
				return
			}
			
			a.logger.Info("Generated remediation plan for %s: %s", 
			driftItem.ResourceID, plan.Description)
			
			// Create remediation
			if a.config.Remediation.Enabled {
				a.logger.Info("Creating remediation for %s", driftItem.ResourceID)
				
				remediation, err := a.remediationTrigger.CreateRemediation(ctx, driftItem, plan)
				if err != nil {
					a.logger.Error(err, "Failed to create remediation for %s", driftItem.ResourceID)
					return
				}
				
				a.logger.Info("Created remediation %s for drift %s", 
					remediation.ID, driftItem.ID)
			} else {
				a.logger.Info("Remediation is disabled, skipping creation")
			}
		}(driftReport)
	}
	
	// Wait for all drifts to be processed
	wg.Wait()
	
	a.logger.Info("Completed processing drifts with LLM")
}

// GetDriftReports returns drift reports for a specific run
func (a *App) GetDriftReports(timestamp string) ([]drift.DriftReport, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	
	if timestamp == "latest" {
		// Find the latest timestamp
		var latestTimestamp string
		for ts := range a.driftDetections {
			if latestTimestamp == "" || ts > latestTimestamp {
				latestTimestamp = ts
			}
		}
		
		if latestTimestamp == "" {
			return nil, fmt.Errorf("no drift detections found")
		}
		
		return a.driftDetections[latestTimestamp], nil
	}
	
	// Get reports for specific timestamp
	reports, ok := a.driftDetections[timestamp]
	if !ok {
		return nil, fmt.Errorf("no drift detection found for timestamp %s", timestamp)
	}
	
	return reports, nil
}

// ListDriftDetections returns a list of all drift detection runs
func (a *App) ListDriftDetections() []string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	
	timestamps := make([]string, 0, len(a.driftDetections))
	for timestamp := range a.driftDetections {
		timestamps = append(timestamps, timestamp)
	}
	
	return timestamps
}

// RunManualDriftDetection runs a manual drift detection
func (a *App) RunManualDriftDetection(ctx context.Context) ([]drift.DriftReport, error) {
	a.logger.Info("Running manual drift detection")
	
	// Run drift detection
	if err := a.runDriftDetection(ctx); err != nil {
		return nil, fmt.Errorf("drift detection failed: %w", err)
	}
	
	// Get latest reports
	reports, err := a.GetDriftReports("latest")
	if err != nil {
		return nil, fmt.Errorf("failed to get latest drift reports: %w", err)
	}
	
	return reports, nil
}

// GetRemediations returns all remediations
func (a *App) GetRemediations() []*remediation.Remediation {
	return a.remediationTrigger.ListRemediations()
}

// ApproveRemediation approves a remediation
func (a *App) ApproveRemediation(ctx context.Context, id string, approver string) error {
	return a.remediationTrigger.ApproveRemediation(ctx, id, approver)
}

// RejectRemediation rejects a remediation
func (a *App) RejectRemediation(id string, rejecter string, reason string) error {
	return a.remediationTrigger.RejectRemediation(id, rejecter, reason)
}