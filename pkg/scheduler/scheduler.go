package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/logging"
	"github.com/robfig/cron/v3"
)

// JobFunc is a function that executes a scheduled job
type JobFunc func(ctx context.Context) error

// JobStatus represents the status of a job
type JobStatus string

// Job statuses
const (
	JobStatusIdle     JobStatus = "IDLE"
	JobStatusRunning  JobStatus = "RUNNING"
	JobStatusSuccess  JobStatus = "SUCCESS"
	JobStatusFailed   JobStatus = "FAILED"
)

// JobResult represents the result of a job execution
type JobResult struct {
	JobID      string    `json:"job_id"`
	Status     JobStatus `json:"status"`
	StartedAt  time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error      string    `json:"error,omitempty"`
	Duration   string    `json:"duration,omitempty"`
}

// Job represents a scheduled job
type Job struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CronSpec    string    `json:"cron_spec"`
	Enabled     bool      `json:"enabled"`
	Function    JobFunc   `json:"-"`
	LastResult  *JobResult `json:"last_result,omitempty"`
	NextRunTime time.Time `json:"next_run_time"`
}

// Scheduler is responsible for scheduling and executing jobs
type Scheduler struct {
	config    *config.SchedulerConfig
	logger    *logging.Logger
	cron      *cron.Cron
	jobs      map[string]*Job
	runningJobs sync.Map
	mutex     sync.RWMutex
	location  *time.Location
	shutdown  chan struct{}
}

// NewScheduler creates a new scheduler
func NewScheduler(cfg *config.SchedulerConfig) (*Scheduler, error) {
	logger := logging.GetGlobalLogger().WithField("component", "scheduler")
	
	// Parse timezone
	location, err := time.LoadLocation(cfg.TimeZone)
	if err != nil {
		logger.Warn("Failed to load timezone %s: %v, using UTC", cfg.TimeZone, err)
		location = time.UTC
	}
	
	// Create cron scheduler with timezone
	cronOptions := []cron.Option{
		cron.WithLocation(location),
		cron.WithLogger(cronLogger{logger}),
	}
	
	cronScheduler := cron.New(cronOptions...)
	
	return &Scheduler{
		config:    cfg,
		logger:    logger,
		cron:      cronScheduler,
		jobs:      make(map[string]*Job),
		location:  location,
		shutdown:  make(chan struct{}),
	}, nil
}

// Start starts the scheduler
func (s *Scheduler) Start() {
	if !s.config.Enabled {
		s.logger.Info("Scheduler is disabled, not starting")
		return
	}
	
	s.logger.Info("Starting scheduler")
	s.cron.Start()
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	s.logger.Info("Stopping scheduler")
	
	// Stop accepting new jobs
	if s.cron != nil {
		ctx := s.cron.Stop()
		<-ctx.Done()
	}
	
	// Signal shutdown
	close(s.shutdown)
	
	// Wait for running jobs to complete
	s.runningJobs.Range(func(key, value interface{}) bool {
		jobID := key.(string)
		s.logger.Info("Waiting for job %s to complete", jobID)
		return true
	})
}

// AddJob adds a job to the scheduler
func (s *Scheduler) AddJob(id, name, description, cronSpec string, fn JobFunc) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if _, exists := s.jobs[id]; exists {
		return fmt.Errorf("job with ID %s already exists", id)
	}
	
	// Parse cron expression
	schedule, err := cron.ParseStandard(cronSpec)
	if err != nil {
		return fmt.Errorf("invalid cron expression %s: %w", cronSpec, err)
	}
	
	// Calculate next run time
	nextRun := schedule.Next(time.Now())
	
	// Create job
	job := &Job{
		ID:          id,
		Name:        name,
		Description: description,
		CronSpec:    cronSpec,
		Enabled:     true,
		Function:    fn,
		NextRunTime: nextRun,
	}
	
	// Add to list of jobs
	s.jobs[id] = job
	
	// Add to cron scheduler if the scheduler is enabled
	if s.config.Enabled {
		cronID, err := s.cron.AddFunc(cronSpec, func() {
			s.executeJob(id)
		})
		
		if err != nil {
			return fmt.Errorf("failed to schedule job: %w", err)
		}
		
		s.logger.Info("Job %s (%s) scheduled with cron ID %d, next run at %s",
			id, name, cronID, nextRun.Format(time.RFC3339))
	} else {
		s.logger.Info("Job %s (%s) added but scheduler is disabled",
			id, name)
	}
	
	return nil
}

// RemoveJob removes a job from the scheduler
func (s *Scheduler) RemoveJob(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	job, exists := s.jobs[id]
	if !exists {
		return fmt.Errorf("job with ID %s not found", id)
	}
	
	// Remove from list of jobs
	delete(s.jobs, id)
	
	s.logger.Info("Job %s (%s) removed from scheduler", id, job.Name)
	
	return nil
}

// GetJob gets a job by ID
func (s *Scheduler) GetJob(id string) (*Job, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	job, exists := s.jobs[id]
	if !exists {
		return nil, fmt.Errorf("job with ID %s not found", id)
	}
	
	return job, nil
}

// ListJobs gets all jobs
func (s *Scheduler) ListJobs() []*Job {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	jobs := make([]*Job, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}
	
	return jobs
}

// RunJobNow runs a job immediately
func (s *Scheduler) RunJobNow(id string) error {
	job, err := s.GetJob(id)
	if err != nil {
		return err
	}
	
	if !job.Enabled {
		return fmt.Errorf("job %s is disabled", id)
	}
	
	// Execute job in a goroutine
	go s.executeJob(id)
	
	return nil
}

// EnableJob enables a job
func (s *Scheduler) EnableJob(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	job, exists := s.jobs[id]
	if !exists {
		return fmt.Errorf("job with ID %s not found", id)
	}
	
	if job.Enabled {
		return nil // Already enabled
	}
	
	job.Enabled = true
	
	s.logger.Info("Job %s (%s) enabled", id, job.Name)
	
	return nil
}

// DisableJob disables a job
func (s *Scheduler) DisableJob(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	job, exists := s.jobs[id]
	if !exists {
		return fmt.Errorf("job with ID %s not found", id)
	}
	
	if !job.Enabled {
		return nil // Already disabled
	}
	
	job.Enabled = false
	
	s.logger.Info("Job %s (%s) disabled", id, job.Name)
	
	return nil
}

// executeJob executes a job
func (s *Scheduler) executeJob(id string) {
	// Check if job exists
	job, err := s.GetJob(id)
	if err != nil {
		s.logger.Error(err, "Failed to get job %s", id)
		return
	}
	
	// Check if job is enabled
	if !job.Enabled {
		s.logger.Info("Skipping disabled job %s", id)
		return
	}
	
	// Check if job is already running
	if _, running := s.runningJobs.LoadOrStore(id, true); running {
		s.logger.Warn("Job %s is already running, skipping", id)
		return
	}
	defer s.runningJobs.Delete(id)
	
	// Create job result
	result := &JobResult{
		JobID:     id,
		Status:    JobStatusRunning,
		StartedAt: time.Now(),
	}
	
	// Update job last result
	s.mutex.Lock()
	job.LastResult = result
	
	// Calculate next run time
	schedule, _ := cron.ParseStandard(job.CronSpec)
	job.NextRunTime = schedule.Next(time.Now())
	s.mutex.Unlock()
	
	s.logger.Info("Executing job %s (%s)", id, job.Name)
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	
	// Execute job function
	err = job.Function(ctx)
	
	// Update job result
	completedAt := time.Now()
	result.CompletedAt = &completedAt
	result.Duration = completedAt.Sub(result.StartedAt).String()
	
	if err != nil {
		result.Status = JobStatusFailed
		result.Error = err.Error()
		s.logger.Error(err, "Job %s failed", id)
	} else {
		result.Status = JobStatusSuccess
		s.logger.Info("Job %s completed successfully", id)
	}
	
	// Update job last result
	s.mutex.Lock()
	job.LastResult = result
	s.mutex.Unlock()
}

// cronLogger implements cron.Logger interface
type cronLogger struct {
	logger *logging.Logger
}

func (l cronLogger) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Info(msg, keysAndValues...)
}

func (l cronLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	l.logger.Error(err, msg, keysAndValues...)
}