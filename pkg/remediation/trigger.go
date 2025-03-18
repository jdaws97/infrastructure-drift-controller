package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/drift"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/llm"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/logging"
)

// RemediationStatus represents the status of a remediation
type RemediationStatus string

// Remediation statuses
const (
	RemediationPending  RemediationStatus = "PENDING"
	RemediationApproved RemediationStatus = "APPROVED"
	RemediationRejected RemediationStatus = "REJECTED"
	RemediationRunning  RemediationStatus = "RUNNING"
	RemediationSuccess  RemediationStatus = "SUCCESS"
	RemediationFailed   RemediationStatus = "FAILED"
)

// Remediation represents a remediation for an infrastructure drift
type Remediation struct {
	ID            string             `json:"id"`
	DriftID       string             `json:"drift_id"`
	Plan          *llm.RemediationPlan `json:"plan"`
	Status        RemediationStatus  `json:"status"`
	ApprovedBy    string             `json:"approved_by,omitempty"`
	ApprovedAt    *time.Time         `json:"approved_at,omitempty"`
	RejectedBy    string             `json:"rejected_by,omitempty"`
	RejectedAt    *time.Time         `json:"rejected_at,omitempty"`
	StartedAt     *time.Time         `json:"started_at,omitempty"`
	CompletedAt   *time.Time         `json:"completed_at,omitempty"`
	ErrorMessage  string             `json:"error_message,omitempty"`
	OutputLog     string             `json:"output_log,omitempty"`
	AttemptCount  int                `json:"attempt_count"`
}

// RemediationTrigger is responsible for triggering remediations
type RemediationTrigger struct {
	config         *config.RemediationConfig
	logger         *logging.Logger
	remediations   map[string]*Remediation
	notifier       *NotificationService
	workingDir     string
}

// NewRemediationTrigger creates a new remediation trigger
func NewRemediationTrigger(cfg *config.RemediationConfig, workingDir string) *RemediationTrigger {
	logger := logging.GetGlobalLogger().WithField("component", "remediation_trigger")
	
	// Create notification service
	notifier := NewNotificationService(cfg.NotifyEmails)
	
	return &RemediationTrigger{
		config:       cfg,
		logger:       logger,
		remediations: make(map[string]*Remediation),
		notifier:     notifier,
		workingDir:   workingDir,
	}
}

// CreateRemediation creates a new remediation based on a drift report and remediation plan
func (t *RemediationTrigger) CreateRemediation(ctx context.Context, driftReport drift.DriftReport, plan *llm.RemediationPlan) (*Remediation, error) {
	// Generate unique ID for remediation
	remediationID := fmt.Sprintf("remediation-%s-%d", driftReport.ID, time.Now().Unix())
	
	// Create remediation
	remediation := &Remediation{
		ID:            remediationID,
		DriftID:       driftReport.ID,
		Plan:          plan,
		Status:        RemediationPending,
		AttemptCount:  0,
	}
	
	// Store remediation
	t.remediations[remediationID] = remediation
	
	// For manual approval mode, send notification
	if t.config.ApprovalMode == "manual" {
		t.logger.Info("Sending remediation approval notification for %s", remediationID)
		
		// Prepare notification context
		context := map[string]interface{}{
			"remediation_id": remediationID,
			"drift_report":   driftReport,
			"plan":           plan,
		}
		
		// Send notification
		if err := t.notifier.SendRemediationApprovalNotification(context); err != nil {
			t.logger.Error(err, "Failed to send remediation approval notification")
			// Don't fail the whole process if notification fails
		}
	} else if t.config.ApprovalMode == "auto" {
		// For auto approval mode, automatically approve and execute remediation
		t.logger.Info("Auto-approving remediation %s", remediationID)
		
		now := time.Now()
		remediation.Status = RemediationApproved
		remediation.ApprovedBy = "auto"
		remediation.ApprovedAt = &now
		
		// Execute remediation asynchronously
		go func() {
			if err := t.executeRemediation(context.Background(), remediation); err != nil {
				t.logger.Error(err, "Failed to execute remediation %s", remediationID)
			}
		}()
	}
	
	return remediation, nil
}

// GetRemediation retrieves a remediation by ID
func (t *RemediationTrigger) GetRemediation(id string) (*Remediation, error) {
	remediation, ok := t.remediations[id]
	if !ok {
		return nil, fmt.Errorf("remediation not found: %s", id)
	}
	return remediation, nil
}

// ApproveRemediation approves a remediation
func (t *RemediationTrigger) ApproveRemediation(ctx context.Context, id string, approver string) error {
	remediation, err := t.GetRemediation(id)
	if err != nil {
		return err
	}
	
	// Check if remediation can be approved
	if remediation.Status != RemediationPending {
		return fmt.Errorf("remediation %s is not in PENDING status", id)
	}
	
	// Update remediation status
	now := time.Now()
	remediation.Status = RemediationApproved
	remediation.ApprovedBy = approver
	remediation.ApprovedAt = &now
	
	t.logger.Info("Remediation %s approved by %s", id, approver)
	
	// Execute remediation asynchronously
	go func() {
		if err := t.executeRemediation(context.Background(), remediation); err != nil {
			t.logger.Error(err, "Failed to execute remediation %s", id)
		}
	}()
	
	return nil
}

// RejectRemediation rejects a remediation
func (t *RemediationTrigger) RejectRemediation(id string, rejecter string, reason string) error {
	remediation, err := t.GetRemediation(id)
	if err != nil {
		return err
	}
	
	// Check if remediation can be rejected
	if remediation.Status != RemediationPending {
		return fmt.Errorf("remediation %s is not in PENDING status", id)
	}
	
	// Update remediation status
	now := time.Now()
	remediation.Status = RemediationRejected
	remediation.RejectedBy = rejecter
	remediation.RejectedAt = &now
	remediation.ErrorMessage = reason
	
	t.logger.Info("Remediation %s rejected by %s: %s", id, rejecter, reason)
	
	return nil
}

// executeRemediation executes a remediation
func (t *RemediationTrigger) executeRemediation(ctx context.Context, remediation *Remediation) error {
	// Check if remediation is approved
	if remediation.Status != RemediationApproved {
		return fmt.Errorf("remediation %s is not approved", remediation.ID)
	}
	
	// Update status to running
	now := time.Now()
	remediation.Status = RemediationRunning
	remediation.StartedAt = &now
	remediation.AttemptCount++
	
	t.logger.Info("Executing remediation %s (attempt %d/%d)", 
		remediation.ID, remediation.AttemptCount, t.config.MaxAttempts)
	
	// Create temporary directory for remediation
	tempDir, err := os.MkdirTemp(t.workingDir, fmt.Sprintf("remediation-%s-", remediation.ID))
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Generate remediation script
	scriptPath, err := t.generateRemediationScript(tempDir, remediation)
	if err != nil {
		return fmt.Errorf("failed to generate remediation script: %w", err)
	}
	
	// Make script executable
	if err := os.Chmod(scriptPath, 0755); err != nil {
		return fmt.Errorf("failed to make remediation script executable: %w", err)
	}
	
	// Execute remediation script
	cmd := exec.CommandContext(ctx, scriptPath)
	cmd.Dir = tempDir
	
	// Capture output
	output, err := cmd.CombinedOutput()
	
	// Update remediation with output
	remediation.OutputLog = string(output)
	
	// Handle execution result
	completedAt := time.Now()
	remediation.CompletedAt = &completedAt
	
	if err != nil {
		remediation.Status = RemediationFailed
		remediation.ErrorMessage = fmt.Sprintf("Execution failed: %s", err)
		
		t.logger.Error(err, "Remediation %s failed: %s", remediation.ID, remediation.ErrorMessage)
		
		// Check if we should retry
		if remediation.AttemptCount < t.config.MaxAttempts {
			t.logger.Info("Scheduling retry for remediation %s", remediation.ID)
			
			// Reset status to pending for retry
			remediation.Status = RemediationPending
			
			// Schedule retry
			go func() {
				// Wait before retrying
				time.Sleep(time.Second * 30)
				
				// Re-approve automatically for retry
				retryCtx := context.Background()
				if err := t.ApproveRemediation(retryCtx, remediation.ID, "auto-retry"); err != nil {
					t.logger.Error(err, "Failed to auto-approve remediation retry")
				}
			}()
		}
		
		return fmt.Errorf("remediation script execution failed: %w", err)
	}
	
	// Update status to success
	remediation.Status = RemediationSuccess
	
	t.logger.Info("Remediation %s completed successfully", remediation.ID)
	
	// Send notification
	if t.config.ApprovalMode == "manual" {
		context := map[string]interface{}{
			"remediation_id": remediation.ID,
			"status":        "success",
			"output":        remediation.OutputLog,
		}
		
		if err := t.notifier.SendRemediationCompletionNotification(context); err != nil {
			t.logger.Error(err, "Failed to send remediation completion notification")
		}
	}
	
	return nil
}

// generateRemediationScript generates a script to execute the remediation
func (t *RemediationTrigger) generateRemediationScript(dir string, remediation *Remediation) (string, error) {
	// Create script file
	scriptPath := filepath.Join(dir, "remediate.sh")
	scriptFile, err := os.Create(scriptPath)
	if err != nil {
		return "", fmt.Errorf("failed to create script file: %w", err)
	}
	defer scriptFile.Close()
	
	// Write script header
	scriptContent := []string{
		"#!/bin/bash",
		"set -e",
		"",
		fmt.Sprintf("# Remediation script for %s", remediation.ID),
		fmt.Sprintf("# Generated at %s", time.Now().Format(time.RFC3339)),
		"",
		"echo \"Starting remediation...\"",
		"",
	}
	
	// Add each action as a step in the script
	for i, action := range remediation.Plan.Actions {
		scriptContent = append(scriptContent,
			fmt.Sprintf("echo \"Step %d: %s\"", i+1, action),
			"",
			"# TODO: Implement this action",
			fmt.Sprintf("# %s", action),
			"",
			"# For now, we'll just simulate success",
			"echo \"Step completed successfully\"",
			"",
		)
	}
	
	// Add script footer
	scriptContent = append(scriptContent,
		"echo \"Remediation completed successfully\"",
		"exit 0",
	)
	
	// Write script content
	_, err = scriptFile.WriteString(strings.Join(scriptContent, "\n"))
	if err != nil {
		return "", fmt.Errorf("failed to write script content: %w", err)
	}
	
	return scriptPath, nil
}

// ListRemediations lists all remediations
func (t *RemediationTrigger) ListRemediations() []*Remediation {
	remediations := make([]*Remediation, 0, len(t.remediations))
	for _, remediation := range t.remediations {
		remediations = append(remediations, remediation)
	}
	return remediations
}

// NotificationService handles sending notifications
type NotificationService struct {
	recipients []string
	logger     *logging.Logger
}

// NewNotificationService creates a new notification service
func NewNotificationService(recipients []string) *NotificationService {
	return &NotificationService{
		recipients: recipients,
		logger:     logging.GetGlobalLogger().WithField("component", "notification_service"),
	}
}

// SendRemediationApprovalNotification sends a notification for remediation approval
func (s *NotificationService) SendRemediationApprovalNotification(context map[string]interface{}) error {
	if len(s.recipients) == 0 {
		s.logger.Warn("No recipients configured for notifications")
		return nil
	}
	
	// In a real implementation, this would send emails or other notifications
	// For now, we'll just log it
	s.logger.Info("Would send remediation approval notification to %v: %s",
		s.recipients, prettyFormatJSON(context))
	
	return nil
}

// SendRemediationCompletionNotification sends a notification for remediation completion
func (s *NotificationService) SendRemediationCompletionNotification(context map[string]interface{}) error {
	if len(s.recipients) == 0 {
		s.logger.Warn("No recipients configured for notifications")
		return nil
	}
	
	// In a real implementation, this would send emails or other notifications
	// For now, we'll just log it
	s.logger.Info("Would send remediation completion notification to %v: %s", 
		s.recipients, prettyFormatJSON(context))
	
	return nil
}

// prettyFormatJSON formats a value as a pretty-printed JSON string
func prettyFormatJSON(v interface{}) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting JSON: %s", err)
	}
	return string(data)
}