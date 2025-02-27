package workflow

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jdaws97/infrastructure-drift-controller/internal/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/notification"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
)

// Engine handles workflow creation and execution
type Engine struct {
	config          config.WorkflowConfig
	db              *database.DB
	notifier        *notification.Service
	reconciler      *Reconciler
	templateMatcher *TemplateMatcher

	// For managing the execution engine
	runnerCtx       context.Context
	runnerCancel    context.CancelFunc
	workflowCh      chan string
}

// New creates a new workflow engine
func New(config config.WorkflowConfig, db *database.DB, notifier *notification.Service) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	
	engine := &Engine{
		config:       config,
		db:           db,
		notifier:     notifier,
		reconciler:   NewReconciler(db),
		workflowCh:   make(chan string, 100),
		runnerCtx:    ctx,
		runnerCancel: cancel,
	}
	
	engine.templateMatcher = NewTemplateMatcher(db)
	
	// Start the workflow runner
	go engine.runWorkflows()
	
	return engine
}

// CreateWorkflowForDrift creates a workflow for a detected drift
func (e *Engine) CreateWorkflowForDrift(drift *models.Drift) error {
	// Find the appropriate workflow template for this drift
	template, err := e.templateMatcher.FindTemplateForDrift(drift, drift.Resource)
	if err != nil {
		return fmt.Errorf("failed to find workflow template: %w", err)
	}
	
	// Create a new workflow based on the template
	workflow := &models.Workflow{
		ID:            uuid.New().String(),
		Name:          fmt.Sprintf("Drift-%s-%s", drift.Resource.Type, time.Now().Format("20060102-150405")),
		Description:   fmt.Sprintf("Workflow for drift detected in %s (%s)", drift.Resource.Name, drift.Resource.ID),
		TemplateID:    template.ID,
		Status:        models.WorkflowStatusPending,
		CreatedAt:     time.Now(),
		DriftID:       drift.ID,
		ResourceID:    drift.ResourceID,
		CurrentAction: -1, // Not started yet
	}
	
	// Create actions from template
	for _, actionTemplate := range template.Actions {
		action := models.WorkflowAction{
			ID:          uuid.New().String(),
			WorkflowID:  workflow.ID,
			Type:        actionTemplate.Type,
			Name:        actionTemplate.Name,
			Description: actionTemplate.Description,
			Status:      models.ActionStatusPending,
			Order:       actionTemplate.Order,
			Config:      actionTemplate.Config,
		}
		
		workflow.Actions = append(workflow.Actions, action)
	}
	
	// Save the workflow
	if err := e.db.CreateWorkflow(workflow); err != nil {
		return fmt.Errorf("failed to create workflow: %w", err)
	}
	
	// Update the drift to reference the workflow
	drift.WorkflowID = workflow.ID
	drift.Status = models.DriftStatusInProgress
	if err := e.db.UpdateDrift(drift); err != nil {
		return fmt.Errorf("failed to update drift: %w", err)
	}
	
	// Queue the workflow for execution
	e.workflowCh <- workflow.ID
	
	return nil
}

// Stop stops the workflow engine
func (e *Engine) Stop() {
	e.runnerCancel()
}

// runWorkflows processes workflows from the queue
func (e *Engine) runWorkflows() {
	for {
		select {
		case workflowID := <-e.workflowCh:
			// Process the workflow in a separate goroutine
			go e.processWorkflow(workflowID)
		case <-e.runnerCtx.Done():
			// Engine is shutting down
			log.Println("Workflow engine shutting down")
			return
		}
	}
}

// processWorkflow executes a single workflow
func (e *Engine) processWorkflow(workflowID string) {
	// Get the workflow
	workflow, err := e.db.GetWorkflow(workflowID)
	if err != nil {
		log.Printf("Error loading workflow %s: %v", workflowID, err)
		return
	}
	
	// Check if workflow is already completed or failed
	if workflow.Status == models.WorkflowStatusCompleted || 
	   workflow.Status == models.WorkflowStatusFailed ||
	   workflow.Status == models.WorkflowStatusCancelled {
		return
	}
	
	// Start the workflow if it's pending
	if workflow.Status == models.WorkflowStatusPending {
		workflow.Status = models.WorkflowStatusInProgress
		now := time.Now()
		workflow.StartedAt = &now
		workflow.CurrentAction = 0
		
		if err := e.db.UpdateWorkflow(workflow); err != nil {
			log.Printf("Error updating workflow %s: %v", workflowID, err)
			return
		}
	}
	
	// Process actions in sequence
	for i := workflow.CurrentAction; i < len(workflow.Actions); i++ {
		action := &workflow.Actions[i]
		
		// Skip completed or failed actions
		if action.Status == models.ActionStatusCompleted ||
		   action.Status == models.ActionStatusFailed ||
		   action.Status == models.ActionStatusSkipped {
			continue
		}
		
		// Update current action index
		workflow.CurrentAction = i
		if err := e.db.UpdateWorkflow(workflow); err != nil {
			log.Printf("Error updating workflow current action: %v", err)
			return
		}
		
		// Start the action
		now := time.Now()
		action.Status = models.ActionStatusInProgress
		action.StartedAt = &now
		
		if err := e.executeAction(workflow, action); err != nil {
			action.Status = models.ActionStatusFailed
			action.ErrorMessage = err.Error()
			action.CompletedAt = &now
			
			// Handle failure based on action config
			failureAction := "abort" // Default
			if action.Config.FailureAction != "" {
				failureAction = action.Config.FailureAction
			}
			
			if failureAction == "abort" {
				workflow.Status = models.WorkflowStatusFailed
				workflow.ErrorMessage = fmt.Sprintf("Action %s failed: %v", action.Name, err)
				workflow.CompletedAt = &now
				
				if err := e.db.UpdateWorkflow(workflow); err != nil {
					log.Printf("Error updating workflow %s: %v", workflowID, err)
				}
				return
			}
			
			// Continue to next action if failure action is "continue"
			continue
		}
		
		// Mark action as completed
		now = time.Now()
		action.Status = models.ActionStatusCompleted
		action.CompletedAt = &now
	}
	
	// All actions completed, mark workflow as completed
	now := time.Now()
	workflow.Status = models.WorkflowStatusCompleted
	workflow.CompletedAt = &now
	
	if err := e.db.UpdateWorkflow(workflow); err != nil {
		log.Printf("Error updating workflow %s: %v", workflowID, err)
		return
	}
	
	// Update the drift status
	drift, err := e.db.GetDrift(workflow.DriftID)
	if err != nil {
		log.Printf("Error loading drift %s: %v", workflow.DriftID, err)
		return
	}
	
	drift.Status = models.DriftStatusResolved
	drift.ResolvedAt = &now
	drift.ResolutionNotes = fmt.Sprintf("Resolved by workflow %s", workflow.ID)
	
	if err := e.db.UpdateDrift(drift); err != nil {
		log.Printf("Error updating drift %s: %v", drift.ID, err)
	}
}

// executeAction executes a single workflow action
func (e *Engine) executeAction(workflow *models.Workflow, action *models.WorkflowAction) error {
	// Get the drift and resource for context
	drift, err := e.db.GetDrift(workflow.DriftID)
	if err != nil {
		return fmt.Errorf("failed to load drift: %w", err)
	}
	
	resource, err := e.db.GetResource(workflow.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to load resource: %w", err)
	}
	
	// Execute different action types
	switch action.Type {
	case models.ActionTypeNotify:
		return e.executeNotifyAction(workflow, action, drift, resource)
	case models.ActionTypeApproval:
		return e.executeApprovalAction(workflow, action, drift, resource)
	case models.ActionTypeRemediate:
		return e.executeRemediateAction(workflow, action, drift, resource)
	case models.ActionTypeLog:
		return e.executeLogAction(workflow, action, drift, resource)
	case models.ActionTypeCustom:
		return e.executeCustomAction(workflow, action, drift, resource)
	default:
		return fmt.Errorf("unsupported action type: %s", action.Type)
	}
}

// executeNotifyAction sends notifications
func (e *Engine) executeNotifyAction(workflow *models.Workflow, action *models.WorkflowAction, drift *models.Drift, resource *models.Resource) error {
	// Prepare notification data
	data := map[string]interface{}{
		"workflow":  workflow,
		"action":    action,
		"drift":     drift,
		"resource":  resource,
		"timestamp": time.Now(),
	}
	
	// Use template if specified
	message := action.Config.Message
	if action.Config.TemplateID != "" {
		// Fetch template and render it
		// This would be implemented in the notification service
		var err error
		message, err = e.notifier.RenderTemplate(action.Config.TemplateID, data)
		if err != nil {
			return fmt.Errorf("failed to render notification template: %w", err)
		}
	}
	
	// Send to all specified channels
	for _, channelID := range action.Config.Channels {
		if err := e.notifier.Send(channelID, message, data); err != nil {
			return fmt.Errorf("failed to send notification to channel %s: %w", channelID, err)
		}
	}
	
	// Send to all specified recipients
	for _, recipient := range action.Config.Recipients {
		if err := e.notifier.SendToRecipient(recipient, message, data); err != nil {
			return fmt.Errorf("failed to send notification to recipient %s: %w", recipient, err)
		}
	}
	
	return nil
}

// executeApprovalAction handles approval requests
func (e *Engine) executeApprovalAction(workflow *models.Workflow, action *models.WorkflowAction, drift *models.Drift, resource *models.Resource) error {
	// Create an approval request
	approvalRequest := &database.ApprovalRequest{
		ID:          uuid.New().String(),
		WorkflowID:  workflow.ID,
		ActionID:    action.ID,
		Status:      database.ApprovalStatusPending,
		CreatedAt:   time.Now(),
		Approvers:   action.Config.Approvers,
		MinApprovals: action.Config.MinApprovals,
		DriftID:     drift.ID,
		ResourceID:  resource.ID,
	}
	
	// Set approval timeout
	timeoutStr := action.Config.ApprovalTimeout
	if timeoutStr == "" {
		timeoutStr = e.config.DefaultApprovalTimeout.String()
	}
	
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return fmt.Errorf("invalid approval timeout: %w", err)
	}
	
	expiresAt := time.Now().Add(timeout)
	approvalRequest.ExpiresAt = &expiresAt
	
	// Save the approval request
	if err := e.db.CreateApprovalRequest(approvalRequest); err != nil {
		return fmt.Errorf("failed to create approval request: %w", err)
	}
	
	// Update the drift status
	drift.Status = models.DriftStatusApprovalRequired
	if err := e.db.UpdateDrift(drift); err != nil {
		return fmt.Errorf("failed to update drift status: %w", err)
	}
	
	// Notify approvers
	data := map[string]interface{}{
		"workflow":       workflow,
		"action":         action,
		"drift":          drift,
		"resource":       resource,
		"approvalRequest": approvalRequest,
		"timestamp":      time.Now(),
	}
	
	// Send notifications to approvers
	for _, approver := range approvalRequest.Approvers {
		if err := e.notifier.SendToRecipient(approver, "Action requires your approval", data); err != nil {
			log.Printf("Error notifying approver %s: %v", approver, err)
			// Continue even if notification fails
		}
	}
	
	// Wait for approval
	approved, err := e.waitForApproval(approvalRequest)
	if err != nil {
		return fmt.Errorf("approval process failed: %w", err)
	}
	
	if !approved {
		// Update the drift status
		drift.Status = models.DriftStatusRejected
		if err := e.db.UpdateDrift(drift); err != nil {
			return fmt.Errorf("failed to update drift status: %w", err)
		}
		
		return fmt.Errorf("approval was rejected or timed out")
	}
	
	// Store approval result in action
	action.Result = map[string]interface{}{
		"approved": true,
		"approvers": approvalRequest.Approvals,
	}
	
	return nil
}

// waitForApproval waits for an approval request to be resolved
func (e *Engine) waitForApproval(request *database.ApprovalRequest) (bool, error) {
	// Check every minute for approval status
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Refresh the approval request
			updated, err := e.db.GetApprovalRequest(request.ID)
			if err != nil {
				return false, fmt.Errorf("failed to get approval request: %w", err)
			}
			
			// Check if it's been approved
			if updated.Status == database.ApprovalStatusApproved {
				return true, nil
			}
			
			// Check if it's been rejected
			if updated.Status == database.ApprovalStatusRejected {
				return false, nil
			}
			
			// Check if it's expired
			if updated.ExpiresAt != nil && time.Now().After(*updated.ExpiresAt) {
				// Update status to expired
				updated.Status = database.ApprovalStatusExpired
				if err := e.db.UpdateApprovalRequest(updated); err != nil {
					log.Printf("Error updating expired approval request: %v", err)
				}
				
				return false, fmt.Errorf("approval request expired")
			}
		case <-e.runnerCtx.Done():
			// Engine is shutting down
			return false, fmt.Errorf("workflow engine shutting down")
		}
	}
}

// executeRemediateAction performs remediation
func (e *Engine) executeRemediateAction(workflow *models.Workflow, action *models.WorkflowAction, drift *models.Drift, resource *models.Resource) error {
	// Determine remediation type
	remediationType := action.Config.RemediationType
	if remediationType == "" {
		remediationType = "auto" // Default
	}
	
	// Perform remediation
	switch remediationType {
	case "auto":
		return e.reconciler.AutoRemediate(drift, resource)
	case "plan":
		plan, err := e.reconciler.CreateRemediationPlan(drift, resource)
		if err != nil {
			return fmt.Errorf("failed to create remediation plan: %w", err)
		}
		
		// Store the plan in the action result
		action.Result = map[string]interface{}{
			"plan": plan,
		}
		
		return nil
	case "terraform":
		return e.reconciler.RemediateWithTerraform(drift, resource)
	default:
		return fmt.Errorf("unsupported remediation type: %s", remediationType)
	}
}

// executeLogAction logs information
func (e *Engine) executeLogAction(workflow *models.Workflow, action *models.WorkflowAction, drift *models.Drift, resource *models.Resource) error {
	// This is a simple action that just logs what's happening
	// In a real implementation, this might write to a database, external log system, etc.
	log.Printf("[Workflow %s] %s: Resource %s (%s) drift detected with severity %s",
		workflow.ID, action.Name, resource.Name, resource.ID, drift.Severity)
	
	// Create log entry in database
	logEntry := map[string]interface{}{
		"workflow_id": workflow.ID,
		"action_id":   action.ID,
		"drift_id":    drift.ID,
		"resource_id": resource.ID,
		"message":     action.Config.Message,
		"timestamp":   time.Now(),
	}
	
	// Store the log entry in the action result
	action.Result = logEntry
	
	return nil
}

// executeCustomAction runs custom scripts or functions
func (e *Engine) executeCustomAction(workflow *models.Workflow, action *models.WorkflowAction, drift *models.Drift, resource *models.Resource) error {
	// This is a placeholder for custom action execution
	// In a real implementation, this might:
	// - Run a script
	// - Call a webhook
	// - Execute a function loaded from a plugin
	
	if action.Config.Script != "" {
		return e.executeScript(action.Config.Script, workflow, action, drift, resource)
	}
	
	if action.Config.FunctionName != "" {
		return e.executeFunction(action.Config.FunctionName, action.Config.Parameters, workflow, action, drift, resource)
	}
	
	return fmt.Errorf("custom action missing script or function")
}

// executeScript is a placeholder for script execution
func (e *Engine) executeScript(script string, workflow *models.Workflow, action *models.WorkflowAction, drift *models.Drift, resource *models.Resource) error {
	// In a real implementation, this would execute the script
	log.Printf("Would execute script for workflow %s: %s", workflow.ID, script)
	
	// Return success for now
	return nil
}

// executeFunction is a placeholder for function execution
func (e *Engine) executeFunction(functionName string, params map[string]interface{}, workflow *models.Workflow, action *models.WorkflowAction, drift *models.Drift, resource *models.Resource) error {
	// In a real implementation, this would look up and execute a function
	log.Printf("Would execute function %s for workflow %s with %d parameters", 
		functionName, workflow.ID, len(params))
	
	// Return success for now
	return nil
}