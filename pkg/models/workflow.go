package models

import (
	"time"
)

// WorkflowStatus represents the current status of a workflow
type WorkflowStatus string

const (
	WorkflowStatusPending    WorkflowStatus = "pending"
	WorkflowStatusInProgress WorkflowStatus = "in_progress"
	WorkflowStatusCompleted  WorkflowStatus = "completed"
	WorkflowStatusFailed     WorkflowStatus = "failed"
	WorkflowStatusCancelled  WorkflowStatus = "cancelled"
)

// ActionType represents the type of workflow action
type ActionType string

const (
	ActionTypeNotify      ActionType = "notify"
	ActionTypeApproval    ActionType = "approval"
	ActionTypeRemediate   ActionType = "remediate"
	ActionTypeLog         ActionType = "log"
	ActionTypeCustom      ActionType = "custom"
)

// ActionStatus represents the current status of a workflow action
type ActionStatus string

const (
	ActionStatusPending    ActionStatus = "pending"
	ActionStatusInProgress ActionStatus = "in_progress"
	ActionStatusCompleted  ActionStatus = "completed"
	ActionStatusFailed     ActionStatus = "failed"
	ActionStatusSkipped    ActionStatus = "skipped"
)

// Workflow represents a sequence of actions to handle drift
type Workflow struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	TemplateID     string         `json:"template_id,omitempty"`
	Status         WorkflowStatus `json:"status"`
	CreatedAt      time.Time      `json:"created_at"`
	StartedAt      *time.Time     `json:"started_at,omitempty"`
	CompletedAt    *time.Time     `json:"completed_at,omitempty"`
	DriftID        string         `json:"drift_id"`
	ResourceID     string         `json:"resource_id"`
	CurrentAction  int            `json:"current_action"`
	Actions        []WorkflowAction `json:"actions"`
	ErrorMessage   string         `json:"error_message,omitempty"`
}

// WorkflowAction represents a single action in a workflow
type WorkflowAction struct {
	ID          string       `json:"id"`
	WorkflowID  string       `json:"workflow_id"`
	Type        ActionType   `json:"type"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Status      ActionStatus `json:"status"`
	Order       int          `json:"order"`
	Config      ActionConfig `json:"config"`
	StartedAt   *time.Time   `json:"started_at,omitempty"`
	CompletedAt *time.Time   `json:"completed_at,omitempty"`
	Result      interface{}  `json:"result,omitempty"`
	ErrorMessage string      `json:"error_message,omitempty"`
}

// ActionConfig contains configuration for a workflow action
type ActionConfig struct {
	// Common fields
	Timeout          string                 `json:"timeout,omitempty"`
	RetryCount       int                    `json:"retry_count,omitempty"`
	RetryInterval    string                 `json:"retry_interval,omitempty"`
	FailureAction    string                 `json:"failure_action,omitempty"` // "continue", "abort"
	
	// Notification specific fields
	Channels         []string               `json:"channels,omitempty"`
	Recipients       []string               `json:"recipients,omitempty"`
	Message          string                 `json:"message,omitempty"`
	TemplateID       string                 `json:"template_id,omitempty"`
	
	// Approval specific fields
	Approvers        []string               `json:"approvers,omitempty"`
	MinApprovals     int                    `json:"min_approvals,omitempty"`
	ApprovalTimeout  string                 `json:"approval_timeout,omitempty"`
	
	// Remediation specific fields
	RemediationType  string                 `json:"remediation_type,omitempty"` // "auto", "plan", "terraform"
	ResourceIDs      []string               `json:"resource_ids,omitempty"`
	
	// Custom action fields
	Script           string                 `json:"script,omitempty"`
	FunctionName     string                 `json:"function_name,omitempty"`
	Parameters       map[string]interface{} `json:"parameters,omitempty"`
}

// WorkflowTemplate represents a reusable workflow definition
type WorkflowTemplate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	IsDefault   bool `json:"is_default"`
	
	// Resource matching criteria
	ResourceTypes []ResourceType `json:"resource_types,omitempty"`
	Providers     []ProviderType `json:"providers,omitempty"`
	Tags          Tags `json:"tags,omitempty"`
	
	Properties map[string]interface{} `json:"properties,omitempty"`

	// Action templates
	Actions []WorkflowActionTemplate `json:"actions"`
}

// WorkflowActionTemplate represents a template for a workflow action
type WorkflowActionTemplate struct {
	Type        ActionType `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Order       int `json:"order"`
	Config      ActionConfig `json:"config"`
}

// WorkflowRepository defines the interface for workflow data operations
type WorkflowRepository interface {
	CreateWorkflow(workflow *Workflow) error
	GetWorkflow(id string) (*Workflow, error)
	UpdateWorkflow(workflow *Workflow) error
	DeleteWorkflow(id string) error
	ListWorkflows(filter WorkflowFilter) ([]*Workflow, error)
	
	CreateTemplate(template *WorkflowTemplate) error
	GetTemplate(id string) (*WorkflowTemplate, error)
	UpdateTemplate(template *WorkflowTemplate) error
	DeleteTemplate(id string) error
	ListTemplates() ([]*WorkflowTemplate, error)
}

// WorkflowFilter provides filtering options for workflow queries
type WorkflowFilter struct {
	DriftID       string `json:"drift_id,omitempty"`
	ResourceID    string `json:"resource_id,omitempty"`
	Status        []WorkflowStatus `json:"status,omitempty"`
	CreatedAfter  *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`
}