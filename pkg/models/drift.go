package models

import (
	"time"
)

// DriftStatus represents the current status of a detected drift
type DriftStatus string

const (
	DriftStatusDetected    DriftStatus = "detected"
	DriftStatusInProgress  DriftStatus = "in_progress"
	DriftStatusResolved    DriftStatus = "resolved"
	DriftStatusIgnored     DriftStatus = "ignored"
	DriftStatusApprovalRequired DriftStatus = "approval_required"
	DriftStatusRejected    DriftStatus = "rejected"
)

// DriftSeverity represents the impact level of the drift
type DriftSeverity string

const (
	DriftSeverityCritical DriftSeverity = "critical"
	DriftSeverityHigh     DriftSeverity = "high"
	DriftSeverityMedium   DriftSeverity = "medium"
	DriftSeverityLow      DriftSeverity = "low"
	DriftSeverityInfo     DriftSeverity = "info"
)

// PropertyChange represents a change to a single property
type PropertyChange struct {
	PropertyPath string      `json:"property_path"`
	ExpectedValue interface{} `json:"expected_value"`
	ActualValue   interface{} `json:"actual_value"`
	ChangeType    ChangeType  `json:"change_type"`
}

// ChangeType represents the type of change to a property
type ChangeType string

const (
	ChangeTypeAdded    ChangeType = "added"
	ChangeTypeRemoved  ChangeType = "removed"
	ChangeTypeModified ChangeType = "modified"
)

// Drift represents a detected drift between expected and actual state
type Drift struct {
	ID              string          `json:"id"`
	ResourceID      string          `json:"resource_id"`
	Resource        *Resource       `json:"resource,omitempty"`
	DetectedAt      time.Time       `json:"detected_at"`
	Status          DriftStatus     `json:"status"`
	Severity        DriftSeverity   `json:"severity"`
	Changes         []PropertyChange `json:"changes"`
	ExpectedStateID string          `json:"expected_state_id"`
	ActualStateID   string          `json:"actual_state_id"`
	WorkflowID      string          `json:"workflow_id,omitempty"`
	ResolvedAt      *time.Time      `json:"resolved_at,omitempty"`
	ResolutionNotes string          `json:"resolution_notes,omitempty"`
}

// DriftFilter provides filtering options for drift queries
type DriftFilter struct {
	ResourceID      string          `json:"resource_id,omitempty"`
	ResourceTypes   []ResourceType   `json:"resource_types,omitempty"`
	Provider        ProviderType    `json:"provider,omitempty"`
	Region          string          `json:"region,omitempty"`
	Account         string          `json:"account,omitempty"`
	Project         string          `json:"project,omitempty"`
	Status          []DriftStatus   `json:"status,omitempty"`
	Severity        []DriftSeverity `json:"severity,omitempty"`
	DetectedAfter   *time.Time      `json:"detected_after,omitempty"`
	DetectedBefore  *time.Time      `json:"detected_before,omitempty"`
	HasWorkflow     *bool           `json:"has_workflow,omitempty"`
}

// DriftRepository defines the interface for drift data operations
type DriftRepository interface {
	Create(drift *Drift) error
	Get(id string) (*Drift, error)
	Update(drift *Drift) error
	Delete(id string) error
	List(filter DriftFilter) ([]*Drift, error)
	GetByResource(resourceID string, status []DriftStatus) ([]*Drift, error)
}

// CalculateSeverity determines the severity of a drift based on the property changes
func CalculateSeverity(resource *Resource, changes []PropertyChange) DriftSeverity {
	// This is a simplified example - in a real implementation, you would have
	// more sophisticated logic based on resource type, change types, etc.
	
	criticalProperties := map[string]bool{
		"security_group.rules":        true,
		"iam_role.policy":            true,
		"*.public_access":            true,
		"*.encryption":               true,
		"network_interface.security": true,
	}
	
	highProperties := map[string]bool{
		"instance_type":              true,
		"vm_size":                    true,
		"*.backup":                   true,
		"*.monitoring":               true,
		"*.logging":                  true,
	}
	
	// Count changes by potential severity
	criticalCount := 0
	highCount := 0
	
	for _, change := range changes {
		// Check for critical property patterns
		for pattern := range criticalProperties {
			if matchPropertyPattern(change.PropertyPath, pattern) {
				criticalCount++
				break
			}
		}
		
		// Check for high severity property patterns
		for pattern := range highProperties {
			if matchPropertyPattern(change.PropertyPath, pattern) {
				highCount++
				break
			}
		}
	}
	
	// Determine overall severity
	if criticalCount > 0 {
		return DriftSeverityCritical
	} else if highCount > 0 {
		return DriftSeverityHigh
	} else if len(changes) > 5 {
		return DriftSeverityMedium
	} else if len(changes) > 0 {
		return DriftSeverityLow
	}
	
	return DriftSeverityInfo
}

// matchPropertyPattern is a simple pattern matcher for property paths
// In a real implementation, this would be more sophisticated
func matchPropertyPattern(path, pattern string) bool {
	// Simple implementation for the example
	// Would use proper pattern matching in a real implementation
	if pattern == path {
		return true
	}
	
	// Handle wildcard patterns
	if len(pattern) > 0 && pattern[0] == '*' && len(pattern) > 2 {
		suffix := pattern[1:]
		return len(path) >= len(suffix) && path[len(path)-len(suffix):] == suffix
	}
	
	return false
}