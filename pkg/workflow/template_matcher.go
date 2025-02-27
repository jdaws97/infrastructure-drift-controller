package workflow

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
)

// TemplateMatcher finds appropriate workflow templates for resources
type TemplateMatcher struct {
	db *database.DB
}

// NewTemplateMatcher creates a new template matcher
func NewTemplateMatcher(db *database.DB) *TemplateMatcher {
	return &TemplateMatcher{
		db: db,
	}
}

// FindTemplateForDrift finds the best matching workflow template for a detected drift
func (m *TemplateMatcher) FindTemplateForDrift(drift *models.Drift, resource *models.Resource) (*models.WorkflowTemplate, error) {
	// Get all templates
	templates, err := m.db.GetWorkflowTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to load workflow templates: %w", err)
	}
	
	log.Printf("Finding template for drift %s (resource: %s)", drift.ID, resource.ID)
	
	// Find the best matching template
	var bestTemplate *models.WorkflowTemplate
	bestMatchScore := 0
	
	for _, template := range templates {
		score := m.calculateMatchScore(template, resource, drift)
		log.Printf("Template %s score: %d", template.Name, score)
		
		if score > bestMatchScore {
			bestMatchScore = score
			bestTemplate = template
		}
	}
	
	// Check if we found a matching template
	if bestTemplate == nil {
		// Get default template
		for _, template := range templates {
			if template.IsDefault {
				log.Printf("Using default template: %s", template.Name)
				return template, nil
			}
		}
		
		return nil, fmt.Errorf("no matching template found")
	}
	
	log.Printf("Selected template: %s with score %d", bestTemplate.Name, bestMatchScore)
	return bestTemplate, nil
}

func (m *TemplateMatcher) FindTemplateForResource(drift *models.Drift, resource *models.Resource) (*models.WorkflowTemplate, error) {
	// Get all templates
	templates, err := m.db.GetWorkflowTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to load workflow templates: %w", err)
	}
	
	// Find the best matching template
	var bestTemplate *models.WorkflowTemplate
	bestMatchScore := 0
	
	for _, template := range templates {
		score := m.calculateMatchScore(template, resource, drift)
		
		if score > bestMatchScore {
			bestMatchScore = score
			bestTemplate = template
		}
	}
	
	// Check if we found a matching template
	if bestTemplate == nil {
		// Get default template
		for _, template := range templates {
			if template.IsDefault {
				return template, nil
			}
		}
		
		return nil, fmt.Errorf("no matching template found")
	}
	
	return bestTemplate, nil
}

// calculateMatchScore calculates how well a template matches a resource and drift
func (m *TemplateMatcher) calculateMatchScore(template *models.WorkflowTemplate, resource *models.Resource, drift *models.Drift) int {
	score := 0
	
	// Check resource type match (highest priority)
	if m.matchesResourceType(template, resource) {
		score += 100
	}
	
	// Check provider match
	if m.matchesProvider(template, resource) {
		score += 50
	}
	
	// Check tag matches
	tagScore := m.calculateTagScore(template, resource)
	score += tagScore * 10
	
	// Check severity match
	if m.matchesSeverity(template, drift) {
		score += 30
	}
	
	// Check for specific property changes
	changeScore := m.calculateChangeScore(template, drift)
	score += changeScore * 5
	
	return score
}

// matchesResourceType checks if a template matches the resource type
func (m *TemplateMatcher) matchesResourceType(template *models.WorkflowTemplate, resource *models.Resource) bool {
	if len(template.ResourceTypes) == 0 {
		// Empty list means match all types
		return true
	}
	
	resourceType := string(resource.Type)
	
	for _, templateType := range template.ResourceTypes {
		// Check for exact match
		if string(templateType) == resourceType {
			return true
		}
		
		// Check for wildcard matches
		if strings.Contains(string(templateType), "*") {
			pattern := strings.ReplaceAll(string(templateType), "*", ".*")
			match, err := regexp.MatchString(pattern, resourceType)
			if err == nil && match {
				return true
			}
		}
	}
	
	return false
}

// matchesProvider checks if a template matches the provider
func (m *TemplateMatcher) matchesProvider(template *models.WorkflowTemplate, resource *models.Resource) bool {
	if len(template.Providers) == 0 {
		// Empty list means match all providers
		return true
	}
	
	for _, provider := range template.Providers {
		if provider == resource.Provider {
			return true
		}
	}
	
	return false
}

// calculateTagScore calculates how well tags match
func (m *TemplateMatcher) calculateTagScore(template *models.WorkflowTemplate, resource *models.Resource) int {
	if len(template.Tags) == 0 {
		return 0
	}
	
	matches := 0
	
	for key, value := range template.Tags {
		if resourceValue, exists := resource.Tags[key]; exists {
			// Check for wildcard value
			if value == "*" || resourceValue == value {
				matches++
			}
		}
	}
	
	return matches
}

// matchesSeverity checks if the template is appropriate for the drift severity
func (m *TemplateMatcher) matchesSeverity(template *models.WorkflowTemplate, drift *models.Drift) bool {
	// Check if template has severity preferences
	var severities []string
	
	if severityPref, ok := template.Properties["severities"].([]string); ok && len(severityPref) > 0 {
		severities = severityPref
	} else if severityPref, ok := template.Properties["severity"].(string); ok && severityPref != "" {
		severities = []string{severityPref}
	} else {
		// No severity preference means match all
		return true
	}
	
	for _, severity := range severities {
		if string(drift.Severity) == severity {
			return true
		}
	}
	
	return false
}

// calculateChangeScore checks how well a template matches the property changes
func (m *TemplateMatcher) calculateChangeScore(template *models.WorkflowTemplate, drift *models.Drift) int {
	// Check if template has property change preferences
	var propertyPatterns []string
	
	if propPatterns, ok := template.Properties["property_patterns"].([]string); ok && len(propPatterns) > 0 {
		propertyPatterns = propPatterns
	} else {
		return 0
	}
	
	matches := 0
	
	for _, pattern := range propertyPatterns {
		for _, change := range drift.Changes {
			match, err := regexp.MatchString(pattern, change.PropertyPath)
			if err == nil && match {
				matches++
				break
			}
		}
	}
	
	return matches
}

// CreateDefaultTemplates creates some standard workflow templates
func (m *TemplateMatcher) CreateDefaultTemplates() error {
	// Create a default notification-only template
	notifyTemplate := &models.WorkflowTemplate{
		ID:          "default-notification",
		Name:        "Default Notification Workflow",
		Description: "A simple workflow that sends a notification when drift is detected",
		IsDefault:   true,
		CreatedAt:   timeNow(),
		UpdatedAt:   timeNow(),
	}
	
	// Add a simple notification action
	notifyAction := models.WorkflowActionTemplate{
		Type:        models.ActionTypeNotify,
		Name:        "Send Drift Notification",
		Description: "Notifies the team about detected drift",
		Order:       0,
		Config: models.ActionConfig{
			Message:    "Drift detected in {{.resource.Name}} ({{.resource.Type}}). Severity: {{.drift.Severity}}",
			TemplateID: "drift-notification",
		},
	}
	
	notifyTemplate.Actions = []models.WorkflowActionTemplate{notifyAction}
	
	// Create an approval+remediation template for critical resources
	criticalTemplate := &models.WorkflowTemplate{
		ID:          "critical-approval-remediation",
		Name:        "Critical Resource Approval Workflow",
		Description: "A workflow for critical resources that requires approval before remediation",
		IsDefault:   false,
		CreatedAt:   timeNow(),
		UpdatedAt:   timeNow(),
		ResourceTypes: []models.ResourceType{
			models.ResourceTypeS3Bucket,
			models.ResourceTypeSecurityGroup,
		},
		Providers: []models.ProviderType{
			models.ProviderAWS,
			models.ProviderAzure,
		},
		Tags: models.Tags{
			"environment": "production",
			"criticality": "high",
		},
		Properties: map[string]interface{}{
			"severities": []string{
				string(models.DriftSeverityCritical),
				string(models.DriftSeverityHigh),
			},
		},
	}
	
	// Add workflow actions
	criticalNotifyAction := models.WorkflowActionTemplate{
		Type:        models.ActionTypeNotify,
		Name:        "Send Critical Drift Alert",
		Description: "Notifies the security team about critical drift",
		Order:       0,
		Config: models.ActionConfig{
			Message:    "CRITICAL: Security drift detected in {{.resource.Name}}",
			TemplateID: "critical-alert",
			Channels:   []string{"security-alerts"},
		},
	}
	
	approvalAction := models.WorkflowActionTemplate{
		Type:        models.ActionTypeApproval,
		Name:        "Security Team Approval",
		Description: "Requires approval from the security team",
		Order:       1,
		Config: models.ActionConfig{
			ApprovalTimeout: "24h",
			MinApprovals:    2,
			Approvers:       []string{"security-team"},
		},
	}
	
	remediateAction := models.WorkflowActionTemplate{
		Type:        models.ActionTypeRemediate,
		Name:        "Auto-Remediate",
		Description: "Automatically fixes the drift if approved",
		Order:       2,
		Config: models.ActionConfig{
			RemediationType: "auto",
		},
	}
	
	criticalTemplate.Actions = []models.WorkflowActionTemplate{
		criticalNotifyAction,
		approvalAction,
		remediateAction,
	}
	
	// Save templates to database
	if err := m.db.CreateWorkflowTemplate(notifyTemplate); err != nil {
		return fmt.Errorf("failed to create default template: %w", err)
	}
	
	if err := m.db.CreateWorkflowTemplate(criticalTemplate); err != nil {
		return fmt.Errorf("failed to create critical template: %w", err)
	}
	
	return nil
}

// timeNow is a helper to get current time (makes testing easier)
func timeNow() time.Time {
	return time.Now()
}