package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/internal/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
)

// Service manages sending notifications through various channels
type Service struct {
	config config.NotificationConfig
	db     *database.DB
	templates map[string]*template.Template
	
	// Channel providers
	slackProvider    *SlackProvider
	emailProvider    *EmailProvider
	webhookProvider  *WebhookProvider
	matterMostProvider *MatterMostProvider
	teamsProvider    *TeamsProvider
}

// New creates a new notification service
func New(config config.NotificationConfig, db *database.DB) *Service {
	service := &Service{
		config:    config,
		db:        db,
		templates: make(map[string]*template.Template),
	}
	
	// Initialize providers
	service.slackProvider = NewSlackProvider(config.Slack)
	service.emailProvider = NewEmailProvider(config.Email)
	service.webhookProvider = NewWebhookProvider()
	service.matterMostProvider = NewMatterMostProvider(config.MatterMost)
	service.teamsProvider = NewTeamsProvider(config.Teams)
	
	// Load templates from database
	service.loadTemplates()
	
	// Create default templates if needed
	service.ensureDefaultTemplates()
	
	return service
}

// loadTemplates loads notification templates from the database
func (s *Service) loadTemplates() {
	templates, err := s.db.GetNotificationTemplates()
	if err != nil {
		log.Printf("Error loading notification templates: %v", err)
		return
	}
	
	for _, tmpl := range templates {
		parsed, err := template.New(tmpl.ID).Parse(tmpl.Content)
		if err != nil {
			log.Printf("Error parsing template %s: %v", tmpl.ID, err)
			continue
		}
		
		s.templates[tmpl.ID] = parsed
	}
}

// ensureDefaultTemplates creates default notification templates if they don't exist
func (s *Service) ensureDefaultTemplates() {
	// Default drift notification template
	driftTemplate := `
# Infrastructure Drift Detected

## Resource Information
- **Name**: {{.resource.Name}}
- **Type**: {{.resource.Type}}
- **Provider**: {{.resource.Provider}}
- **Region**: {{.resource.Region}}

## Drift Details
- **Severity**: {{.drift.Severity}}
- **Detected At**: {{.drift.DetectedAt.Format "Jan 02, 2006 15:04:05"}}
- **Changes**: {{len .drift.Changes}}

## Changes
{{range .drift.Changes}}
- **Path**: {{.PropertyPath}}  
  **Change Type**: {{.ChangeType}}  
  **Expected**: {{.ExpectedValue}}  
  **Actual**: {{.ActualValue}}
{{end}}

## Workflow
{{if .workflow}}
A workflow has been created to address this drift: {{.workflow.Name}}
{{else}}
No workflow has been created for this drift.
{{end}}
`

	// Critical alert template
	criticalTemplate := `
# CRITICAL SECURITY DRIFT DETECTED

## IMMEDIATE ATTENTION REQUIRED

## Resource Information
- **Name**: {{.resource.Name}}
- **Type**: {{.resource.Type}}
- **Provider**: {{.resource.Provider}}
- **Region**: {{.resource.Region}}

## Drift Details
- **Severity**: {{.drift.Severity}}
- **Detected At**: {{.drift.DetectedAt.Format "Jan 02, 2006 15:04:05"}}

## Changes
{{range .drift.Changes}}
- **Path**: {{.PropertyPath}}  
  **Change Type**: {{.ChangeType}}  
  **Expected**: {{.ExpectedValue}}  
  **Actual**: {{.ActualValue}}
{{end}}

## Action Required
Please review and approve the remediation workflow: {{.workflow.Name}}
`

	// Approval request template
	approvalTemplate := `
# Approval Required: Infrastructure Drift Remediation

## Resource Information
- **Name**: {{.resource.Name}}
- **Type**: {{.resource.Type}}
- **Provider**: {{.resource.Provider}}

## Drift Details
- **Severity**: {{.drift.Severity}}
- **Detected At**: {{.drift.DetectedAt.Format "Jan 02, 2006 15:04:05"}}

## Proposed Remediation
{{if .plan}}
The following changes will be made:

{{.plan}}
{{else}}
The system will attempt to reconcile the infrastructure with the IaC definition.
{{end}}

## Approval Information
- **Required Approvals**: {{.approvalRequest.MinApprovals}}
- **Current Approvals**: {{len .approvalRequest.Approvals}}
- **Expires At**: {{if .approvalRequest.ExpiresAt}}{{.approvalRequest.ExpiresAt.Format "Jan 02, 2006 15:04:05"}}{{else}}No expiration{{end}}

Please use the web UI to approve or reject this request.
`

	// Create templates in the database if needed
	templates := []struct {
		id      string
		name    string
		content string
	}{
		{"drift-notification", "Default Drift Notification", driftTemplate},
		{"critical-alert", "Critical Security Drift Alert", criticalTemplate},
		{"approval-request", "Approval Request", approvalTemplate},
	}

	for _, t := range templates {
		// Check if template exists
		_, err := s.db.GetNotificationTemplate(t.id)
		if err != nil {
			// Template doesn't exist, create it
			template := database.NotificationTemplate{
				ID:      t.id,
				Name:    t.name,
				Content: t.content,
			}
			
			if err := s.db.CreateNotificationTemplate(&template); err != nil {
				log.Printf("Error creating default template %s: %v", t.id, err)
			} else {
				// Parse and add to memory
				parsed, err := template.New(t.id).Parse(t.content)
				if err != nil {
					log.Printf("Error parsing template %s: %v", t.id, err)
				} else {
					s.templates[t.id] = parsed
				}
			}
		}
	}
}

// Send sends a notification through a specific channel
func (s *Service) Send(channelID string, message string, data map[string]interface{}) error {
	// Get channel info from database
	channel, err := s.db.GetNotificationChannel(channelID)
	if err != nil {
		return fmt.Errorf("channel not found: %w", err)
	}
	
	log.Printf("Sending notification via channel %s (%s)", channel.Name, channel.Type)
	
	switch channel.Type {
	case "slack":
		return s.slackProvider.Send(channel.Config, message, data)
	case "email":
		return s.emailProvider.Send(channel.Config, message, data)
	case "webhook":
		return s.webhookProvider.Send(channel.Config, message, data)
	case "mattermost":
		return s.matterMostProvider.Send(channel.Config, message, data)
	case "teams":
		return s.teamsProvider.Send(channel.Config, message, data)
	default:
		return fmt.Errorf("unsupported channel type: %s", channel.Type)
	}
}

// SendToRecipient sends a notification to a specific recipient
func (s *Service) SendToRecipient(recipientID string, message string, data map[string]interface{}) error {
	// Get recipient info from database
	recipient, err := s.db.GetNotificationRecipient(recipientID)
	if err != nil {
		return fmt.Errorf("recipient not found: %w", err)
	}
	
	log.Printf("Sending notification to recipient %s", recipient.Name)
	
	// Send to all recipient channels
	var lastErr error
	sentCount := 0
	
	for _, channelID := range recipient.Channels {
		if err := s.Send(channelID, message, data); err != nil {
			log.Printf("Error sending to channel %s: %v", channelID, err)
			lastErr = err
		} else {
			sentCount++
		}
	}
	
	// If we couldn't send to any channel, return the last error
	if sentCount == 0 && lastErr != nil {
		return fmt.Errorf("failed to send to any channel: %w", lastErr)
	}
	
	return nil
}

// SendToGroup sends a notification to a group of recipients
func (s *Service) SendToGroup(groupID string, message string, data map[string]interface{}) error {
	// Get group recipients
	recipients, err := s.db.GetGroupRecipients(groupID)
	if err != nil {
		return fmt.Errorf("failed to get group recipients: %w", err)
	}
	
	log.Printf("Sending notification to group %s (%d recipients)", groupID, len(recipients))
	
	// Send to all recipients in the group
	var lastErr error
	sentCount := 0
	
	for _, recipient := range recipients {
		if err := s.SendToRecipient(recipient, message, data); err != nil {
			log.Printf("Error sending to recipient %s: %v", recipient, err)
			lastErr = err
		} else {
			sentCount++
		}
	}
	
	// If we couldn't send to any recipient, return the last error
	if sentCount == 0 && lastErr != nil {
		return fmt.Errorf("failed to send to any recipient: %w", lastErr)
	}
	
	return nil
}

// RenderTemplate renders a notification template with data
func (s *Service) RenderTemplate(templateID string, data map[string]interface{}) (string, error) {
	tmpl, exists := s.templates[templateID]
	if !exists {
		// Try to load it from the database
		template, err := s.db.GetNotificationTemplate(templateID)
		if err != nil {
			return "", fmt.Errorf("template not found: %w", err)
		}
		
		// Parse the template
		tmpl, err = template.New(templateID).Parse(template.Content)
		if err != nil {
			return "", fmt.Errorf("error parsing template: %w", err)
		}
		
		// Save for future use
		s.templates[templateID] = tmpl
	}
	
	// Render the template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("error rendering template: %w", err)
	}
	
	return buf.String(), nil
}

// Provider interface for notification channels
type Provider interface {
	Send(config map[string]interface{}, message string, data map[string]interface{}) error
}

// SlackProvider provides Slack notifications
type SlackProvider struct {
	config map[string]interface{}
}

// NewSlackProvider creates a new Slack provider
func NewSlackProvider(config map[string]interface{}) *SlackProvider {
	return &SlackProvider{
		config: config,
	}
}

// Send sends a notification through Slack
func (p *SlackProvider) Send(channelConfig map[string]interface{}, message string, data map[string]interface{}) error {
	// Get webhook URL from channel config
	webhookURL, ok := channelConfig["webhook_url"].(string)
	if !ok {
		return fmt.Errorf("webhook URL not found in channel config")
	}
	
	// Create the Slack message payload
	payload := map[string]interface{}{
		"text": message,
	}
	
	// Add channel if specified
	if channelName, ok := channelConfig["channel"].(string); ok && channelName != "" {
		payload["channel"] = channelName
	}
	
	// Add blocks if available
	if blocks, ok := data["blocks"].([]map[string]interface{}); ok {
		payload["blocks"] = blocks
	} else {
		// Convert message to blocks for better formatting
		blocks := []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": message,
				},
			},
		}
		payload["blocks"] = blocks
	}
	
	// Add attachments if available
	if attachments, ok := data["attachments"].([]map[string]interface{}); ok {
		payload["attachments"] = attachments
	}
	
	// Send the HTTP request
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %w", err)
	}
	
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("error sending webhook request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK response: %s", resp.Status)
	}
	
	return nil
}

// EmailProvider provides email notifications
type EmailProvider struct {
	config map[string]interface{}
}

// NewEmailProvider creates a new email provider
func NewEmailProvider(config map[string]interface{}) *EmailProvider {
	return &EmailProvider{
		config: config,
	}
}

// Send sends a notification through email
func (p *EmailProvider) Send(channelConfig map[string]interface{}, message string, data map[string]interface{}) error {
	// Email implementation would typically use SMTP
	// This is a placeholder for a real email implementation
	
	// Get necessary config
	smtpServer, _ := p.config["smtp_server"].(string)
	smtpPort, _ := p.config["smtp_port"].(float64)
	fromEmail, _ := p.config["from_email"].(string)
	
	// Get recipient from channel config
	toEmail, ok := channelConfig["email"].(string)
	if !ok {
		return fmt.Errorf("recipient email not found in channel config")
	}
	
	// Get subject from data or use default
	subject := "Infrastructure Drift Notification"
	if subjectData, ok := data["subject"].(string); ok {
		subject = subjectData
	}
	
	log.Printf("Would send email via SMTP %s:%d from %s to %s with subject: %s", 
		smtpServer, int(smtpPort), fromEmail, toEmail, subject)
	log.Printf("Email body: %s", message)
	
	// In a real implementation, this would connect to the SMTP server and send the email
	
	return nil
}

// WebhookProvider provides webhook notifications
type WebhookProvider struct{}

// NewWebhookProvider creates a new webhook provider
func NewWebhookProvider() *WebhookProvider {
	return &WebhookProvider{}
}

// Send sends a notification through a webhook
func (p *WebhookProvider) Send(channelConfig map[string]interface{}, message string, data map[string]interface{}) error {
	// Get webhook URL from channel config
	webhookURL, ok := channelConfig["url"].(string)
	if !ok {
		return fmt.Errorf("webhook URL not found in channel config")
	}
	
	// Create the payload
	payload := map[string]interface{}{
		"message": message,
		"timestamp": time.Now().Format(time.RFC3339),
	}
	
	// Add data if available
	if data != nil {
		payload["data"] = data
	}
	
	// Send the HTTP request
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %w", err)
	}
	
	// Set method (POST by default)
	method := "POST"
	if methodConfig, ok := channelConfig["method"].(string); ok && methodConfig != "" {
		method = methodConfig
	}
	
	// Create request
	req, err := http.NewRequest(method, webhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	
	// Add custom headers if specified
	if headers, ok := channelConfig["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			if strValue, ok := value.(string); ok {
				req.Header.Set(key, strValue)
			}
		}
	}
	
	// Send the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending webhook request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("received non-success response: %s", resp.Status)
	}
	
	return nil
}

// MatterMostProvider provides MatterMost notifications
type MatterMostProvider struct {
	config map[string]interface{}
}

// NewMatterMostProvider creates a new MatterMost provider
func NewMatterMostProvider(config map[string]interface{}) *MatterMostProvider {
	return &MatterMostProvider{
		config: config,
	}
}

// Send sends a notification through MatterMost
func (p *MatterMostProvider) Send(channelConfig map[string]interface{}, message string, data map[string]interface{}) error {
	// Get webhook URL from channel config
	webhookURL, ok := channelConfig["webhook_url"].(string)
	if !ok {
		return fmt.Errorf("webhook URL not found in channel config")
	}
	
	// Create the MatterMost message payload
	payload := map[string]interface{}{
		"text": message,
	}
	
	// Add channel if specified
	if channelName, ok := channelConfig["channel"].(string); ok && channelName != "" {
		payload["channel"] = channelName
	}
	
	// Add username if specified
	if username, ok := channelConfig["username"].(string); ok && username != "" {
		payload["username"] = username
	}
	
	// Add icon URL if specified
	if iconURL, ok := channelConfig["icon_url"].(string); ok && iconURL != "" {
		payload["icon_url"] = iconURL
	}
	
	// Add attachments for better formatting
	if attachments, ok := data["attachments"].([]map[string]interface{}); ok {
		payload["attachments"] = attachments
	} else {
		// Create a simple attachment with the message
		attachments := []map[string]interface{}{
			{
				"fallback": message,
				"color":    "#FF9000", // Orange color for drift notifications
				"text":     message,
			},
		}
		
		// Add title if available
		if title, ok := data["title"].(string); ok {
			attachments[0]["title"] = title
		} else {
			attachments[0]["title"] = "Infrastructure Drift Notification"
		}
		
		payload["attachments"] = attachments
	}
	
	// Send the HTTP request
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %w", err)
	}
	
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("error sending webhook request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK response: %s", resp.Status)
	}
	
	return nil
}

// TeamsProvider provides Microsoft Teams notifications
type TeamsProvider struct {
	config map[string]interface{}
}

// NewTeamsProvider creates a new Microsoft Teams provider
func NewTeamsProvider(config map[string]interface{}) *TeamsProvider {
	return &TeamsProvider{
		config: config,
	}
}

// Send sends a notification through Microsoft Teams
func (p *TeamsProvider) Send(channelConfig map[string]interface{}, message string, data map[string]interface{}) error {
	// Get webhook URL from channel config
	webhookURL, ok := channelConfig["webhook_url"].(string)
	if !ok {
		return fmt.Errorf("webhook URL not found in channel config")
	}
	
	// Create the Teams message payload
	// Teams uses a different format called "Adaptive Cards"
	title := "Infrastructure Drift Notification"
	if titleData, ok := data["title"].(string); ok {
		title = titleData
	}
	
	// Format using Teams Adaptive Card schema
	payload := map[string]interface{}{
		"@type":    "MessageCard",
		"@context": "http://schema.org/extensions",
		"summary":  title,
		"title":    title,
		"text":     message,
		"themeColor": "0078D7", // Blue color
	}
	
	// Add sections if available
	if sections, ok := data["sections"].([]map[string]interface{}); ok {
		payload["sections"] = sections
	} else if drift, ok := data["drift"].(map[string]interface{}); ok {
		// Create a section with drift information
		section := map[string]interface{}{
			"facts": []map[string]string{
				{"name": "Resource", "value": fmt.Sprintf("%v", data["resource"].(map[string]interface{})["Name"])},
				{"name": "Severity", "value": fmt.Sprintf("%v", drift["Severity"])},
				{"name": "Detected At", "value": fmt.Sprintf("%v", drift["DetectedAt"])},
			},
		}
		payload["sections"] = []map[string]interface{}{section}
	}
	
	// Add potential actions
	if actions, ok := data["actions"].([]map[string]interface{}); ok {
		payload["potentialAction"] = actions
	} else if workflow, ok := data["workflow"].(map[string]interface{}); ok {
		// Create an action to view the workflow
		action := map[string]interface{}{
			"@type": "OpenUri",
			"name":  "View Workflow",
			"targets": []map[string]string{
				{"os": "default", "uri": fmt.Sprintf("/workflows/%v", workflow["ID"])},
			},
		}
		payload["potentialAction"] = []map[string]interface{}{action}
	}
	
	// Send the HTTP request
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %w", err)
	}
	
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("error sending webhook request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("received non-success response: %s", resp.Status)
	}
	
	return nil
}