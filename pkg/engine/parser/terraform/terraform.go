package parser

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
)

// TerraformAdapter implements the IaCAdapter interface for Terraform
type TerraformAdapter struct{}

// NewTerraformAdapter creates a new Terraform adapter
func NewTerraformAdapter() *TerraformAdapter {
	return &TerraformAdapter{}
}

// ParseFile parses a Terraform file to extract resources and their expected states
func (a *TerraformAdapter) ParseFile(filePath string) ([]*models.Resource, []*models.ResourceState, error) {
	// For a single file, we need to find the directory that contains it
	dirPath := filepath.Dir(filePath)
	return a.ParseDirectory(dirPath)
}

// ParseDirectory parses a directory of Terraform files
func (a *TerraformAdapter) ParseDirectory(dirPath string) ([]*models.Resource, []*models.ResourceState, error) {
	// Check if terraform binary is available
	if _, err := exec.LookPath("terraform"); err != nil {
		return nil, nil, fmt.Errorf("terraform binary not found: %w", err)
	}

	// Initialize workspace if needed
	initCmd := exec.Command("terraform", "init", "-no-color")
	initCmd.Dir = dirPath
	if output, err := initCmd.CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("terraform init failed: %s, %w", output, err)
	}

	// Run terraform show to get the current state
	showCmd := exec.Command("terraform", "show", "-json")
	showCmd.Dir = dirPath
	showOutput, err := showCmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("terraform show failed: %w", err)
	}

	// Parse the JSON state
	var tfState TerraformState
	if err := json.Unmarshal(showOutput, &tfState); err != nil {
		return nil, nil, fmt.Errorf("failed to parse terraform state: %w", err)
	}

	// Extract resources and states
	resources := make([]*models.Resource, 0)
	states := make([]*models.ResourceState, 0)

	if tfState.Values != nil && tfState.Values.RootModule != nil {
		// Process root module resources
		rootResources, rootStates := a.processModuleResources(*tfState.Values.RootModule, "", dirPath)
		resources = append(resources, rootResources...)
		states = append(states, rootStates...)

		// Process child module resources
		for _, childModule := range tfState.Values.RootModule.ChildModules {
			childResources, childStates := a.processModule(childModule, dirPath)
			resources = append(resources, childResources...)
			states = append(states, childStates...)
		}
	}

	return resources, states, nil
}

// processModule processes a Terraform module and its child modules
func (a *TerraformAdapter) processModule(module TerraformModule, dirPath string) ([]*models.Resource, []*models.ResourceState) {
	resources, states := a.processModuleResources(module, module.Address, dirPath)

	// Process child modules recursively
	for _, childModule := range module.ChildModules {
		childResources, childStates := a.processModule(childModule, dirPath)
		resources = append(resources, childResources...)
		states = append(states, childStates...)
	}

	return resources, states
}

// processModuleResources processes resources in a Terraform module
func (a *TerraformAdapter) processModuleResources(module TerraformModule, moduleAddress string, dirPath string) ([]*models.Resource, []*models.ResourceState) {
	resources := make([]*models.Resource, 0, len(module.Resources))
	states := make([]*models.ResourceState, 0, len(module.Resources))

	for _, tfResource := range module.Resources {
		// Skip data sources
		if tfResource.Mode == "data" {
			continue
		}

		// Determine provider type
		provider := a.getProviderFromType(tfResource.Type)

		// Create resource model
		resource := &models.Resource{
			ID:        a.GenerateResourceID(tfResource.AttributeValues, provider),
			Name:      tfResource.Name,
			Type:      a.getResourceType(tfResource.Type, provider),
			Provider:  provider,
			IaCType:   models.IaCTypeTerraform,
			Region:    a.getRegionFromTerraformResource(tfResource),
			Account:   a.getAccountFromTerraformResource(tfResource),
			Properties: make(models.Properties),
			Tags:      a.extractTags(tfResource.AttributeValues),
		}

		// Add module info to properties if in a module
		if moduleAddress != "" {
			resource.Properties["terraform_module"] = moduleAddress
		}

		// Extract properties
		for k, v := range tfResource.AttributeValues {
			if k != "tags" && k != "id" {
				resource.Properties[k] = v
			}
		}

		// Create resource state
		state := &models.ResourceState{
			ResourceID:   resource.ID,
			StateType:    models.StateTypeExpected,
			Properties:   resource.Properties,
			CapturedAt:   time.Now(),
			StateVersion: uuid.New().String(),
			Source:       models.StateSourceTerraform,
		}

		resources = append(resources, resource)
		states = append(states, state)
	}

	return resources, states
}

// GenerateResourceID generates a consistent ID for a Terraform resource
func (a *TerraformAdapter) GenerateResourceID(resource map[string]interface{}, provider models.ProviderType) string {
	// Use the resource's own ID if available
	if id, ok := resource["id"].(string); ok && id != "" {
		return id
	}

	// Otherwise, create a UUID
	return uuid.New().String()
}

// getProviderFromType extracts the provider from the resource type
func (a *TerraformAdapter) getProviderFromType(resourceType string) models.ProviderType {
	// Resource type format is typically "provider_resource"
	parts := strings.Split(resourceType, "_")
	if len(parts) > 0 {
		switch parts[0] {
		case "aws":
			return models.ProviderAWS
		case "azurerm":
			return models.ProviderAzure
		case "google":
			return models.ProviderGCP
		case "kubernetes":
			return models.ProviderKubernetes
		}
	}
	
	return models.ProviderType(parts[0])
}

// getResourceType converts a Terraform resource type to our resource type
func (a *TerraformAdapter) getResourceType(tfType string, provider models.ProviderType) models.ResourceType {
	// Map common resource types
	switch provider {
	case models.ProviderAWS:
		if tfType == "aws_instance" {
			return models.ResourceTypeEC2Instance
		} else if tfType == "aws_s3_bucket" {
			return models.ResourceTypeS3Bucket
		} else if tfType == "aws_security_group" {
			return models.ResourceTypeSecurityGroup
		}
	case models.ProviderAzure:
		if tfType == "azurerm_virtual_machine" || tfType == "azurerm_linux_virtual_machine" || tfType == "azurerm_windows_virtual_machine" {
			return models.ResourceTypeAzureVM
		}
	case models.ProviderGCP:
		if tfType == "google_compute_instance" {
			return models.ResourceTypeGCPInstance
		}
	}
	
	// Default to the terraform type if no mapping exists
	return models.ResourceType(tfType)
}

// getRegionFromTerraformResource attempts to determine the region from resource attributes
func (a *TerraformAdapter) getRegionFromTerraformResource(resource TerraformResource) string {
	// First, check if there's an explicit region/location attribute
	if region, ok := resource.AttributeValues["region"].(string); ok {
		return region
	}
	
	if location, ok := resource.AttributeValues["location"].(string); ok {
		return location
	}
	
	// For AWS, we might find it in an ARN
	if arn, ok := resource.AttributeValues["arn"].(string); ok {
		// ARN format: arn:partition:service:region:account-id:resource-id
		parts := strings.Split(arn, ":")
		if len(parts) >= 4 {
			return parts[3]
		}
	}
	
	// Default to empty string if we can't determine
	return ""
}

// getAccountFromTerraformResource attempts to determine the account from resource attributes
func (a *TerraformAdapter) getAccountFromTerraformResource(resource TerraformResource) string {
	// Check for specific provider attributes
	switch {
	case strings.HasPrefix(resource.Type, "aws_"):
		// For AWS, check the ARN which contains the account ID
		if arn, ok := resource.AttributeValues["arn"].(string); ok {
			// ARN format: arn:partition:service:region:account-id:resource-id
			parts := strings.Split(arn, ":")
			if len(parts) >= 5 {
				return parts[4]
			}
		}
	case strings.HasPrefix(resource.Type, "azurerm_"):
		// For Azure, check subscription_id
		if subID, ok := resource.AttributeValues["subscription_id"].(string); ok {
			return subID
		}
		
		// Try to extract from ID
		if id, ok := resource.AttributeValues["id"].(string); ok {
			// Azure IDs often have format /subscriptions/{subscription-id}/...
			if strings.Contains(id, "/subscriptions/") {
				parts := strings.Split(id, "/")
				for i, part := range parts {
					if part == "subscriptions" && i+1 < len(parts) {
						return parts[i+1]
					}
				}
			}
		}
	case strings.HasPrefix(resource.Type, "google_"):
		// For GCP, check project
		if project, ok := resource.AttributeValues["project"].(string); ok {
			return project
		}
	}
	
	return ""
}

// extractTags extracts tags from resource attributes
func (a *TerraformAdapter) extractTags(attributes map[string]interface{}) models.Tags {
	tags := make(models.Tags)
	
	// Check for tags attribute
	if tagsAttr, ok := attributes["tags"]; ok {
		// Handle tags as map[string]string
		if tagsMap, ok := tagsAttr.(map[string]interface{}); ok {
			for k, v := range tagsMap {
				if strVal, ok := v.(string); ok {
					tags[k] = strVal
				} else {
					tags[k] = fmt.Sprintf("%v", v)
				}
			}
		}
	}
	
	return tags
}

// TerraformState represents the Terraform state JSON structure
type TerraformState struct {
	FormatVersion    string         `json:"format_version"`
	TerraformVersion string         `json:"terraform_version"`
	Values           *TerraformValues `json:"values"`
}

// TerraformValues contains the values from Terraform state
type TerraformValues struct {
	RootModule *TerraformModule `json:"root_module"`
}

// TerraformModule represents a module in the Terraform state
type TerraformModule struct {
	Resources    []TerraformResource `json:"resources"`
	Address      string             `json:"address"`
	ChildModules []TerraformModule  `json:"child_modules"`
}

// TerraformResource represents a resource in the Terraform state
type TerraformResource struct {
	Address         string                 `json:"address"`
	Mode            string                 `json:"mode"`
	Type            string                 `json:"type"`
	Name            string                 `json:"name"`
	Provider        string                 `json:"provider_name"`
	AttributeValues map[string]interface{} `json:"values"`
}