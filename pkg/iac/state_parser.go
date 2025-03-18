package iac

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/logging"
)

// ResourceState holds the parsed state of a Terraform resource
type ResourceState struct {
	ResourceType string                 `json:"resource_type"`
	ResourceName string                 `json:"resource_name"`
	ResourceID   string                 `json:"resource_id"`
	ProviderName string                 `json:"provider_name"`
	ModulePath   string                 `json:"module_path"`
	Attributes   map[string]interface{} `json:"attributes"`
	Dependencies []string               `json:"dependencies"`
}

// TerraformStateParser is responsible for parsing Terraform state files
type TerraformStateParser struct {
	logger *logging.Logger
}

// NewTerraformStateParser creates a new parser instance
func NewTerraformStateParser() *TerraformStateParser {
	return &TerraformStateParser{
		logger: logging.GetGlobalLogger().WithField("component", "terraform_state_parser"),
	}
}

// ParseStateFile parses a Terraform state file and returns the resource states
func (p *TerraformStateParser) ParseStateFile(filePath string, resourceTypes []string) (map[string]ResourceState, error) {
	// Read state file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Terraform state file: %w", err)
	}

	// Parse state file
	var tfState tfjson.State
	if err := json.Unmarshal(data, &tfState); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Terraform state file: %w", err)
	}

	p.logger.Info("Parsed Terraform state file %s (format version: %s, terraform version: %s)", 
		filePath, tfState.FormatVersion, tfState.TerraformVersion)

	// Extract resources
	resources := make(map[string]ResourceState)
	resourceTypeFilter := make(map[string]bool)
	
	// Build resource type filter
	for _, rt := range resourceTypes {
		resourceTypeFilter[rt] = true
	}

	// Process resources in the state
	if tfState.Values != nil && tfState.Values.RootModule != nil {
		// Process root module and nested modules recursively
		processModule(tfState.Values.RootModule, "root", resources, resourceTypeFilter, p.logger)
	}
	p.logger.Info("Extracted %d resources from Terraform state", len(resources))
	return resources, nil
}

// processModule processes a module and its resources recursively
func processModule(module *tfjson.StateModule, modulePath string, resources map[string]ResourceState, resourceTypeFilter map[string]bool, logger *logging.Logger) {
	// Process resources in this module
	for _, res := range module.Resources {
		// Skip non-managed resources
		if res.Mode != "managed" {
			continue
		}

		// Apply resource type filter if specified
		if len(resourceTypeFilter) > 0 && !resourceTypeFilter[res.Type] {
			continue
		}

		// Generate unique resource key
		resourceKey := fmt.Sprintf("%s.%s", res.Type, res.Name)
		if modulePath != "root" {
			resourceKey = fmt.Sprintf("%s.%s", modulePath, resourceKey)
		}

		// Extract resource ID and provider
		var resourceID string
		providerName := ""

		if res.ProviderName != "" {
			parts := strings.Split(res.ProviderName, "/")
			if len(parts) > 0 {
				providerName = parts[0]
			}
		}

		// Extract attributes and dependencies
		var dependencies []string
		if res.DependsOn != nil {
			dependencies = res.DependsOn
		}
		
		// Try to get the ID based on common ID field names
		idFields := []string{"id", "arn", "name"}
		for _, field := range idFields {
			if val, ok := res.AttributeValues[field]; ok {
				if idStr, ok := val.(string); ok && idStr != "" {
					resourceID = idStr
					break
				}
			}
		}

		// Store resource state
		resources[resourceKey] = ResourceState{
			ResourceType: res.Type,
			ResourceName: res.Name,
			ResourceID:   resourceID,
			ProviderName: providerName,
			ModulePath:   modulePath,
			Attributes:   res.AttributeValues,
			Dependencies: dependencies,
		}
	}

	// Process child modules recursively
	for _, childModule := range module.ChildModules {
		// Create child module path
		childPath := childModule.Address
		if modulePath != "root" {
			childPath = fmt.Sprintf("%s.%s", modulePath, childModule.Address)
		}
		
		// Process child module
		processModule(childModule, childPath, resources, resourceTypeFilter, logger)
	}
}

// GetResourceTypeFromAddress extracts the resource type from a resource address
func GetResourceTypeFromAddress(address string) string {
	parts := strings.Split(address, ".")
	if len(parts) >= 2 {
		return parts[0]
	}
	return ""
}

// GetResourceNameFromAddress extracts the resource name from a resource address
func GetResourceNameFromAddress(address string) string {
	parts := strings.Split(address, ".")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// FilterResourcesByType filters resources by their type
func FilterResourcesByType(resources map[string]ResourceState, resourceTypes []string) map[string]ResourceState {
	// If no filter is provided, return all resources
	if len(resourceTypes) == 0 {
		return resources
	}

	// Create type lookup map
	typeLookup := make(map[string]bool)
	for _, rt := range resourceTypes {
		typeLookup[rt] = true
	}

	// Filter resources
	filtered := make(map[string]ResourceState)
	for key, resource := range resources {
		if typeLookup[resource.ResourceType] {
			filtered[key] = resource
		}
	}

	return filtered
}

// GroupResourcesByType groups resources by their type
func GroupResourcesByType(resources map[string]ResourceState) map[string]map[string]ResourceState {
	grouped := make(map[string]map[string]ResourceState)
	
	for key, resource := range resources {
		if _, ok := grouped[resource.ResourceType]; !ok {
			grouped[resource.ResourceType] = make(map[string]ResourceState)
		}
		grouped[resource.ResourceType][key] = resource
	}
	
	return grouped
}