package arm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
)

// ARMAdapter implements the IaCAdapter interface for Azure Resource Manager Templates
type ARMAdapter struct{}

// NewARMAdapter creates a new ARM template adapter
func NewARMAdapter() *ARMAdapter {
	return &ARMAdapter{}
}

// ParseFile parses an ARM template file
func (a *ARMAdapter) ParseFile(filePath string) ([]*models.Resource, []*models.ResourceState, error) {
	// Read and parse the file
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read ARM template: %w", err)
	}

	// Parse JSON
	var armTemplate map[string]interface{}
	if err := json.Unmarshal(fileContent, &armTemplate); err != nil {
		return nil, nil, fmt.Errorf("failed to parse ARM template JSON: %w", err)
	}

	// Verify this is an ARM template
	schema, ok := armTemplate["$schema"].(string)
	if !ok || !strings.Contains(schema, "deploymentTemplate.json") {
		return nil, nil, fmt.Errorf("file does not appear to be an ARM template")
	}

	// Extract resources
	resourcesArray, ok := armTemplate["resources"].([]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("no resources found in ARM template")
	}

	resources := make([]*models.Resource, 0)
	states := make([]*models.ResourceState, 0)

	// Process resources recursively (ARM templates can nest resources)
	a.processARMResources(resourcesArray, "", &resources, &states)

	return resources, states, nil
}

// processARMResources processes Azure ARM resources, including nested ones
func (a *ARMAdapter) processARMResources(resourcesArray []interface{}, parentName string, resources *[]*models.Resource, states *[]*models.ResourceState) {
	for _, res := range resourcesArray {
		resourceMap, ok := res.(map[string]interface{})
		if !ok {
			continue
		}

		resourceType, typeOk := resourceMap["type"].(string)
		resourceName, nameOk := resourceMap["name"].(string)

		if !typeOk || !nameOk {
			continue
		}

		// Process resource properties
		properties := make(models.Properties)

		// Extract all top-level properties
		for k, v := range resourceMap {
			// Skip some special fields
			if k == "resources" || k == "dependsOn" {
				continue
			}
			properties[k] = v
		}

		// Get full name for nested resources
		fullName := resourceName
		if parentName != "" {
			fullName = fmt.Sprintf("%s/%s", parentName, resourceName)
		}

		// Create resource
		resource := &models.Resource{
			ID:         a.GenerateResourceID(properties, models.ProviderAzure),
			Name:       fullName,
			Type:       a.getResourceType(resourceType),
			Provider:   models.ProviderAzure,
			IaCType:    models.IaCTypeARMTemplate,
			Region:     a.getRegionFromProperties(resourceMap),
			Account:    "", // Will be filled when deployed
			Properties: properties,
			Tags:       a.extractTags(resourceMap),
		}

		// Create expected state
		state := &models.ResourceState{
			ResourceID:   resource.ID,
			StateType:    models.StateTypeExpected,
			Properties:   properties,
			CapturedAt:   time.Now(),
			StateVersion: uuid.New().String(),
			Source:       models.StateSourceAzure,
		}

		*resources = append(*resources, resource)
		*states = append(*states, state)

		// Process nested resources if any
		if nestedResources, ok := resourceMap["resources"].([]interface{}); ok && len(nestedResources) > 0 {
			a.processARMResources(nestedResources, fullName, resources, states)
		}
	}
}

// ParseDirectory parses a directory of ARM templates
func (a *ARMAdapter) ParseDirectory(dirPath string) ([]*models.Resource, []*models.ResourceState, error) {
	var allResources []*models.Resource
	var allStates []*models.ResourceState

	// Walk through the directory and find ARM templates
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Check if this is likely an ARM template
		if strings.HasSuffix(path, ".json") {
			// Try to parse as ARM template
			resources, states, err := a.ParseFile(path)
			if err == nil && len(resources) > 0 {
				allResources = append(allResources, resources...)
				allStates = append(allStates, states...)
			}
		}

		return nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("error walking directory: %w", err)
	}

	return allResources, allStates, nil
}

// GenerateResourceID generates a consistent ID for an ARM template resource
func (a *ARMAdapter) GenerateResourceID(resource map[string]interface{}, provider models.ProviderType) string {
	// Use name or other identifying properties
	if name, ok := resource["name"].(string); ok && name != "" {
		if resourceType, ok := resource["type"].(string); ok && resourceType != "" {
			return fmt.Sprintf("%s/%s", resourceType, name)
		}
		return name
	}

	// Otherwise, create a UUID
	return uuid.New().String()
}

// getResourceType maps ARM resource types to our resource types
func (a *ARMAdapter) getResourceType(armType string) models.ResourceType {
	// Map common ARM resource types to our types
	switch armType {
	case "Microsoft.Compute/virtualMachines":
		return models.ResourceTypeAzureVM
	case "Microsoft.Storage/storageAccounts":
		return models.ResourceType("azure_storage_account")
	case "Microsoft.Network/virtualNetworks":
		return models.ResourceType("azure_virtual_network")
	case "Microsoft.Network/networkSecurityGroups":
		return models.ResourceType("azure_network_security_group")
	}

	// Default to the ARM type
	return models.ResourceType(armType)
}

// getRegionFromProperties attempts to extract region from resource properties
func (a *ARMAdapter) getRegionFromProperties(properties map[string]interface{}) string {
	// Check for location property
	if location, ok := properties["location"].(string); ok {
		return location
	}

	return ""
}

// extractTags extracts tags from ARM resource properties
func (a *ARMAdapter) extractTags(properties map[string]interface{}) models.Tags {
	tags := make(models.Tags)

	// Check for tags property
	if tagsObj, ok := properties["tags"].(map[string]interface{}); ok {
		for k, v := range tagsObj {
			if strVal, ok := v.(string); ok {
				tags[k] = strVal
			} else {
				tags[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	return tags
}
