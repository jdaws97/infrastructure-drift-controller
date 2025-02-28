package pulumi

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"gopkg.in/yaml.v2"
)

// PulumiAdapter implements the IaCAdapter interface for Pulumi
type PulumiAdapter struct{}

// NewPulumiAdapter creates a new Pulumi adapter
func NewPulumiAdapter() *PulumiAdapter {
	return &PulumiAdapter{}
}

// ParseFile parses a Pulumi file
func (a *PulumiAdapter) ParseFile(filePath string) ([]*models.Resource, []*models.ResourceState, error) {
	// For a single file, we need to find the directory that contains it
	dirPath := filepath.Dir(filePath)
	return a.ParseDirectory(dirPath)
}

// ParseDirectory parses a directory of Pulumi files
func (a *PulumiAdapter) ParseDirectory(dirPath string) ([]*models.Resource, []*models.ResourceState, error) {
	// Check if pulumi binary is available
	if _, err := exec.LookPath("pulumi"); err != nil {
		return nil, nil, fmt.Errorf("pulumi binary not found: %w", err)
	}

	// Determine the stack from Pulumi.yaml or prompt user
	stack := a.getStack(dirPath)
	if stack == "" {
		return nil, nil, fmt.Errorf("could not determine Pulumi stack")
	}

	// Use pulumi CLI to export the stack
	cmd := exec.Command("pulumi", "stack", "export", "--stack", stack)
	cmd.Dir = dirPath
	output, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to export Pulumi stack: %w", err)
	}

	// Parse the JSON output
	var pulumiState PulumiState
	if err := json.Unmarshal(output, &pulumiState); err != nil {
		return nil, nil, fmt.Errorf("failed to parse Pulumi state: %w", err)
	}

	// Extract resources and states
	resources := make([]*models.Resource, 0)
	states := make([]*models.ResourceState, 0)

	for urn, resource := range pulumiState.Deployment.Resources {
		// Skip provider resources and component resources
		if resource.Type == "pulumi:providers" || resource.Custom == false {
			continue
		}

		// Determine provider type
		provider := a.getProviderFromType(resource.Type)

		// Create resource model
		modelResource := &models.Resource{
			ID:         a.GenerateResourceID(resource.Outputs, provider),
			Name:       resource.Outputs["name"].(string),
			Type:       a.getResourceType(resource.Type, provider),
			Provider:   provider,
			IaCType:    models.IaCTypePulumi,
			Region:     a.getRegionFromPulumiResource(resource),
			Account:    a.getAccountFromPulumiResource(resource),
			Properties: make(models.Properties),
			Tags:       a.extractTags(resource.Outputs),
		}

		// Extract properties
		for k, v := range resource.Outputs {
			if k != "tags" && k != "id" {
				modelResource.Properties[k] = v
			}
		}

		// Add URN as a property
		modelResource.Properties["pulumi_urn"] = urn

		// Create resource state
		state := &models.ResourceState{
			ResourceID:   modelResource.ID,
			StateType:    models.StateTypeExpected,
			Properties:   modelResource.Properties,
			CapturedAt:   time.Now(),
			StateVersion: uuid.New().String(),
			Source:       models.StateSourceTerraform, // Using Terraform as the source type
		}

		resources = append(resources, modelResource)
		states = append(states, state)
	}

	return resources, states, nil
}

// getStack attempts to determine the Pulumi stack from configuration
func (a *PulumiAdapter) getStack(dirPath string) string {
	// Try to read the current stack from Pulumi.yaml
	yamlPath := filepath.Join(dirPath, "Pulumi.yaml")
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return ""
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return ""
	}

	// Try to get stack name from current selection
	cmd := exec.Command("pulumi", "stack", "ls", "--json")
	cmd.Dir = dirPath
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	var stacks []struct {
		Name    string `json:"name"`
		Current bool   `json:"current"`
	}
	if err := json.Unmarshal(output, &stacks); err != nil {
		return ""
	}

	for _, stack := range stacks {
		if stack.Current {
			return stack.Name
		}
	}

	// If no current stack, use the first one
	if len(stacks) > 0 {
		return stacks[0].Name
	}

	return ""
}

// GenerateResourceID generates a consistent ID for a Pulumi resource
func (a *PulumiAdapter) GenerateResourceID(resource map[string]interface{}, provider models.ProviderType) string {
	// Use the resource's own ID if available
	if id, ok := resource["id"].(string); ok && id != "" {
		return id
	}

	// Otherwise, create a UUID
	return uuid.New().String()
}

// getProviderFromType extracts the provider from the resource type
func (a *PulumiAdapter) getProviderFromType(resourceType string) models.ProviderType {
	// Pulumi resource type format is typically "provider:module:resource"
	parts := strings.Split(resourceType, ":")
	if len(parts) > 0 {
		switch parts[0] {
		case "aws":
			return models.ProviderAWS
		case "azure", "azurerm":
			return models.ProviderAzure
		case "gcp":
			return models.ProviderGCP
		case "kubernetes":
			return models.ProviderKubernetes
		}
	}

	return models.ProviderType(parts[0])
}

// getResourceType converts a Pulumi resource type to our resource type
func (a *PulumiAdapter) getResourceType(pulumiType string, provider models.ProviderType) models.ResourceType {
	// Map common Pulumi resource types
	parts := strings.Split(pulumiType, ":")
	if len(parts) < 2 {
		return models.ResourceType(pulumiType)
	}

	switch provider {
	case models.ProviderAWS:
		if parts[1] == "ec2" && parts[2] == "Instance" {
			return models.ResourceTypeEC2Instance
		} else if parts[1] == "s3" && parts[2] == "Bucket" {
			return models.ResourceTypeS3Bucket
		} else if parts[1] == "ec2" && parts[2] == "SecurityGroup" {
			return models.ResourceTypeSecurityGroup
		}
	case models.ProviderAzure:
		if parts[1] == "compute" && (parts[2] == "VirtualMachine" || parts[2] == "LinuxVirtualMachine" || parts[2] == "WindowsVirtualMachine") {
			return models.ResourceTypeAzureVM
		}
	case models.ProviderGCP:
		if parts[1] == "compute" && parts[2] == "Instance" {
			return models.ResourceTypeGCPInstance
		}
	}

	// Default to the Pulumi type if no mapping exists
	return models.ResourceType(pulumiType)
}

// getRegionFromPulumiResource attempts to determine the region from resource attributes
func (a *PulumiAdapter) getRegionFromPulumiResource(resource PulumiResource) string {
	// First, check for common region/location attributes
	if region, ok := resource.Outputs["region"].(string); ok {
		return region
	}

	if location, ok := resource.Outputs["location"].(string); ok {
		return location
	}

	// For AWS, we might find it in an ARN
	if arn, ok := resource.Outputs["arn"].(string); ok {
		// ARN format: arn:partition:service:region:account-id:resource-id
		parts := strings.Split(arn, ":")
		if len(parts) >= 4 {
			return parts[3]
		}
	}

	// Default to empty string if we can't determine
	return ""
}

// getAccountFromPulumiResource attempts to determine the account from resource attributes
func (a *PulumiAdapter) getAccountFromPulumiResource(resource PulumiResource) string {
	// Check for specific provider attributes
	providerParts := strings.Split(resource.Type, ":")
	if len(providerParts) == 0 {
		return ""
	}

	switch providerParts[0] {
	case "aws":
		// For AWS, check the ARN which contains the account ID
		if arn, ok := resource.Outputs["arn"].(string); ok {
			// ARN format: arn:partition:service:region:account-id:resource-id
			parts := strings.Split(arn, ":")
			if len(parts) >= 5 {
				return parts[4]
			}
		}
	case "azure", "azurerm":
		// For Azure, check subscription_id
		if subID, ok := resource.Outputs["subscription_id"].(string); ok {
			return subID
		}

		// Try to extract from ID
		if id, ok := resource.Outputs["id"].(string); ok {
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
	case "gcp":
		// For GCP, check project
		if project, ok := resource.Outputs["project"].(string); ok {
			return project
		}
	}

	return ""
}

// extractTags extracts tags from resource attributes
func (a *PulumiAdapter) extractTags(attributes map[string]interface{}) models.Tags {
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

// PulumiState represents the state structure returned by Pulumi stack export
type PulumiState struct {
	Version    int              `json:"version"`
	Deployment PulumiDeployment `json:"deployment"`
}

// PulumiDeployment represents the deployment section of Pulumi state
type PulumiDeployment struct {
	Resources map[string]PulumiResource `json:"resources"`
}

// PulumiResource represents a resource in the Pulumi state
type PulumiResource struct {
	Type      string                 `json:"type"`
	Custom    bool                   `json:"custom"`
	Outputs   map[string]interface{} `json:"outputs"`
	InputDeps []string               `json:"inputDeps"`
}
