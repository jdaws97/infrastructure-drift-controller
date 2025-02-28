package cloudformation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"gopkg.in/yaml.v2"
)

// CloudFormationAdapter implements the IaCAdapter interface for CloudFormation
type CloudFormationAdapter struct{}

// NewCloudFormationAdapter creates a new CloudFormation adapter
func NewCloudFormationAdapter() *CloudFormationAdapter {
	return &CloudFormationAdapter{}
}

// ParseFile parses a CloudFormation template file
func (a *CloudFormationAdapter) ParseFile(filePath string) ([]*models.Resource, []*models.ResourceState, error) {
	// Read and parse the file
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CloudFormation template: %w", err)
	}

	// Determine if this is JSON or YAML
	var cfnTemplate map[string]interface{}
	if strings.HasSuffix(filePath, ".json") {
		if err := json.Unmarshal(fileContent, &cfnTemplate); err != nil {
			return nil, nil, fmt.Errorf("failed to parse CloudFormation JSON: %w", err)
		}
	} else {
		// Assume YAML if not JSON
		if err := yaml.Unmarshal(fileContent, &cfnTemplate); err != nil {
			return nil, nil, fmt.Errorf("failed to parse CloudFormation YAML: %w", err)
		}
	}

	// Extract CloudFormation resources
	resourcesMap, ok := cfnTemplate["Resources"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("no resources found in CloudFormation template")
	}

	resources := make([]*models.Resource, 0, len(resourcesMap))
	states := make([]*models.ResourceState, 0, len(resourcesMap))

	for name, resourceData := range resourcesMap {
		resourceMap, ok := resourceData.(map[string]interface{})
		if !ok {
			continue
		}

		resourceType, ok := resourceMap["Type"].(string)
		if !ok {
			continue
		}

		// Determine provider (AWS for CloudFormation)
		provider := models.ProviderAWS

		// Extract properties
		propertiesMap, _ := resourceMap["Properties"].(map[string]interface{})

		// Create resource
		resource := &models.Resource{
			ID:         a.GenerateResourceID(propertiesMap, provider),
			Name:       name,
			Type:       a.getResourceType(resourceType),
			Provider:   provider,
			IaCType:    models.IaCTypeCloudFormation,
			Region:     a.getRegionFromProperties(propertiesMap),
			Account:    "", // Will be determined when deployed
			Properties: make(models.Properties),
			Tags:       a.extractTags(propertiesMap),
		}

		// Copy all properties
		for k, v := range propertiesMap {
			resource.Properties[k] = v
		}

		// Also include any metadata
		if metadata, ok := resourceMap["Metadata"].(map[string]interface{}); ok {
			resource.Properties["Metadata"] = metadata
		}

		// Create expected state
		state := &models.ResourceState{
			ResourceID:   resource.ID,
			StateType:    models.StateTypeExpected,
			Properties:   resource.Properties,
			CapturedAt:   time.Now(),
			StateVersion: uuid.New().String(),
			Source:       models.StateSourceCloudFormation,
		}

		resources = append(resources, resource)
		states = append(states, state)
	}

	return resources, states, nil
}

// ParseDirectory parses a directory of CloudFormation templates
func (a *CloudFormationAdapter) ParseDirectory(dirPath string) ([]*models.Resource, []*models.ResourceState, error) {
	var allResources []*models.Resource
	var allStates []*models.ResourceState

	// Walk through the directory and find CloudFormation templates
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Check if this is a CloudFormation template
		if strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			// Try to parse as CloudFormation
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

// GenerateResourceID generates a consistent ID for a CloudFormation resource
func (a *CloudFormationAdapter) GenerateResourceID(resource map[string]interface{}, provider models.ProviderType) string {
	// Use resource logical ID or properties that might indicate identity
	if physicalID, ok := resource["PhysicalResourceId"].(string); ok && physicalID != "" {
		return physicalID
	}

	// Look for common AWS identifiers
	for _, key := range []string{"Arn", "Id", "Name"} {
		if id, ok := resource[key].(string); ok && id != "" {
			return id
		}
	}

	// Otherwise, create a UUID
	return uuid.New().String()
}

// getResourceType maps CloudFormation resource types to our resource types
func (a *CloudFormationAdapter) getResourceType(cfnType string) models.ResourceType {
	// Map common CloudFormation resource types to our types
	switch cfnType {
	case "AWS::EC2::Instance":
		return models.ResourceTypeEC2Instance
	case "AWS::S3::Bucket":
		return models.ResourceTypeS3Bucket
	case "AWS::EC2::SecurityGroup":
		return models.ResourceTypeSecurityGroup
	}

	// Default to the CloudFormation type
	return models.ResourceType(cfnType)
}

// getRegionFromProperties attempts to extract region from resource properties
func (a *CloudFormationAdapter) getRegionFromProperties(properties map[string]interface{}) string {
	// Check for region in various properties
	if region, ok := properties["Region"].(string); ok {
		return region
	}

	if availabilityZone, ok := properties["AvailabilityZone"].(string); ok {
		// Extract region from AZ (e.g., us-east-1a -> us-east-1)
		parts := strings.Split(availabilityZone, "-")
		if len(parts) >= 3 {
			return strings.Join(parts[:len(parts)-1], "-")
		}
	}

	// Default to empty string if we can't determine
	return ""
}

// extractTags extracts tags from CloudFormation resource properties
func (a *CloudFormationAdapter) extractTags(properties map[string]interface{}) models.Tags {
	tags := make(models.Tags)

	// Check for Tags property
	if tagsProperty, ok := properties["Tags"].([]interface{}); ok {
		for _, tagObj := range tagsProperty {
			if tag, ok := tagObj.(map[string]interface{}); ok {
				key, keyOk := tag["Key"].(string)
				value, valueOk := tag["Value"].(string)

				if keyOk && valueOk {
					tags[key] = value
				}
			}
		}
	}

	return tags
}
