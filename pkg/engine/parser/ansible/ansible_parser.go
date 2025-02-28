package ansible

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"gopkg.in/yaml.v2"
)

// AnsibleAdapter implements the IaCAdapter interface for Ansible
type AnsibleAdapter struct{}

// NewAnsibleAdapter creates a new Ansible adapter
func NewAnsibleAdapter() *AnsibleAdapter {
	return &AnsibleAdapter{}
}

// ParseFile parses an Ansible file
func (a *AnsibleAdapter) ParseFile(filePath string) ([]*models.Resource, []*models.ResourceState, error) {
	// Read and parse the file
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read Ansible file: %w", err)
	}

	// Parse YAML
	var ansibleContent map[string]interface{}
	if err := yaml.Unmarshal(fileContent, &ansibleContent); err != nil {
		return nil, nil, fmt.Errorf("failed to parse Ansible YAML: %w", err)
	}

	resources := make([]*models.Resource, 0)
	states := make([]*models.ResourceState, 0)

	// Parse playbook tasks
	tasks, ok := a.extractTasks(ansibleContent)
	if !ok {
		return nil, nil, fmt.Errorf("no tasks found in Ansible file")
	}

	// Process each task
	for _, task := range tasks {
		taskMap, ok := task.(map[string]interface{})
		if !ok {
			continue
		}

		// Get task name
		name, _ := taskMap["name"].(string)
		if name == "" {
			name = "unnamed-task"
		}

		// Process resource-creating modules
		for module, moduleArgs := range taskMap {
			// Skip common task keys that aren't modules
			if a.isTaskMetadata(module) {
				continue
			}

			// Determine if this module creates infrastructure
			provider, resourceType := a.getProviderAndType(module)
			if provider == "" || resourceType == "" {
				continue
			}

			// Extract module arguments
			argsMap, ok := moduleArgs.(map[string]interface{})
			if !ok {
				continue
			}

			// Create resource
			resource := &models.Resource{
				ID:         a.GenerateResourceID(argsMap, provider),
				Name:       name,
				Type:       models.ResourceType(resourceType),
				Provider:   provider,
				IaCType:    models.IaCTypeAnsible,
				Region:     a.getRegionFromArgs(argsMap, module),
				Account:    a.getAccountFromArgs(argsMap, module),
				Properties: make(models.Properties),
				Tags:       a.extractTags(argsMap),
			}

			// Copy all arguments to properties
			for k, v := range argsMap {
				resource.Properties[k] = v
			}

			// Add module name to properties
			resource.Properties["ansible_module"] = module

			// Create expected state
			state := &models.ResourceState{
				ResourceID:   resource.ID,
				StateType:    models.StateTypeExpected,
				Properties:   resource.Properties,
				CapturedAt:   time.Now(),
				StateVersion: uuid.New().String(),
				Source:       models.StateSourceAnsible,
			}

			resources = append(resources, resource)
			states = append(states, state)
		}
	}

	return resources, states, nil
}

// ParseDirectory parses a directory of Ansible files
func (a *AnsibleAdapter) ParseDirectory(dirPath string) ([]*models.Resource, []*models.ResourceState, error) {
	var allResources []*models.Resource
	var allStates []*models.ResourceState

	// Walk through the directory and find Ansible playbooks and roles
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Check if this is an Ansible file
		if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
			// Try to parse as Ansible
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

// GenerateResourceID generates a consistent ID for an Ansible resource
func (a *AnsibleAdapter) GenerateResourceID(resource map[string]interface{}, provider models.ProviderType) string {
	// Use name or other identifying properties
	if name, ok := resource["name"].(string); ok && name != "" {
		return fmt.Sprintf("%s-%s", provider, name)
	}

	if id, ok := resource["id"].(string); ok && id != "" {
		return id
	}

	// Otherwise, create a UUID
	return uuid.New().String()
}

// extractTasks extracts tasks from Ansible content
func (a *AnsibleAdapter) extractTasks(content map[string]interface{}) ([]interface{}, bool) {
	// Check for tasks directly in the playbook
	if tasks, ok := content["tasks"].([]interface{}); ok {
		return tasks, true
	}

	// Check for tasks in plays
	if plays, ok := content["plays"].([]interface{}); ok {
		for _, play := range plays {
			if playMap, ok := play.(map[string]interface{}); ok {
				if tasks, ok := playMap["tasks"].([]interface{}); ok {
					return tasks, true
				}
			}
		}
	}

	// For playbooks with multiple plays
	if _, ok := content["0"]; ok {
		// This might be an array at the root
		for i := 0; i < 100; i++ { // Arbitrary limit
			if play, ok := content[fmt.Sprintf("%d", i)].(map[string]interface{}); ok {
				if tasks, ok := play["tasks"].([]interface{}); ok {
					return tasks, true
				}
			} else {
				break
			}
		}
	}

	return nil, false
}

// isTaskMetadata checks if a key is task metadata rather than a module name
func (a *AnsibleAdapter) isTaskMetadata(key string) bool {
	metadataKeys := map[string]bool{
		"name":          true,
		"register":      true,
		"when":          true,
		"with_items":    true,
		"loop":          true,
		"notify":        true,
		"tags":          true,
		"ignore_errors": true,
		"become":        true,
		"become_user":   true,
		"vars":          true,
		"no_log":        true,
	}

	return metadataKeys[key]
}

// getProviderAndType determines the provider and resource type from an Ansible module
func (a *AnsibleAdapter) getProviderAndType(module string) (models.ProviderType, string) {
	// Map Ansible modules to providers and resource types

	// AWS modules
	if strings.HasPrefix(module, "aws_") || strings.HasPrefix(module, "ec2_") || strings.HasPrefix(module, "s3_") {
		switch module {
		case "ec2", "ec2_instance":
			return models.ProviderAWS, string(models.ResourceTypeEC2Instance)
		case "s3_bucket":
			return models.ProviderAWS, string(models.ResourceTypeS3Bucket)
		case "ec2_group", "ec2_security_group":
			return models.ProviderAWS, string(models.ResourceTypeSecurityGroup)
		default:
			return models.ProviderAWS, module
		}
	}

	// Azure modules
	if strings.HasPrefix(module, "azure_") || strings.HasPrefix(module, "azure_rm_") {
		switch module {
		case "azure_rm_virtualmachine":
			return models.ProviderAzure, string(models.ResourceTypeAzureVM)
		case "azure_rm_storageaccount":
			return models.ProviderAzure, "azure_storage_account"
		case "azure_rm_securitygroup":
			return models.ProviderAzure, "azure_network_security_group"
		default:
			return models.ProviderAzure, module
		}
	}

	// GCP modules
	if strings.HasPrefix(module, "gcp_") {
		switch module {
		case "gcp_compute_instance":
			return models.ProviderGCP, string(models.ResourceTypeGCPInstance)
		default:
			return models.ProviderGCP, module
		}
	}

	// Not a recognized infrastructure module
	return "", ""
}

// getRegionFromArgs attempts to extract region from module arguments
func (a *AnsibleAdapter) getRegionFromArgs(args map[string]interface{}, module string) string {
	// Check for region or location in various properties
	for _, key := range []string{"region", "aws_region", "location", "availability_zone"} {
		if region, ok := args[key].(string); ok {
			return region
		}
	}

	return ""
}

// getAccountFromArgs attempts to extract account from module arguments
func (a *AnsibleAdapter) getAccountFromArgs(args map[string]interface{}, module string) string {
	// Check for account ID in various properties
	for _, key := range []string{"account_id", "subscription_id", "project", "project_id"} {
		if account, ok := args[key].(string); ok {
			return account
		}
	}

	return ""
}

// extractTags extracts tags from Ansible module arguments
func (a *AnsibleAdapter) extractTags(args map[string]interface{}) models.Tags {
	tags := make(models.Tags)

	// Check for tags property in various formats
	if tagsObj, ok := args["tags"].(map[string]interface{}); ok {
		// Format: tags: { Name: 'value', Environment: 'prod' }
		for k, v := range tagsObj {
			if strVal, ok := v.(string); ok {
				tags[k] = strVal
			} else {
				tags[k] = fmt.Sprintf("%v", v)
			}
		}
	} else if tagsList, ok := args["tags"].([]interface{}); ok {
		// Format: tags: [ { key: 'Name', value: 'webserver' }, ... ]
		for _, tagItem := range tagsList {
			if tagMap, ok := tagItem.(map[string]interface{}); ok {
				key, keyOk := tagMap["key"].(string)
				value, valueOk := tagMap["value"].(string)

				if keyOk && valueOk {
					tags[key] = value
				}
			}
		}
	}

	return tags
}
