package parser

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
)

// UniversalParser parses different IaC formats to extract expected state
type UniversalParser struct {
	db       *database.DB
	adapters map[models.IaCType]IaCAdapter
}

// IaCAdapter defines the interface for IaC format-specific adapters
type IaCAdapter interface {
	// ParseFile parses a file and returns resources and their expected states
	ParseFile(filePath string) ([]*models.Resource, []*models.ResourceState, error)
	
	// ParseDirectory parses a directory of IaC files
	ParseDirectory(dirPath string) ([]*models.Resource, []*models.ResourceState, error)
	
	// GenerateResourceID generates a consistent ID for a resource
	GenerateResourceID(resource map[string]interface{}, provider models.ProviderType) string
}

// New creates a new universal parser
func New(db *database.DB) *UniversalParser {
	parser := &UniversalParser{
		db:       db,
		adapters: make(map[models.IaCType]IaCAdapter),
	}
	
	// Register adapters
	parser.adapters[models.IaCTypeTerraform] = NewTerraformAdapter()
	parser.adapters[models.IaCTypeCloudFormation] = NewCloudFormationAdapter()
	parser.adapters[models.IaCTypePulumi] = NewPulumiAdapter()
	parser.adapters[models.IaCTypeAnsible] = NewAnsibleAdapter()
	parser.adapters[models.IaCTypeARMTemplate] = NewARMAdapter()
	
	return parser
}

// RegisterAdapter registers a new IaC adapter
func (p *UniversalParser) RegisterAdapter(iacType models.IaCType, adapter IaCAdapter) {
	p.adapters[iacType] = adapter
}

// ParseIaCFile parses an IaC file and stores the extracted resources and states
func (p *UniversalParser) ParseIaCFile(filePath string, iacType models.IaCType) error {
	adapter, exists := p.adapters[iacType]
	if !exists {
		return fmt.Errorf("unsupported IaC type: %s", iacType)
	}
	
	// Parse the file
	resources, states, err := adapter.ParseFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to parse file %s: %w", filePath, err)
	}
	
	// Store resources and states in database
	for i, resource := range resources {
		// Check if resource already exists
		existing, err := p.db.GetResource(resource.ID)
		if err == nil {
			// Update existing resource
			resource.CreatedAt = existing.CreatedAt
			resource.UpdatedAt = time.Now()
			if err := p.db.UpdateResource(resource); err != nil {
				return fmt.Errorf("failed to update resource %s: %w", resource.ID, err)
			}
		} else {
			// Create new resource
			resource.CreatedAt = time.Now()
			resource.UpdatedAt = time.Now()
			if err := p.db.CreateResource(resource); err != nil {
				return fmt.Errorf("failed to create resource %s: %w", resource.ID, err)
			}
		}
		
		// Store the state
		if i < len(states) {
			if err := p.db.SaveResourceState(states[i]); err != nil {
				return fmt.Errorf("failed to save resource state for %s: %w", resource.ID, err)
			}
		}
		
		// Store metadata about the IaC file
		if err := p.db.SetResourceMetadata(resource.ID, fmt.Sprintf("%s_file_path", iacType), filePath); err != nil {
			return fmt.Errorf("failed to save resource metadata: %w", err)
		}
	}
	
	return nil
}

// ParseIaCDirectory parses a directory of IaC files
func (p *UniversalParser) ParseIaCDirectory(dirPath string, iacType models.IaCType) error {
	adapter, exists := p.adapters[iacType]
	if !exists {
		return fmt.Errorf("unsupported IaC type: %s", iacType)
	}
	
	// Parse the directory
	resources, states, err := adapter.ParseDirectory(dirPath)
	if err != nil {
		return fmt.Errorf("failed to parse directory %s: %w", dirPath, err)
	}
	
	// Store resources and states in database
	for i, resource := range resources {
		// Check if resource already exists
		existing, err := p.db.GetResource(resource.ID)
		if err == nil {
			// Update existing resource
			resource.CreatedAt = existing.CreatedAt
			resource.UpdatedAt = time.Now()
			if err := p.db.UpdateResource(resource); err != nil {
				return fmt.Errorf("failed to update resource %s: %w", resource.ID, err)
			}
		} else {
			// Create new resource
			resource.CreatedAt = time.Now()
			resource.UpdatedAt = time.Now()
			if err := p.db.CreateResource(resource); err != nil {
				return fmt.Errorf("failed to create resource %s: %w", resource.ID, err)
			}
		}
		
		// Store the state
		if i < len(states) {
			if err := p.db.SaveResourceState(states[i]); err != nil {
				return fmt.Errorf("failed to save resource state for %s: %w", resource.ID, err)
			}
		}
		
		// Store metadata about the IaC directory
		if err := p.db.SetResourceMetadata(resource.ID, fmt.Sprintf("%s_dir_path", iacType), dirPath); err != nil {
			return fmt.Errorf("failed to save resource metadata: %w", err)
		}
	}
	
	return nil
}

// AutoDetectIaCType attempts to determine the IaC type from file content and extension
func (p *UniversalParser) AutoDetectIaCType(filePath string) (models.IaCType, error) {
	// Check file extension first
	ext := strings.ToLower(filepath.Ext(filePath))
	
	switch ext {
	case ".tf":
		return models.IaCTypeTerraform, nil
	case ".yaml", ".yml":
		// Could be CloudFormation, Ansible, or other YAML-based IaC
		// Need to examine content
		return p.detectYAMLType(filePath)
	case ".json":
		// Could be CloudFormation, ARM template, or other JSON-based IaC
		return p.detectJSONType(filePath)
	}
	
	return "", fmt.Errorf("unable to determine IaC type for file: %s", filePath)
}

// detectYAMLType determines the IaC type from YAML content
func (p *UniversalParser) detectYAMLType(filePath string) (models.IaCType, error) {
	// Read file content
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	
	// Look for common patterns in the content
	contentStr := string(content)
	
	if strings.Contains(contentStr, "AWSTemplateFormatVersion") || 
	   strings.Contains(contentStr, "Resources:") && strings.Contains(contentStr, "Type: AWS::") {
		return models.IaCTypeCloudFormation, nil
	}
	
	if strings.Contains(contentStr, "hosts:") && 
	   (strings.Contains(contentStr, "tasks:") || strings.Contains(contentStr, "roles:")) {
		return models.IaCTypeAnsible, nil
	}
	
	return "", fmt.Errorf("unable to determine YAML IaC type for file: %s", filePath)
}

// detectJSONType determines the IaC type from JSON content
func (p *UniversalParser) detectJSONType(filePath string) (models.IaCType, error) {
	// Read file content
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	
	// Parse JSON
	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}
	
	// Check for CloudFormation template
	if _, exists := data["AWSTemplateFormatVersion"]; exists {
		return models.IaCTypeCloudFormation, nil
	}
	
	// Check for ARM template
	if _, exists := data["$schema"]; exists {
		if schemaStr, ok := data["$schema"].(string); ok && 
		   strings.Contains(schemaStr, "deploymentTemplate.json") {
			return models.IaCTypeARMTemplate, nil
		}
	}
	
	return "", fmt.Errorf("unable to determine JSON IaC type for file: %s", filePath)
}

// ParseIaCSourceWithAutoDetect parses an IaC source with automatic type detection
func (p *UniversalParser) ParseIaCSourceWithAutoDetect(sourcePath string) error {
	// Check if source is a file or directory
	fileInfo, err := os.Stat(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to access source path: %w", err)
	}
	
	if fileInfo.IsDir() {
		// For directories, we need to examine files to determine type
		// Start by looking for common markers
		if _, err := os.Stat(filepath.Join(sourcePath, "terraform.tfstate")); err == nil {
			return p.ParseIaCDirectory(sourcePath, models.IaCTypeTerraform)
		}
		
		if _, err := os.Stat(filepath.Join(sourcePath, "Pulumi.yaml")); err == nil {
			return p.ParseIaCDirectory(sourcePath, models.IaCTypePulumi)
		}
		
		// If no clear markers, we'll need to scan files and make a best guess
		return p.scanDirectoryForIaC(sourcePath)
	} else {
		// For individual files, detect type and parse
		iacType, err := p.AutoDetectIaCType(sourcePath)
		if err != nil {
			return fmt.Errorf("failed to detect IaC type: %w", err)
		}
		
		return p.ParseIaCFile(sourcePath, iacType)
	}
}

// scanDirectoryForIaC scans a directory to identify and parse IaC files
func (p *UniversalParser) scanDirectoryForIaC(dirPath string) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return nil // Continue to next file
		}
		
		// Try to detect IaC type
		iacType, err := p.AutoDetectIaCType(path)
		if err != nil {
			// Not an IaC file we recognize, skip it
			return nil
		}
		
		// Parse the file
		if err := p.ParseIaCFile(path, iacType); err != nil {
			// Log error but continue processing other files
			fmt.Printf("Error parsing file %s: %v\n", path, err)
			return nil
		}
		
		return nil
	})
}

// TerraformAdapter implements the IaCAdapter interface for Terraform
type TerraformAdapter struct {}

// NewTerraformAdapter creates a new Terraform adapter
func NewTerraformAdapter() *TerraformAdapter {
	return &TerraformAdapter{}
}

// ParseFile parses a Terraform file
func (a *TerraformAdapter) ParseFile(filePath string) ([]*models.Resource, []*models.ResourceState, error) {
	// TODO: Implement Terraform file parsing
	// This would typically use a Terraform SDK or execute the CLI to get the state
	
	// For now, we'll return an empty result
	return []*models.Resource{}, []*models.ResourceState{}, nil
}

// ParseDirectory parses a directory of Terraform files
func (a *TerraformAdapter) ParseDirectory(dirPath string) ([]*models.Resource, []*models.ResourceState, error) {
	// TODO: Implement Terraform directory parsing
	// This would typically use a Terraform SDK or execute the CLI to get the state
	
	// For now, we'll return an empty result
	return []*models.Resource{}, []*models.ResourceState{}, nil
}

// GenerateResourceID generates a consistent ID for a Terraform resource
func (a *TerraformAdapter) GenerateResourceID(resource map[string]interface{}, provider models.ProviderType) string {
	// TODO: Implement proper ID generation logic
	// This would create a consistent ID based on the resource attributes
	
	return ""
}

// CloudFormationAdapter implements the IaCAdapter interface for CloudFormation
type CloudFormationAdapter struct {}

// NewCloudFormationAdapter creates a new CloudFormation adapter
func NewCloudFormationAdapter() *CloudFormationAdapter {
	return &CloudFormationAdapter{}
}

// ParseFile parses a CloudFormation template file
func (a *CloudFormationAdapter) ParseFile(filePath string) ([]*models.Resource, []*models.ResourceState, error) {
	// TODO: Implement CloudFormation file parsing
	// This would parse the template file and extract resources
	
	// For now, we'll return an empty result
	return []*models.Resource{}, []*models.ResourceState{}, nil
}

// ParseDirectory parses a directory of CloudFormation templates
func (a *CloudFormationAdapter) ParseDirectory(dirPath string) ([]*models.Resource, []*models.ResourceState, error) {
	// TODO: Implement CloudFormation directory parsing
	// This would find all template files and parse them
	
	// For now, we'll return an empty result
	return []*models.Resource{}, []*models.ResourceState{}, nil
}

// GenerateResourceID generates a consistent ID for a CloudFormation resource
func (a *CloudFormationAdapter) GenerateResourceID(resource map[string]interface{}, provider models.ProviderType) string {
	// TODO: Implement proper ID generation logic
	// This would create a consistent ID based on the resource attributes
	
	return ""
}

// PulumiAdapter implements the IaCAdapter interface for Pulumi
type PulumiAdapter struct {}

// NewPulumiAdapter creates a new Pulumi adapter
func NewPulumiAdapter() *PulumiAdapter {
	return &PulumiAdapter{}
}

// ParseFile parses a Pulumi file
func (a *PulumiAdapter) ParseFile(filePath string) ([]*models.Resource, []*models.ResourceState, error) {
	// TODO: Implement Pulumi file parsing
	// This would typically use the Pulumi SDK or CLI to extract state
	
	// For now, we'll return an empty result
	return []*models.Resource{}, []*models.ResourceState{}, nil
}

// ParseDirectory parses a directory of Pulumi files
func (a *PulumiAdapter) ParseDirectory(dirPath string) ([]*models.Resource, []*models.ResourceState, error) {
	// TODO: Implement Pulumi directory parsing
	// This would typically use the Pulumi SDK or CLI to extract state
	
	// For now, we'll return an empty result
	return []*models.Resource{}, []*models.ResourceState{}, nil
}

// GenerateResourceID generates a consistent ID for a Pulumi resource
func (a *PulumiAdapter) GenerateResourceID(resource map[string]interface{}, provider models.ProviderType) string {
	// TODO: Implement proper ID generation logic
	// This would create a consistent ID based on the resource attributes
	
	return ""
}

// AnsibleAdapter implements the IaCAdapter interface for Ansible
type AnsibleAdapter struct {}

// NewAnsibleAdapter creates a new Ansible adapter
func NewAnsibleAdapter() *AnsibleAdapter {
	return &AnsibleAdapter{}
}

// ParseFile parses an Ansible file
func (a *AnsibleAdapter) ParseFile(filePath string) ([]*models.Resource, []*models.ResourceState, error) {
	// TODO: Implement Ansible file parsing
	// This would parse the playbook file and extract resources
	
	// For now, we'll return an empty result
	return []*models.Resource{}, []*models.ResourceState{}, nil
}

// ParseDirectory parses a directory of Ansible files
func (a *AnsibleAdapter) ParseDirectory(dirPath string) ([]*models.Resource, []*models.ResourceState, error) {
	// TODO: Implement Ansible directory parsing
	// This would find all playbook files and parse them
	
	// For now, we'll return an empty result
	return []*models.Resource{}, []*models.ResourceState{}, nil
}

// GenerateResourceID generates a consistent ID for an Ansible resource
func (a *AnsibleAdapter) GenerateResourceID(resource map[string]interface{}, provider models.ProviderType) string {
	// TODO: Implement proper ID generation logic
	// This would create a consistent ID based on the resource attributes
	
	return ""
}

// ARMAdapter implements the IaCAdapter interface for ARM Templates
type ARMAdapter struct {}

// NewARMAdapter creates a new ARM template adapter
func NewARMAdapter() *ARMAdapter {
	return &ARMAdapter{}
}

// ParseFile parses an ARM template file
func (a *ARMAdapter) ParseFile(filePath string) ([]*models.Resource, []*models.ResourceState, error) {
	// TODO: Implement ARM template file parsing
	// This would parse the template file and extract resources
	
	// For now, we'll return an empty result
	return []*models.Resource{}, []*models.ResourceState{}, nil
}

// ParseDirectory parses a directory of ARM templates
func (a *ARMAdapter) ParseDirectory(dirPath string) ([]*models.Resource, []*models.ResourceState, error) {
	// TODO: Implement ARM template directory parsing
	// This would find all template files and parse them
	
	// For now, we'll return an empty result
	return []*models.Resource{}, []*models.ResourceState{}, nil
}

// GenerateResourceID generates a consistent ID for an ARM template resource
func (a *ARMAdapter) GenerateResourceID(resource map[string]interface{}, provider models.ProviderType) string {
	// TODO: Implement proper ID generation logic
	// This would create a consistent ID based on the resource attributes
	
	return ""
}