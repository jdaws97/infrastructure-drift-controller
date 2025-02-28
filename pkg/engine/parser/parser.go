package parser

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/parser/ansible"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/parser/arm"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/parser/cloudformation"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/parser/pulumi"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/parser/terraform"
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
	parser.adapters[models.IaCTypeTerraform] = terraform.NewTerraformAdapter()
	parser.adapters[models.IaCTypeCloudFormation] = cloudformation.NewCloudFormationAdapter()
	parser.adapters[models.IaCTypePulumi] = pulumi.NewPulumiAdapter()
	parser.adapters[models.IaCTypeAnsible] = ansible.NewAnsibleAdapter()
	parser.adapters[models.IaCTypeARMTemplate] = arm.NewARMAdapter()

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

	// Check for Pulumi
	if strings.Contains(contentStr, "name:") && strings.Contains(contentStr, "runtime:") {
		return models.IaCTypePulumi, nil
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

	// Check for Terraform JSON
	if _, exists := data["terraform_version"]; exists {
		return models.IaCTypeTerraform, nil
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

		// Check for CloudFormation template directory
		if _, err := os.Stat(filepath.Join(sourcePath, "template.yaml")); err == nil {
			return p.ParseIaCDirectory(sourcePath, models.IaCTypeCloudFormation)
		}

		// Check for Ansible playbook directory
		if _, err := os.Stat(filepath.Join(sourcePath, "playbook.yml")); err == nil {
			return p.ParseIaCDirectory(sourcePath, models.IaCTypeAnsible)
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

// SyncDirectory synchronizes a directory, detecting changes since last sync
func (p *UniversalParser) SyncDirectory(dirPath string) error {
	// Determine IaC type
	iacType, err := p.detectDirectoryIaCType(dirPath)
	if err != nil {
		return fmt.Errorf("failed to determine IaC type for directory: %w", err)
	}

	// Get the last sync time
	lastSyncFile := filepath.Join(dirPath, ".idc_last_sync")
	lastSyncTime := time.Time{}

	if lastSyncData, err := ioutil.ReadFile(lastSyncFile); err == nil {
		if t, err := time.Parse(time.RFC3339, string(lastSyncData)); err == nil {
			lastSyncTime = t
		}
	}

	// Get last modified time of IaC files
	var mostRecentModTime time.Time

	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Skip non-IaC files and hidden files
		if strings.HasPrefix(filepath.Base(path), ".") {
			return nil
		}

		if info.ModTime().After(lastSyncTime) {
			// File was modified since last sync
			if info.ModTime().After(mostRecentModTime) {
				mostRecentModTime = info.ModTime()
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error checking for modified files: %w", err)
	}

	// If no files were modified, no need to sync
	if mostRecentModTime.IsZero() {
		return nil
	}

	// Parse the directory
	if err := p.ParseIaCDirectory(dirPath, iacType); err != nil {
		return fmt.Errorf("error parsing directory: %w", err)
	}

	// Update the last sync time
	now := time.Now()
	if err := ioutil.WriteFile(lastSyncFile, []byte(now.Format(time.RFC3339)), 0644); err != nil {
		return fmt.Errorf("error updating last sync time: %w", err)
	}

	return nil
}

// detectDirectoryIaCType tries to determine the IaC type for a directory
func (p *UniversalParser) detectDirectoryIaCType(dirPath string) (models.IaCType, error) {
	// Check for common markers
	if _, err := os.Stat(filepath.Join(dirPath, "terraform.tfstate")); err == nil {
		return models.IaCTypeTerraform, nil
	}

	if _, err := os.Stat(filepath.Join(dirPath, "Pulumi.yaml")); err == nil {
		return models.IaCTypePulumi, nil
	}

	if _, err := os.Stat(filepath.Join(dirPath, "playbook.yml")); err == nil {
		return models.IaCTypeAnsible, nil
	}

	if _, err := os.Stat(filepath.Join(dirPath, "template.yaml")); err == nil {
		return models.IaCTypeCloudFormation, nil
	}

	// Look at file extensions in the directory
	var tfFiles, yamlFiles, jsonFiles int

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".tf":
			tfFiles++
		case ".yaml", ".yml":
			yamlFiles++
		case ".json":
			jsonFiles++
		}

		return nil
	})

	if err != nil {
		return "", fmt.Errorf("error scanning directory: %w", err)
	}

	// Make a best guess based on file counts
	if tfFiles > 0 {
		return models.IaCTypeTerraform, nil
	}

	if jsonFiles > yamlFiles {
		// Examine a JSON file to see if it's CloudFormation or ARM
		var jsonType models.IaCType

		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			if strings.ToLower(filepath.Ext(path)) == ".json" {
				t, err := p.detectJSONType(path)
				if err == nil {
					jsonType = t
					return filepath.SkipDir // Stop after finding one
				}
			}

			return nil
		})

		if err != nil {
			return "", fmt.Errorf("error examining JSON files: %w", err)
		}

		if jsonType != "" {
			return jsonType, nil
		}
	}

	if yamlFiles > 0 {
		// Examine a YAML file to see if it's CloudFormation or Ansible
		var yamlType models.IaCType

		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" {
				t, err := p.detectYAMLType(path)
				if err == nil {
					yamlType = t
					return filepath.SkipDir // Stop after finding one
				}
			}

			return nil
		})

		if err != nil {
			return "", fmt.Errorf("error examining YAML files: %w", err)
		}

		if yamlType != "" {
			return yamlType, nil
		}
	}

	return "", fmt.Errorf("could not determine IaC type for directory")
}
