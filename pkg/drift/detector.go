package drift

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/cloud"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/iac"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/logging"
)

// DriftType represents the type of infrastructure drift
type DriftType string

// Drift types
const (
	ResourceMissing  DriftType = "RESOURCE_MISSING"   // Resource exists in IaC but not in cloud
	ResourceExtra    DriftType = "RESOURCE_EXTRA"     // Resource exists in cloud but not in IaC
	AttributeDrift   DriftType = "ATTRIBUTE_DRIFT"    // Resource attribute values differ
	TagDrift         DriftType = "TAG_DRIFT"          // Resource tags differ
)

// DriftSeverity represents the severity level of a drift
type DriftSeverity string

// Drift severities
const (
	SeverityLow     DriftSeverity = "LOW"
	SeverityMedium  DriftSeverity = "MEDIUM"
	SeverityHigh    DriftSeverity = "HIGH"
	SeverityCritical DriftSeverity = "CRITICAL"
)

// AttributeDifference represents a difference in a resource attribute
type AttributeDifference struct {
	PropertyPath string      `json:"property_path"`
	ExpectedValue interface{} `json:"expected_value"`
	ActualValue   interface{} `json:"actual_value"`
}

// DriftReport represents a single drift finding
type DriftReport struct {
	ID           string               `json:"id"`
	ResourceType string               `json:"resource_type"`
	ResourceID   string               `json:"resource_id"`
	ResourceName string               `json:"resource_name"`
	DriftType    DriftType            `json:"drift_type"`
	Severity     DriftSeverity        `json:"severity"`
	Differences  []AttributeDifference `json:"differences,omitempty"`
	DetectedAt   time.Time            `json:"detected_at"`
	ResolvedAt   *time.Time           `json:"resolved_at,omitempty"`
	Metadata     map[string]string    `json:"metadata,omitempty"`
}

// DriftDetector is responsible for detecting infrastructure drift
type DriftDetector struct {
	config          *config.Config
	stateParser     *iac.TerraformStateParser
	cloudQuerier    *cloud.AWSQuerier
	logger          *logging.Logger
	severityMapping map[string]map[string]DriftSeverity
}

// NewDriftDetector creates a new drift detector
func NewDriftDetector(cfg *config.Config, stateParser *iac.TerraformStateParser, cloudQuerier *cloud.AWSQuerier) *DriftDetector {
	return &DriftDetector{
		config:       cfg,
		stateParser:  stateParser,
		cloudQuerier: cloudQuerier,
		logger:       logging.GetGlobalLogger().WithField("component", "drift_detector"),
		severityMapping: initDefaultSeverityMapping(),
	}
}

// initDefaultSeverityMapping initializes the default severity mapping
func initDefaultSeverityMapping() map[string]map[string]DriftSeverity {
	// Default severity mappings
	mapping := map[string]map[string]DriftSeverity{
		// EC2 instances
		"aws_instance": {
			"_default":            SeverityMedium,
			"instance_type":       SeverityHigh,
			"security_groups":     SeverityHigh,
			"ami":                 SeverityMedium,
			"tags":                SeverityLow,
		},
		// S3 buckets
		"aws_s3_bucket": {
			"_default":            SeverityMedium,
			"acl":                 SeverityHigh,
			"versioning":          SeverityHigh,
			"server_side_encryption_configuration": SeverityHigh,
			"tags":                SeverityLow,
		},
		// VPCs
		"aws_vpc": {
			"_default":            SeverityMedium,
			"cidr_block":          SeverityHigh,
			"tags":                SeverityLow,
		},
		// Security groups
		"aws_security_group": {
			"_default":            SeverityMedium,
			"ingress":             SeverityHigh,
			"egress":              SeverityHigh,
			"tags":                SeverityLow,
		},
		// Subnets
		"aws_subnet": {
			"_default":            SeverityMedium,
			"cidr_block":          SeverityHigh,
			"tags":                SeverityLow,
		},
		// Default for all other resource types
		"_default": {
			"_default":            SeverityMedium,
			"tags":                SeverityLow,
		},
	}

	return mapping
}

// DetectDrift checks for infrastructure drift
func (d *DriftDetector) DetectDrift(ctx context.Context) ([]DriftReport, error) {
	d.logger.Info("Starting infrastructure drift detection")
	
	// Parse Terraform state file
	stateResources, err := d.stateParser.ParseStateFile(d.config.Terraform.StatePath, d.config.Terraform.ResourceTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Terraform state file: %w", err)
	}
	d.logger.Info("Parsed %d resources from Terraform state", len(stateResources))
	
	// Extract resource types
	resourceTypes := make(map[string]bool)
	for _, resource := range stateResources {
		resourceTypes[resource.ResourceType] = true
	}
	
	// Convert map to slice
	rtSlice := make([]string, 0, len(resourceTypes))
	for rt := range resourceTypes {
		rtSlice = append(rtSlice, rt)
	}
	
	// Query cloud resources
	cloudResources, err := d.cloudQuerier.GetResources(ctx, rtSlice)
	if err != nil {
		return nil, fmt.Errorf("failed to query cloud resources: %w", err)
	}
	d.logger.Info("Retrieved %d resources from AWS", len(cloudResources))
	
	// Detect drift between IaC and cloud resources
	drifts := d.compareTerraformStateToCloud(stateResources, cloudResources)
	d.logger.Info("Detected %d infrastructure drifts", len(drifts))
	
	return drifts, nil
}

// compareTerraformStateToCloud compares Terraform state with actual cloud resources
func (d *DriftDetector) compareTerraformStateToCloud(
	stateResources map[string]iac.ResourceState,
	cloudResources map[string]cloud.CloudResource,
) []DriftReport {
	var drifts []DriftReport
	
	// Map cloud resources by ID for easier lookup
	cloudResourcesByID := make(map[string]cloud.CloudResource)
	for _, resource := range cloudResources {
		cloudResourcesByID[resource.ResourceID] = resource
	}
	
	// Check for resources in Terraform state that are missing in cloud
	for _, stateResource := range stateResources {
		// Skip resources with empty IDs
		if stateResource.ResourceID == "" {
			continue
		}
		
		// Check if resource exists in cloud
		cloudResource, exists := cloudResourcesByID[stateResource.ResourceID]
		if !exists {
			// Resource exists in Terraform state but not in cloud
			drifts = append(drifts, DriftReport{
				ID:           fmt.Sprintf("drift-%d", len(drifts)+1),
				ResourceType: stateResource.ResourceType,
				ResourceID:   stateResource.ResourceID,
				ResourceName: stateResource.ResourceName,
				DriftType:    ResourceMissing,
				Severity:     SeverityHigh,
				DetectedAt:   time.Now(),
				Metadata: map[string]string{
					"terraform_address": fmt.Sprintf("%s.%s", stateResource.ResourceType, stateResource.ResourceName),
				},
			})
			continue
		}
		
		// Compare resource attributes
		attributeDrifts := d.compareAttributes(stateResource, cloudResource)
		if len(attributeDrifts) > 0 {
			severity := d.calculateSeverity(stateResource.ResourceType, attributeDrifts)
			drifts = append(drifts, DriftReport{
				ID:           fmt.Sprintf("drift-%d", len(drifts)+1),
				ResourceType: stateResource.ResourceType,
				ResourceID:   stateResource.ResourceID,
				ResourceName: stateResource.ResourceName,
				DriftType:    AttributeDrift,
				Severity:     severity,
				Differences:  attributeDrifts,
				DetectedAt:   time.Now(),
				Metadata: map[string]string{
					"terraform_address": fmt.Sprintf("%s.%s", stateResource.ResourceType, stateResource.ResourceName),
				},
			})
		}
		
		// Compare resource tags
		tagDrifts := d.compareTags(stateResource, cloudResource)
		if len(tagDrifts) > 0 {
			drifts = append(drifts, DriftReport{
				ID:           fmt.Sprintf("drift-%d", len(drifts)+1),
				ResourceType: stateResource.ResourceType,
				ResourceID:   stateResource.ResourceID,
				ResourceName: stateResource.ResourceName,
				DriftType:    TagDrift,
				Severity:     SeverityLow,
				Differences:  tagDrifts,
				DetectedAt:   time.Now(),
				Metadata: map[string]string{
					"terraform_address": fmt.Sprintf("%s.%s", stateResource.ResourceType, stateResource.ResourceName),
				},
			})
		}
	}
	
	// Check for resources in cloud that are not in Terraform state
	for _, cloudResource := range cloudResources {
		foundInState := false
		for _, stateResource := range stateResources {
			if stateResource.ResourceID == cloudResource.ResourceID {
				foundInState = true
				break
			}
		}
		
		if !foundInState {
			// Resource exists in cloud but not in Terraform state
			drifts = append(drifts, DriftReport{
				ID:           fmt.Sprintf("drift-%d", len(drifts)+1),
				ResourceType: cloudResource.ResourceType,
				ResourceID:   cloudResource.ResourceID,
				ResourceName: cloudResource.ResourceName,
				DriftType:    ResourceExtra,
				Severity:     SeverityMedium,
				DetectedAt:   time.Now(),
			})
		}
	}
	
	return drifts
}

// compareAttributes compares resource attributes between Terraform state and cloud
func (d *DriftDetector) compareAttributes(stateResource iac.ResourceState, cloudResource cloud.CloudResource) []AttributeDifference {
	var differences []AttributeDifference
	
	// Define a list of attribute keys to compare based on resource type
	// This varies depending on the resource type
	keysToCompare := getAttributeKeysToCompare(stateResource.ResourceType)
	
	for _, key := range keysToCompare {
		stateValue, stateOk := stateResource.Attributes[key]
		cloudValue, cloudOk := cloudResource.Attributes[key]
		
		// Skip if both are not present
		if !stateOk && !cloudOk {
			continue
		}
		
		// Check for missing attribute
		if stateOk && !cloudOk {
			differences = append(differences, AttributeDifference{
				PropertyPath:  key,
				ExpectedValue: stateValue,
				ActualValue:   nil,
			})
			continue
		}
		
		// Check for extra attribute
		if !stateOk && cloudOk {
			differences = append(differences, AttributeDifference{
				PropertyPath:  key,
				ExpectedValue: nil,
				ActualValue:   cloudValue,
			})
			continue
		}
		
		// Compare values
		if !reflect.DeepEqual(stateValue, cloudValue) {
			differences = append(differences, AttributeDifference{
				PropertyPath:  key,
				ExpectedValue: stateValue,
				ActualValue:   cloudValue,
			})
		}
	}
	
	return differences
}

// compareTags compares resource tags between Terraform state and cloud
func (d *DriftDetector) compareTags(stateResource iac.ResourceState, cloudResource cloud.CloudResource) []AttributeDifference {
	var differences []AttributeDifference
	
	// Extract tags from Terraform state
	stateTags := make(map[string]string)
	if tagsRaw, ok := stateResource.Attributes["tags"]; ok {
		switch tagsTyped := tagsRaw.(type) {
		case map[string]interface{}:
			for k, v := range tagsTyped {
				if strVal, ok := v.(string); ok {
					stateTags[k] = strVal
				}
			}
		}
	}
	
	// Compare state tags with cloud tags
	for key, stateValue := range stateTags {
		if cloudValue, ok := cloudResource.Tags[key]; ok {
			if stateValue != cloudValue {
				differences = append(differences, AttributeDifference{
					PropertyPath:  fmt.Sprintf("tags.%s", key),
					ExpectedValue: stateValue,
					ActualValue:   cloudValue,
				})
			}
		} else {
			differences = append(differences, AttributeDifference{
				PropertyPath:  fmt.Sprintf("tags.%s", key),
				ExpectedValue: stateValue,
				ActualValue:   nil,
			})
		}
	}
	
	// Check for extra tags in cloud
	for key, cloudValue := range cloudResource.Tags {
		if _, ok := stateTags[key]; !ok {
			differences = append(differences, AttributeDifference{
				PropertyPath:  fmt.Sprintf("tags.%s", key),
				ExpectedValue: nil,
				ActualValue:   cloudValue,
			})
		}
	}
	
	return differences
}

// calculateSeverity determines the severity of a drift based on attribute differences
func (d *DriftDetector) calculateSeverity(resourceType string, differences []AttributeDifference) DriftSeverity {
	highestSeverity := SeverityLow
	
	// Get severity mapping for resource type
	severityMap, ok := d.severityMapping[resourceType]
	if !ok {
		severityMap = d.severityMapping["_default"]
	}
	
	// Determine highest severity among all differences
	for _, diff := range differences {
		path := diff.PropertyPath
		
		// Check if there's a specific severity for this path
		severity, ok := severityMap[path]
		if !ok {
			// Check for prefix matches
			found := false
			for mapPath, mapSeverity := range severityMap {
				if mapPath != "_default" && strings.HasPrefix(path, mapPath) {
					severity = mapSeverity
					found = true
					break
				}
			}
			
			// Use default severity if no specific mapping found
			if !found {
				severity = severityMap["_default"]
			}
		}
		
		// Update highest severity
		if severityRank(severity) > severityRank(highestSeverity) {
			highestSeverity = severity
		}
	}
	
	return highestSeverity
}

// severityRank returns a numeric rank for a severity level
func severityRank(severity DriftSeverity) int {
	switch severity {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// getAttributeKeysToCompare returns the attribute keys to compare for a resource type
func getAttributeKeysToCompare(resourceType string) []string {
	// Define attributes to compare based on resource type
	attributeMap := map[string][]string{
		"aws_instance": {
			"id", "ami", "instance_type", "availability_zone", "vpc_id", "subnet_id",
		},
		"aws_vpc": {
			"id", "cidr_block", "enable_dns_support", "enable_dns_hostnames",
		},
		"aws_subnet": {
			"id", "vpc_id", "cidr_block", "availability_zone", "map_public_ip_on_launch",
		},
		"aws_security_group": {
			"id", "name", "description", "vpc_id",
		},
		"aws_s3_bucket": {
			"id", "bucket", "acl", "region",
		},
		"aws_db_instance": {
			"id", "engine", "engine_version", "instance_class", "allocated_storage",
			"storage_type", "multi_az",
		},
	}
	
	// Return attribute keys for resource type or a default set
	if keys, ok := attributeMap[resourceType]; ok {
		return keys
	}
	
	// Default attributes to compare
	return []string{"id", "name"}
}

// SerializeDriftReports serializes drift reports to JSON
func SerializeDriftReports(reports []DriftReport) ([]byte, error) {
	return json.Marshal(reports)
}

// ParseDriftReports parses drift reports from JSON
func ParseDriftReports(data []byte) ([]DriftReport, error) {
	var reports []DriftReport
	err := json.Unmarshal(data, &reports)
	return reports, err
}