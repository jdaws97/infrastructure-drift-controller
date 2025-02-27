package models

import (
	"encoding/json"
	"time"
)

// ResourceType represents the type of infrastructure resource
type ResourceType string

// Common resource types
const (
	ResourceTypeEC2Instance    ResourceType = "aws_ec2_instance"
	ResourceTypeS3Bucket       ResourceType = "aws_s3_bucket"
	ResourceTypeSecurityGroup  ResourceType = "aws_security_group"
	ResourceTypeAzureVM        ResourceType = "azure_virtual_machine"
	ResourceTypeGCPInstance    ResourceType = "gcp_compute_instance"
	ResourceTypeKubernetesNode ResourceType = "kubernetes_node"
	// Add more as needed
)

// ProviderType represents the cloud provider
type ProviderType string

// Supported providers
const (
	ProviderAWS        ProviderType = "aws"
	ProviderAzure      ProviderType = "azure"
	ProviderGCP        ProviderType = "gcp"
	ProviderKubernetes ProviderType = "kubernetes"
	// Add more as needed
)

// IaCType represents the IaC tool/language
type IaCType string

// Supported IaC types
const (
	IaCTypeTerraform     IaCType = "terraform"
	IaCTypePulumi        IaCType = "pulumi"
	IaCTypeCloudFormation IaCType = "cloudformation"
	IaCTypeAnsible       IaCType = "ansible"
	IaCTypeARMTemplate   IaCType = "arm"
	// Add more as needed
)

// Resource represents a single infrastructure resource
type Resource struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Type       ResourceType `json:"type"`
	Provider   ProviderType `json:"provider"`
	IaCType    IaCType      `json:"iac_type"`
	Region     string       `json:"region"`
	Account    string       `json:"account"` // AWS account ID, Azure subscription ID, etc.
	Project    string       `json:"project"` // GCP project, etc.
	Properties Properties   `json:"properties"`
	Tags       Tags         `json:"tags"`
	CreatedAt  time.Time    `json:"created_at"`
	UpdatedAt  time.Time    `json:"updated_at"`
}

// Properties represents the actual properties of a resource
type Properties map[string]interface{}

// Tags represents resource tags/labels
type Tags map[string]string

// DeepCopy creates a deep copy of the resource
func (r *Resource) DeepCopy() (*Resource, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	var copy Resource
	if err := json.Unmarshal(data, &copy); err != nil {
		return nil, err
	}

	return &copy, nil
}

// ResourceState represents the state of a resource at a point in time
type ResourceState struct {
	ResourceID   string      `json:"resource_id"`
	StateType    StateType   `json:"state_type"`
	Properties   Properties  `json:"properties"`
	CapturedAt   time.Time   `json:"captured_at"`
	StateVersion string      `json:"state_version"`
	Source       StateSource `json:"source"`
}

// StateType represents the type of state (expected vs actual)
type StateType string

const (
	StateTypeExpected StateType = "expected" // From IaC
	StateTypeActual   StateType = "actual"   // From Provider API
)

// StateSource represents where the state was sourced from
type StateSource string

const (
	StateSourceTerraform     StateSource = "terraform"
	StateSourceAWS           StateSource = "aws_api"
	StateSourceAzure         StateSource = "azure_api"
	StateSourceGCP           StateSource = "gcp_api"
	StateSourceCloudFormation StateSource = "cloudformation"
	// Add more as needed
)

// ResourceFilter provides filtering options for resource queries
type ResourceFilter struct {
	Provider   ProviderType  `json:"provider,omitempty"`
	IaCType    IaCType       `json:"iac_type,omitempty"`
	Region     string        `json:"region,omitempty"`
	Account    string        `json:"account,omitempty"`
	Project    string        `json:"project,omitempty"`
	Types      []ResourceType `json:"types,omitempty"`
	Tags       Tags          `json:"tags,omitempty"`
	UpdatedAfter *time.Time   `json:"updated_after,omitempty"`
}