package workflow

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
)

// Reconciler handles remediation of infrastructure drift
type Reconciler struct {
	db *database.DB
}

// NewReconciler creates a new reconciler
func NewReconciler(db *database.DB) *Reconciler {
	return &Reconciler{
		db: db,
	}
}

// AutoRemediate automatically remediates drift
func (r *Reconciler) AutoRemediate(drift *models.Drift, resource *models.Resource) error {
	// Choose remediation method based on IaC type
	switch resource.IaCType {
	case models.IaCTypeTerraform:
		return r.RemediateWithTerraform(drift, resource)
	case models.IaCTypeCloudFormation:
		return r.RemediateWithCloudFormation(drift, resource)
	case models.IaCTypePulumi:
		return r.RemediateWithPulumi(drift, resource)
	default:
		return fmt.Errorf("unsupported IaC type for auto remediation: %s", resource.IaCType)
	}
}

// CreateRemediationPlan creates a plan for remediation without executing it
func (r *Reconciler) CreateRemediationPlan(drift *models.Drift, resource *models.Resource) (map[string]interface{}, error) {
	// Choose planning method based on IaC type
	switch resource.IaCType {
	case models.IaCTypeTerraform:
		return r.CreateTerraformPlan(drift, resource)
	case models.IaCTypeCloudFormation:
		return r.CreateCloudFormationPlan(drift, resource)
	case models.IaCTypePulumi:
		return r.CreatePulumiPlan(drift, resource)
	default:
		return nil, fmt.Errorf("unsupported IaC type for remediation planning: %s", resource.IaCType)
	}
}

// RemediateWithTerraform remediates drift using Terraform
func (r *Reconciler) RemediateWithTerraform(drift *models.Drift, resource *models.Resource) error {
	// Get Terraform state and code location from resource metadata
	tfState, err := r.db.GetResourceMetadata(resource.ID, "terraform_state_path")
	if err != nil {
		return fmt.Errorf("failed to get Terraform state path: %w", err)
	}
	
	tfCode, err := r.db.GetResourceMetadata(resource.ID, "terraform_code_path")
	if err != nil {
		return fmt.Errorf("failed to get Terraform code path: %w", err)
	}
	
	// Ensure the paths exist
	if _, err := os.Stat(tfCode); os.IsNotExist(err) {
		return fmt.Errorf("terraform code path does not exist: %s", tfCode)
	}
	
	// Create a temporary working directory
	tmpDir, err := os.MkdirTemp("", "tf-remediate-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	
	// Copy the Terraform code to the working directory
	if err := copyDir(tfCode, tmpDir); err != nil {
		return fmt.Errorf("failed to copy Terraform code: %w", err)
	}
	
	// Copy the Terraform state file if it exists
	if tfState != "" {
		if _, err := os.Stat(tfState); err == nil {
			if err := copyFile(tfState, filepath.Join(tmpDir, "terraform.tfstate")); err != nil {
				return fmt.Errorf("failed to copy Terraform state: %w", err)
			}
		}
	}
	
	// Initialize Terraform
	cmd := exec.Command("terraform", "init")
	cmd.Dir = tmpDir
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("terraform init failed: %s, %w", output, err)
	}
	
	// Apply the Terraform configuration
	cmd = exec.Command("terraform", "apply", "-auto-approve")
	cmd.Dir = tmpDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("terraform apply failed: %s, %s, %w", stdout.String(), stderr.String(), err)
	}
	
	// Capture the new state if available
	if _, err := os.Stat(filepath.Join(tmpDir, "terraform.tfstate")); err == nil {
		newState := filepath.Join(tmpDir, "terraform.tfstate")
		
		// Copy the new state back to the original location if specified
		if tfState != "" {
			if err := copyFile(newState, tfState); err != nil {
				return fmt.Errorf("failed to update Terraform state: %w", err)
			}
		}
	}
	
	return nil
}

// CreateTerraformPlan creates a Terraform plan for remediation
func (r *Reconciler) CreateTerraformPlan(drift *models.Drift, resource *models.Resource) (map[string]interface{}, error) {
	// Get Terraform state and code location from resource metadata
	tfState, err := r.db.GetResourceMetadata(resource.ID, "terraform_state_path")
	if err != nil {
		return nil, fmt.Errorf("failed to get Terraform state path: %w", err)
	}
	
	tfCode, err := r.db.GetResourceMetadata(resource.ID, "terraform_code_path")
	if err != nil {
		return nil, fmt.Errorf("failed to get Terraform code path: %w", err)
	}
	
	// Ensure the paths exist
	if _, err := os.Stat(tfCode); os.IsNotExist(err) {
		return nil, fmt.Errorf("terraform code path does not exist: %s", tfCode)
	}
	
	// Create a temporary working directory
	tmpDir, err := os.MkdirTemp("", "tf-plan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	
	// Copy the Terraform code to the working directory
	if err := copyDir(tfCode, tmpDir); err != nil {
		return nil, fmt.Errorf("failed to copy Terraform code: %w", err)
	}
	
	// Copy the Terraform state file if it exists
	if tfState != "" {
		if _, err := os.Stat(tfState); err == nil {
			if err := copyFile(tfState, filepath.Join(tmpDir, "terraform.tfstate")); err != nil {
				return nil, fmt.Errorf("failed to copy Terraform state: %w", err)
			}
		}
	}
	
	// Initialize Terraform
	cmd := exec.Command("terraform", "init")
	cmd.Dir = tmpDir
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("terraform init failed: %s, %w", output, err)
	}
	
	// Create a plan file
	planFile := filepath.Join(tmpDir, "tfplan")
	cmd = exec.Command("terraform", "plan", "-out="+planFile, "-detailed-exitcode")
	cmd.Dir = tmpDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	// Run the plan command
	err = cmd.Run()
	
	// Parse exit code - Terraform uses specific exit codes for plan results
	// Exit code 0 = No changes
	// Exit code 1 = Error
	// Exit code 2 = Changes present
	exitCode := cmd.ProcessState.ExitCode()
	
	if exitCode == 1 {
		// Error running plan
		return nil, fmt.Errorf("terraform plan failed: %s, %s", stdout.String(), stderr.String())
	}
	
	// Get plan as JSON for easier parsing
	cmd = exec.Command("terraform", "show", "-json", planFile)
	cmd.Dir = tmpDir
	planOutput, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to show terraform plan: %w", err)
	}
	
	// Create result map
	result := map[string]interface{}{
		"has_changes": exitCode == 2,
		"plan_output": stdout.String(),
		"plan_json":   string(planOutput),
	}
	
	return result, nil
}

// RemediateWithCloudFormation remediates drift using CloudFormation
func (r *Reconciler) RemediateWithCloudFormation(drift *models.Drift, resource *models.Resource) error {
	// This is a simplified implementation - in a real system,
	// you would interact with AWS CloudFormation APIs
	
	// Get CloudFormation template and stack name from resource metadata
	cfnTemplate, err := r.db.GetResourceMetadata(resource.ID, "cloudformation_template_path")
	if err != nil {
		return fmt.Errorf("failed to get CloudFormation template path: %w", err)
	}
	
	stackName, err := r.db.GetResourceMetadata(resource.ID, "cloudformation_stack_name")
	if err != nil {
		return fmt.Errorf("failed to get CloudFormation stack name: %w", err)
	}
	
	// Ensure the template exists
	if _, err := os.Stat(cfnTemplate); os.IsNotExist(err) {
		return fmt.Errorf("CloudFormation template does not exist: %s", cfnTemplate)
	}
	
	// Example of calling AWS CLI to update the stack
	cmd := exec.Command("aws", "cloudformation", "update-stack",
		"--stack-name", stackName,
		"--template-body", fmt.Sprintf("file://%s", cfnTemplate),
		"--capabilities", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("CloudFormation update-stack failed: %s, %w", output, err)
	}
	
	return nil
}

// CreateCloudFormationPlan creates a CloudFormation change set without executing it
func (r *Reconciler) CreateCloudFormationPlan(drift *models.Drift, resource *models.Resource) (map[string]interface{}, error) {
	// Get CloudFormation template and stack name from resource metadata
	cfnTemplate, err := r.db.GetResourceMetadata(resource.ID, "cloudformation_template_path")
	if err != nil {
		return nil, fmt.Errorf("failed to get CloudFormation template path: %w", err)
	}
	
	stackName, err := r.db.GetResourceMetadata(resource.ID, "cloudformation_stack_name")
	if err != nil {
		return nil, fmt.Errorf("failed to get CloudFormation stack name: %w", err)
	}
	
	// Create a change set name
	changeSetName := fmt.Sprintf("drift-remediation-%s", drift.ID)
	
	// Example of calling AWS CLI to create a change set
	cmd := exec.Command("aws", "cloudformation", "create-change-set",
		"--stack-name", stackName,
		"--change-set-name", changeSetName,
		"--template-body", fmt.Sprintf("file://%s", cfnTemplate),
		"--capabilities", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("CloudFormation create-change-set failed: %s, %w", output, err)
	}
	
	// Describe the change set to get details
	cmd = exec.Command("aws", "cloudformation", "describe-change-set",
		"--stack-name", stackName,
		"--change-set-name", changeSetName)
	
	detailsOutput, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("CloudFormation describe-change-set failed: %s, %w", detailsOutput, err)
	}
	
	// Create result map
	result := map[string]interface{}{
		"change_set_name": changeSetName,
		"stack_name":      stackName,
		"details":         string(detailsOutput),
	}
	
	return result, nil
}

// RemediateWithPulumi remediates drift using Pulumi
func (r *Reconciler) RemediateWithPulumi(drift *models.Drift, resource *models.Resource) error {
	// This is a simplified implementation - in a real system,
	// you would interact with Pulumi APIs
	
	// Get Pulumi project and stack from resource metadata
	pulumiDir, err := r.db.GetResourceMetadata(resource.ID, "pulumi_project_dir")
	if err != nil {
		return fmt.Errorf("failed to get Pulumi project directory: %w", err)
	}
	
	pulumiStack, err := r.db.GetResourceMetadata(resource.ID, "pulumi_stack")
	if err != nil {
		return fmt.Errorf("failed to get Pulumi stack: %w", err)
	}
	
	// Ensure the project directory exists
	if _, err := os.Stat(pulumiDir); os.IsNotExist(err) {
		return fmt.Errorf("Pulumi project directory does not exist: %s", pulumiDir)
	}
	
	// Example of running pulumi up
	cmd := exec.Command("pulumi", "up", "--yes", "--stack", pulumiStack)
	cmd.Dir = pulumiDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Pulumi update failed: %s, %w", output, err)
	}
	
	return nil
}

// CreatePulumiPlan creates a Pulumi preview without executing it
func (r *Reconciler) CreatePulumiPlan(drift *models.Drift, resource *models.Resource) (map[string]interface{}, error) {
	// Get Pulumi project and stack from resource metadata
	pulumiDir, err := r.db.GetResourceMetadata(resource.ID, "pulumi_project_dir")
	if err != nil {
		return nil, fmt.Errorf("failed to get Pulumi project directory: %w", err)
	}
	
	pulumiStack, err := r.db.GetResourceMetadata(resource.ID, "pulumi_stack")
	if err != nil {
		return nil, fmt.Errorf("failed to get Pulumi stack: %w", err)
	}
	
	// Example of running pulumi preview
	cmd := exec.Command("pulumi", "preview", "--json", "--stack", pulumiStack)
	cmd.Dir = pulumiDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Pulumi preview failed: %s, %w", output, err)
	}
	
	// Create result map
	result := map[string]interface{}{
		"preview_output": string(output),
		"stack":          pulumiStack,
	}
	
	return result, nil
}

// Helper functions

// copyDir copies a directory recursively
func copyDir(src, dst string) error {
	// Get file info
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	
	// Create destination directory
	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}
	
	// Read directory entries
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	
	// Copy each entry
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		
		if entry.IsDir() {
			// Recursive copy for directories
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy file
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	
	return nil
}

// copyFile copies a single file
func copyFile(src, dst string) error {
	// Read source file
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	
	// Get file info for permissions
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	
	// Write to destination file
	return os.WriteFile(dst, data, info.Mode())
}

// TemplateMatcher finds appropriate workflow templates for resources
type TemplateMatcher struct {
	db *database.DB
}

// NewTemplateMatcher creates a new template matcher
func NewTemplateMatcher(db *database.DB) *TemplateMatcher {
	return &TemplateMatcher{
		db: db,
	}
}

// FindTemplateForResource finds the best matching workflow template for a resource
func (m *TemplateMatcher) FindTemplateForResource(resource *models.Resource) (*models.WorkflowTemplate, error) {
	// Get all templates
	templates, err := m.db.GetWorkflowTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to load workflow templates: %w", err)
	}
	
	// Find the best matching template
	var bestTemplate *models.WorkflowTemplate
	bestMatchScore := 0
	
	for _, template := range templates {
		score := m.calculateMatchScore(template, resource)
		
		if score > bestMatchScore {
			bestMatchScore = score
			bestTemplate = template
		}
	}
	
	// Check if we found a matching template
	if bestTemplate == nil {
		// Get default template
		for _, template := range templates {
			if template.IsDefault {
				return template, nil
			}
		}
		
		return nil, fmt.Errorf("no matching template found")
	}
	
	return bestTemplate, nil
}

// calculateMatchScore calculates how well a template matches a resource
func (m *TemplateMatcher) calculateMatchScore(template *models.WorkflowTemplate, resource *models.Resource) int {
	score := 0
	
	// Check resource type match
	for _, resourceType := range template.ResourceTypes {
		if resourceType == resource.Type {
			score += 10
			break
		}
	}
	
	// Check provider match
	for _, provider := range template.Providers {
		if provider == resource.Provider {
			score += 5
			break
		}
	}
	
	// Check tag matches
	for key, value := range template.Tags {
		if resourceValue, exists := resource.Tags[key]; exists && resourceValue == value {
			score += 3
		}
	}
	
	return score
}