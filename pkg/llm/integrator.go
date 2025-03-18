package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/drift"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/logging"
)

// ReActStep represents a step in the ReAct process
type ReActStep struct {
	Thought string `json:"thought"`
	Action  string `json:"action"`
	Result  string `json:"result,omitempty"`
}

// RemediationPlan represents a plan to remediate infrastructure drift
type RemediationPlan struct {
	DriftID        string    `json:"drift_id"`
	Description    string    `json:"description"`
	Actions        []string  `json:"actions"`
	Risks          []string  `json:"risks"`
	Justification  string    `json:"justification"`
	ApprovalNeeded bool      `json:"approval_needed"`
	CreatedAt      time.Time `json:"created_at"`
}

// Integrator is responsible for integrating LLM capabilities
type Integrator struct {
	client *Client
	logger *logging.Logger
}

// NewIntegrator creates a new LLM integrator
func NewIntegrator(client *Client) *Integrator {
	return &Integrator{
		client: client,
		logger: logging.GetGlobalLogger().WithField("component", "llm_integrator"),
	}
}

// AnalyzeDrift uses the LLM to analyze drift and generate remediation plans
func (i *Integrator) AnalyzeDrift(ctx context.Context, driftReport drift.DriftReport, 
	stateContext map[string]interface{}, cloudContext map[string]interface{}) (*RemediationPlan, error) {
	
	i.logger.Info("Analyzing drift using LLM for %s (%s)", driftReport.ResourceName, driftReport.ResourceID)
	
	// Create a context for the LLM prompt
	promptContext := map[string]interface{}{
		"drift_report": driftReport,
		"state_context": stateContext,
		"cloud_context": cloudContext,
		"current_time": time.Now().Format(time.RFC3339),
	}
	
	// Convert context to JSON
	contextJSON, err := json.MarshalIndent(promptContext, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal context to JSON: %w", err)
	}
	
	// Create the prompt
	prompt := buildReActPrompt(string(contextJSON))
	
	// Execute ReAct process with the LLM
	plan, err := i.executeReActProcess(ctx, prompt, driftReport)
	if err != nil {
		return nil, fmt.Errorf("failed to execute ReAct process: %w", err)
	}
	
	return plan, nil
}

// executeReActProcess executes the ReAct process with the LLM
func (i *Integrator) executeReActProcess(ctx context.Context, initialPrompt string, 
	driftReport drift.DriftReport) (*RemediationPlan, error) {
	
	// Initialize conversation history
	conversation := []string{initialPrompt}
	
	// Initialize steps
	var steps []ReActStep
	maxIterations := 5
	
	// Execute ReAct loop
	for iteration := 0; iteration < maxIterations; iteration++ {
		// Combine conversation history into a single prompt
		prompt := strings.Join(conversation, "\n\n")
		
		// Send to LLM
		response, err := i.client.Complete(ctx, CompletionRequest{
			Prompt:      prompt,
			MaxTokens:   2048,
			Temperature: 0.2,
		})
		if err != nil {
			return nil, fmt.Errorf("LLM completion failed: %w", err)
		}
		
		// Parse response
		step, isDone, err := i.parseReActResponse(response.Text)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ReAct response: %w", err)
		}
		
		// Add step to history
		steps = append(steps, step)
		
		// Add response to conversation
		conversation = append(conversation, fmt.Sprintf("Thought: %s\n\nAction: %s", step.Thought, step.Action))
		
		// Check if we're done
		if isDone {
			// Generate remediation plan from the final step
			plan, err := i.generateRemediationPlan(driftReport, steps)
			if err != nil {
				return nil, fmt.Errorf("failed to generate remediation plan: %w", err)
			}
			return plan, nil
		}
		
		// Execute action and get result
		result, err := i.executeAction(ctx, step.Action, driftReport)
		if err != nil {
			return nil, fmt.Errorf("failed to execute action: %w", err)
		}
		
		// Update step with result
		step.Result = result
		
		// Add result to conversation
		conversation = append(conversation, fmt.Sprintf("Result: %s", result))
	}
	
	// If we reach here, we've hit the maximum iterations without completing
	return nil, fmt.Errorf("ReAct process did not complete within %d iterations", maxIterations)
}

// parseReActResponse parses the response from the LLM
func (i *Integrator) parseReActResponse(response string) (ReActStep, bool, error) {
	// Split response into sections
	lines := strings.Split(response, "\n")
	
	// Extract thought
	thought := ""
	thoughtStarted := false
	actionStarted := false
	
	for _, line := range lines {
		lineText := strings.TrimSpace(line)
		
		if strings.HasPrefix(strings.ToLower(lineText), "thought:") {
			thoughtStarted = true
			thought = strings.TrimPrefix(lineText, "Thought:")
			thought = strings.TrimPrefix(thought, "thought:")
			thought = strings.TrimSpace(thought)
			continue
		}
		
		if strings.HasPrefix(strings.ToLower(lineText), "action:") {
			actionStarted = true
			break
		}
		
		if thoughtStarted && !actionStarted && lineText != "" {
			thought += " " + lineText
		}
	}
	
	// Extract action
	action := ""
	actionStarted = false
	resultStarted := false
	
	for _, line := range lines {
		lineText := strings.TrimSpace(line)
		
		if strings.HasPrefix(strings.ToLower(lineText), "action:") {
			actionStarted = true
			action = strings.TrimPrefix(lineText, "Action:")
			action = strings.TrimPrefix(action, "action:")
			action = strings.TrimSpace(action)
			continue
		}
		
		if strings.HasPrefix(strings.ToLower(lineText), "result:") || 
		   strings.HasPrefix(strings.ToLower(lineText), "remediation plan:") {
			resultStarted = true
			break
		}
		
		if actionStarted && !resultStarted && lineText != "" {
			action += " " + lineText
		}
	}
	
	// Check if we're done (the action is "FINISH" or contains a remediation plan)
	isDone := strings.Contains(strings.ToUpper(action), "FINISH") || 
		strings.Contains(strings.ToLower(action), "remediation plan")
	
	// Verify we extracted something
	if thought == "" && action == "" {
		return ReActStep{}, false, fmt.Errorf("failed to parse ReAct response: %s", response)
	}
	
	step := ReActStep{
		Thought: thought,
		Action:  action,
	}
	
	return step, isDone, nil
}

// executeAction executes an action specified by the LLM
func (i *Integrator) executeAction(ctx context.Context, action string, driftReport drift.DriftReport) (string, error) {
	// Parse action parameters if any
	actionName, params := parseAction(action)
	
	// Convert action to lowercase for case-insensitive matching
	actionLower := strings.ToLower(actionName)
	
	// Execute appropriate action
	switch {
	case strings.Contains(actionLower, "get_resource_details"):
		// Get more details about the resource
		return i.getResourceDetails(ctx, driftReport, params)
		
	case strings.Contains(actionLower, "get_drift_details"):
		// Get more details about the drift
		return i.getDriftDetails(ctx, driftReport, params)
		
	case strings.Contains(actionLower, "assess_impact"):
		// Assess the impact of the drift
		return i.assessImpact(ctx, driftReport, params)
		
	case strings.Contains(actionLower, "suggest_terraform_code"):
		// Suggest Terraform code to fix the drift
		return i.suggestTerraformCode(ctx, driftReport, params)
		
	case strings.Contains(actionLower, "evaluate_risk"):
		// Evaluate the risk of the drift
		return i.evaluateRisk(ctx, driftReport, params)
		
	case strings.Contains(actionLower, "check_dependencies"):
		// Check for resource dependencies
		return i.checkDependencies(ctx, driftReport, params)
		
	case strings.Contains(actionLower, "get_best_practices"):
		// Get best practices for resource type
		return i.getBestPractices(ctx, driftReport, params)
		
	case strings.Contains(actionLower, "summarize_drift_pattern"):
		// Summarize drift pattern
		return i.summarizeDriftPattern(ctx, driftReport, params)
		
	case strings.Contains(actionLower, "finish"):
		// Finish the process
		return "Process complete. Ready to generate final remediation plan.", nil
		
	default:
		// Unknown action
		return fmt.Sprintf("Unknown action: %s. Available actions: get_resource_details, get_drift_details, assess_impact, suggest_terraform_code, evaluate_risk, check_dependencies, get_best_practices, summarize_drift_pattern, or finish.", actionName), nil
	}
}

// parseAction parses an action string into name and parameters
func parseAction(action string) (string, map[string]string) {
	// Initialize parameters map
	params := make(map[string]string)
	
	// Check if action contains parameters
	parts := strings.SplitN(action, "(", 2)
	if len(parts) != 2 {
		return strings.TrimSpace(action), params
	}
	
	// Extract action name
	actionName := strings.TrimSpace(parts[0])
	
	// Extract parameters
	paramsPart := strings.TrimSuffix(parts[1], ")")
	paramPairs := strings.Split(paramsPart, ",")
	
	for _, pair := range paramPairs {
		keyValue := strings.SplitN(pair, "=", 2)
		if len(keyValue) == 2 {
			key := strings.TrimSpace(keyValue[0])
			value := strings.Trim(strings.TrimSpace(keyValue[1]), "\"'")
			params[key] = value
		}
	}
	
	return actionName, params
}

// getResourceDetails gets detailed information about a resource
func (i *Integrator) getResourceDetails(ctx context.Context, driftReport drift.DriftReport, params map[string]string) (string, error) {
	// Format resource information
	resourceInfo := map[string]interface{}{
		"resource_id":   driftReport.ResourceID,
		"resource_name": driftReport.ResourceName,
		"resource_type": driftReport.ResourceType,
		"drift_type":    driftReport.DriftType,
		"severity":      driftReport.Severity,
		"detected_at":   driftReport.DetectedAt,
	}
	
	// Add metadata
	if driftReport.Metadata != nil && len(driftReport.Metadata) > 0 {
		resourceInfo["metadata"] = driftReport.Metadata
	}
	
	return fmt.Sprintf("Resource details for %s (%s):\n%s", 
		driftReport.ResourceName, driftReport.ResourceID, 
		prettyFormatJSON(resourceInfo)), nil
}

// getDriftDetails gets detailed information about drift differences
func (i *Integrator) getDriftDetails(ctx context.Context, driftReport drift.DriftReport, params map[string]string) (string, error) {
	// Handle different drift types
	switch driftReport.DriftType {
	case drift.ResourceMissing:
		return fmt.Sprintf("Drift details for %s (%s):\n"+
			"This resource exists in the Terraform state but is missing in the AWS account.\n"+
			"This could be because the resource was:\n"+
			"- Deleted manually through the AWS console or CLI\n"+
			"- Deleted by another automation tool\n"+
			"- Failed to be created properly\n\n"+
			"To fix this drift, you'll need to either:\n"+
			"- Run terraform apply to recreate the resource\n"+
			"- Remove the resource from your Terraform configuration",
			driftReport.ResourceName, driftReport.ResourceID), nil
			
	case drift.ResourceExtra:
		return fmt.Sprintf("Drift details for %s (%s):\n"+
			"This resource exists in the AWS account but is not in the Terraform state.\n"+
			"This could be because the resource was:\n"+
			"- Created manually through the AWS console or CLI\n"+
			"- Created by another automation tool\n"+
			"- Previously managed by Terraform but removed from the configuration without being destroyed\n\n"+
			"To fix this drift, you'll need to either:\n"+
			"- Import the resource into your Terraform state\n"+
			"- Delete the resource if it's not needed",
			driftReport.ResourceName, driftReport.ResourceID), nil
			
	case drift.AttributeDrift, drift.TagDrift:
		// Format differences for better readability
		differencesOutput := "Attribute differences:\n"
		
		for i, diff := range driftReport.Differences {
			differencesOutput += fmt.Sprintf("%d. Property: %s\n", i+1, diff.PropertyPath)
			differencesOutput += fmt.Sprintf("   Expected (Terraform): %v\n", formatValue(diff.ExpectedValue))
			differencesOutput += fmt.Sprintf("   Actual (AWS): %v\n", formatValue(diff.ActualValue))
			differencesOutput += "\n"
		}
		
		return fmt.Sprintf("Drift details for %s (%s):\n%s", 
			driftReport.ResourceName, driftReport.ResourceID, differencesOutput), nil
			
	default:
		return fmt.Sprintf("Drift details for %s (%s):\n%s", 
			driftReport.ResourceName, driftReport.ResourceID, 
			prettyFormatJSON(driftReport.Differences)), nil
	}
}

// assessImpact assesses the impact of a drift
func (i *Integrator) assessImpact(ctx context.Context, driftReport drift.DriftReport, params map[string]string) (string, error) {
	// Define impact descriptions based on resource type and drift type
	impactDescriptions := map[string]map[drift.DriftType]string{
		"aws_instance": {
			drift.ResourceMissing: "Critical impact. The instance defined in Terraform doesn't exist in AWS, causing potential application downtime or failure.",
			drift.ResourceExtra: "Medium impact. An unmanaged instance exists in AWS, potentially incurring unnecessary costs.",
			drift.AttributeDrift: "Variable impact depending on which attributes have drifted. Changes to instance type or AMI could affect performance or security.",
			drift.TagDrift: "Low impact. Tag differences may affect cost allocation or resource organization but don't affect functionality.",
		},
		"aws_s3_bucket": {
			drift.ResourceMissing: "High impact. The S3 bucket defined in Terraform doesn't exist in AWS, potentially causing data storage issues.",
			drift.ResourceExtra: "Medium impact. An unmanaged S3 bucket exists in AWS, potentially creating security risks or compliance issues.",
			drift.AttributeDrift: "High impact. Attribute differences could affect access control, encryption, or lifecycle policies.",
			drift.TagDrift: "Low impact. Tag differences may affect cost allocation or resource organization.",
		},
		"aws_security_group": {
			drift.ResourceMissing: "High impact. Missing security group could cause networking issues and security vulnerabilities.",
			drift.ResourceExtra: "Medium impact. Extra security group could create unintended network access paths.",
			drift.AttributeDrift: "Critical impact. Changes to security group rules could create security vulnerabilities or block legitimate traffic.",
			drift.TagDrift: "Low impact. Tag differences don't affect security group functionality.",
		},
	}
	
	// Get resource type and drift type specific impact
	var impactDescription string
	if typeImpacts, ok := impactDescriptions[driftReport.ResourceType]; ok {
		if description, ok := typeImpacts[driftReport.DriftType]; ok {
			impactDescription = description
		}
	}
	
	// Use generic impact if specific one not found
	if impactDescription == "" {
		switch driftReport.DriftType {
		case drift.ResourceMissing:
			impactDescription = "Resource exists in Terraform but not in AWS. This could lead to functionality gaps or failures."
		case drift.ResourceExtra:
			impactDescription = "Resource exists in AWS but not in Terraform. This creates an unmanaged resource that could cause inconsistencies."
		case drift.AttributeDrift:
			impactDescription = "Resource attributes differ between Terraform and AWS. This could cause unexpected behavior."
		case drift.TagDrift:
			impactDescription = "Resource tags differ between Terraform and AWS. This could affect resource organization or cost tracking."
		}
	}
	
	// Generate response
	response := fmt.Sprintf("Impact assessment for drift in %s resource %s:\n"+
		"- Severity: %s\n"+
		"- Affected resource: %s (%s)\n"+
		"- Drift type: %s\n"+
		"- Number of differences: %d\n\n"+
		"Impact description: %s\n\n"+
		"Potential consequences:\n",
		driftReport.ResourceType, driftReport.ResourceName,
		driftReport.Severity, driftReport.ResourceName, driftReport.ResourceID,
		driftReport.DriftType, len(driftReport.Differences),
		impactDescription)
	
	// Add potential consequences based on severity
	switch driftReport.Severity {
	case drift.SeverityCritical:
		response += "- Could cause immediate service disruption\n"
		response += "- May create security vulnerabilities\n"
		response += "- Requires immediate attention\n"
	case drift.SeverityHigh:
		response += "- Could affect service performance or reliability\n"
		response += "- May create compliance issues\n"
		response += "- Should be addressed promptly\n"
	case drift.SeverityMedium:
		response += "- Could cause minor operational issues\n"
		response += "- May affect cost management\n"
		response += "- Should be addressed in the normal course of operations\n"
	case drift.SeverityLow:
		response += "- Minimal operational impact\n"
		response += "- Primarily affects organization or documentation\n"
		response += "- Can be addressed as part of routine maintenance\n"
	}
	
	return response, nil
}

// suggestTerraformCode suggests Terraform code to fix drift
func (i *Integrator) suggestTerraformCode(ctx context.Context, driftReport drift.DriftReport, params map[string]string) (string, error) {
	// Base response
	response := fmt.Sprintf("Suggested Terraform code changes for %s (%s):\n\n", 
		driftReport.ResourceName, driftReport.ResourceID)
	
	// Handle different drift types
	switch driftReport.DriftType {
	case drift.ResourceMissing:
		response += "The resource is missing in AWS but exists in Terraform. You should run:\n\n"
		response += "```bash\nterraform apply\n```\n\n"
		response += "This will recreate the missing resource according to your Terraform configuration.\n"
		
	case drift.ResourceExtra:
		response += "The resource exists in AWS but not in Terraform. You can either:\n\n"
		response += "1. Import the resource into Terraform:\n\n"
		response += fmt.Sprintf("```bash\nterraform import %s.resource_name %s\n```\n\n", 
			driftReport.ResourceType, driftReport.ResourceID)
		response += "Then add the corresponding resource definition to your configuration.\n\n"
		response += "2. Or delete the resource if it's not needed:\n\n"
		response += fmt.Sprintf("```bash\naws %s delete-%s --id %s\n```\n", 
			resourceTypeToAWSService(driftReport.ResourceType),
			resourceTypeToAWSCommand(driftReport.ResourceType),
			driftReport.ResourceID)
		
	case drift.AttributeDrift:
		response += "The resource has attribute differences between Terraform and AWS. Suggested code changes:\n\n"
		response += "```hcl\n"
		response += fmt.Sprintf("resource \"%s\" \"%s\" {\n", 
			driftReport.ResourceType, sanitizeResourceName(driftReport.ResourceName))
		
		// Add changed attributes
		for _, diff := range driftReport.Differences {
			response += fmt.Sprintf("  %s = %s\n", 
				diff.PropertyPath, 
				terraformFormatValue(diff.ActualValue))
		}
		
		response += "  # ... other attributes remain unchanged\n"
		response += "}\n"
		response += "```\n\n"
		
		response += "After making these changes, run:\n\n"
		response += "```bash\nterraform plan\nterraform apply\n```\n"
		
	case drift.TagDrift:
		response += "The resource has tag differences between Terraform and AWS. Suggested code changes:\n\n"
		response += "```hcl\n"
		response += fmt.Sprintf("resource \"%s\" \"%s\" {\n", 
			driftReport.ResourceType, sanitizeResourceName(driftReport.ResourceName))
		response += "  # ... existing resource configuration\n\n"
		response += "  tags = {\n"
		
		// Add tags from actual cloud resource
		for key, value := range extractTags(driftReport.Differences) {
			response += fmt.Sprintf("    %s = \"%s\"\n", key, value)
		}
		
		response += "  }\n"
		response += "}\n"
		response += "```\n"
	}
	
	return response, nil
}

// evaluateRisk evaluates the risk of the drift
func (i *Integrator) evaluateRisk(ctx context.Context, driftReport drift.DriftReport, params map[string]string) (string, error) {
	// Define risk factors based on resource type and drift type
	response := fmt.Sprintf("Risk evaluation for drift in %s resource %s:\n\n", 
		driftReport.ResourceType, driftReport.ResourceName)
	
	// Calculate risk score (simple algorithm)
	var riskScore float64
	
	// Base score from severity
	switch driftReport.Severity {
	case drift.SeverityCritical:
		riskScore += 4.0
		response += "🔴 Critical severity: This drift has critical implications for your infrastructure.\n"
	case drift.SeverityHigh:
		riskScore += 3.0
		response += "🟠 High severity: This drift has significant implications for your infrastructure.\n"
	case drift.SeverityMedium:
		riskScore += 2.0
		response += "🟡 Medium severity: This drift has moderate implications for your infrastructure.\n"
	case drift.SeverityLow:
		riskScore += 1.0
		response += "🟢 Low severity: This drift has minor implications for your infrastructure.\n"
	}
	
	// Add score based on drift type
	switch driftReport.DriftType {
	case drift.ResourceMissing:
		riskScore += 2.0
		response += "• Missing resource: The resource defined in Terraform doesn't exist in AWS.\n"
		response += "  - Risk of functional gaps or application failures\n"
		response += "  - Services depending on this resource may be impaired\n"
	case drift.ResourceExtra:
		riskScore += 1.0
		response += "• Extra resource: A resource exists in AWS that's not in Terraform.\n"
		response += "  - Risk of unmanaged infrastructure\n"
		response += "  - Potential security concerns from unaudited resources\n"
		response += "  - Possible unnecessary costs\n"
	case drift.AttributeDrift:
		riskScore += float64(len(driftReport.Differences)) * 0.5
		response += fmt.Sprintf("• Attribute drift: %d attributes differ between Terraform and AWS.\n", len(driftReport.Differences))
		
		// Identify high-risk attributes
		highRiskAttrs := 0
		for _, diff := range driftReport.Differences {
			if isHighRiskAttribute(driftReport.ResourceType, diff.PropertyPath) {
				highRiskAttrs++
				response += fmt.Sprintf("  - 🚨 High-risk attribute drift: %s\n", diff.PropertyPath)
			}
		}
		
		if highRiskAttrs > 0 {
			riskScore += float64(highRiskAttrs) * 0.5
		}
	case drift.TagDrift:
		riskScore += 0.5
		response += "• Tag drift: Resource tags differ between Terraform and AWS.\n"
		response += "  - Primarily an organizational concern\n"
		response += "  - May affect cost reporting or resource categorization\n"
	}
	
	// Add risk level assessment
	response += "\nOverall risk assessment:\n"
	if riskScore >= 5.0 {
		response += "🔴 Very High Risk (Score: " + fmt.Sprintf("%.1f", riskScore) + "/10)\n"
		response += "Immediate remediation is strongly recommended.\n"
	} else if riskScore >= 3.5 {
		response += "🟠 High Risk (Score: " + fmt.Sprintf("%.1f", riskScore) + "/10)\n"
		response += "Prompt remediation is recommended.\n"
	} else if riskScore >= 2.0 {
		response += "🟡 Medium Risk (Score: " + fmt.Sprintf("%.1f", riskScore) + "/10)\n"
		response += "Remediation should be planned in the short term.\n"
	} else {
		response += "🟢 Low Risk (Score: " + fmt.Sprintf("%.1f", riskScore) + "/10)\n"
		response += "Remediation can be included in routine maintenance.\n"
	}
	
	return response, nil
}

// checkDependencies checks for resource dependencies
func (i *Integrator) checkDependencies(ctx context.Context, driftReport drift.DriftReport, params map[string]string) (string, error) {
	// This would typically involve querying the infrastructure graph
	// For this example, we'll return a simulated response
	
	response := fmt.Sprintf("Dependency analysis for %s resource %s (%s):\n\n", 
		driftReport.ResourceType, driftReport.ResourceName, driftReport.ResourceID)
	
	// Add simulated dependencies based on resource type
	switch driftReport.ResourceType {
	case "aws_instance":
		response += "This EC2 instance may have the following dependencies:\n\n"
		response += "Upstream dependencies (resources this instance depends on):\n"
		response += "- VPC and subnet for networking\n"
		response += "- Security groups for network access control\n"
		response += "- IAM instance profile for AWS API permissions\n"
		response += "- AMI for the instance image\n\n"
		
		response += "Downstream dependencies (resources that depend on this instance):\n"
		response += "- Load balancer target groups\n"
		response += "- Auto-scaling groups\n"
		response += "- Route53 DNS records\n"
		
	case "aws_vpc":
		response += "This VPC may have the following dependencies:\n\n"
		response += "Upstream dependencies (resources this VPC depends on):\n"
		response += "- IPAM pools for IP address management\n\n"
		
		response += "Downstream dependencies (resources that depend on this VPC):\n"
		response += "- Subnets\n"
		response += "- Route tables\n"
		response += "- Network ACLs\n"
		response += "- Internet gateways\n"
		response += "- NAT gateways\n"
		response += "- VPC endpoints\n"
		response += "- EC2 instances\n"
		response += "- RDS instances\n"
		
	case "aws_s3_bucket":
		response += "This S3 bucket may have the following dependencies:\n\n"
		response += "Upstream dependencies (resources this bucket depends on):\n"
		response += "- IAM policies for access control\n"
		response += "- KMS keys for encryption\n\n"
		
		response += "Downstream dependencies (resources that depend on this bucket):\n"
		response += "- CloudFront distributions\n"
		response += "- Lambda functions\n"
		response += "- EC2 instances that access the bucket\n"
		response += "- Application code that reads from or writes to the bucket\n"
		
	default:
		response += "No specific dependency information available for this resource type.\n"
		response += "General considerations:\n"
		response += "- Check Terraform graph to visualize dependencies\n"
		response += "- Review application architecture documentation\n"
		response += "- Consider potential service integrations\n"
	}
	
	// Add remediation considerations
	response += "\nDependency considerations for remediation:\n"
	response += "- Changes to this resource may impact dependent resources\n"
	response += "- Consider testing changes in a non-production environment first\n"
	response += "- Plan for potential service disruptions during remediation\n"
	response += "- Update dependent resources as needed\n"
	
	return response, nil
}

// getBestPractices gets best practices for resource type
func (i *Integrator) getBestPractices(ctx context.Context, driftReport drift.DriftReport, params map[string]string) (string, error) {
	response := fmt.Sprintf("Best practices for %s resources:\n\n", driftReport.ResourceType)
	
	// Add best practices based on resource type
	switch driftReport.ResourceType {
	case "aws_instance":
		response += "EC2 Instance Best Practices:\n\n"
		response += "1. Security\n"
		response += "   - Use security groups to restrict access to only necessary ports\n"
		response += "   - Use IAM roles instead of hardcoded credentials\n"
		response += "   - Keep AMIs updated with latest security patches\n\n"
		
		response += "2. Cost Optimization\n"
		response += "   - Right-size instances based on actual utilization\n"
		response += "   - Use Reserved Instances or Savings Plans for consistent workloads\n"
		response += "   - Enable detailed monitoring for better visibility\n\n"
		
		response += "3. Reliability\n"
		response += "   - Deploy across multiple Availability Zones\n"
		response += "   - Use Auto Scaling Groups for high availability\n"
		response += "   - Implement proper backup strategies\n\n"
		
		response += "4. Performance\n"
		response += "   - Choose instance types optimized for your workload\n"
		response += "   - Use placement groups for low-latency networking\n"
		response += "   - Consider EBS optimized instances for I/O intensive workloads\n"
		
	case "aws_s3_bucket":
		response += "S3 Bucket Best Practices:\n\n"
		response += "1. Security\n"
		response += "   - Block public access unless explicitly required\n"
		response += "   - Enable server-side encryption\n"
		response += "   - Use bucket policies to restrict access\n"
		response += "   - Enable versioning to protect against accidental deletion\n\n"
		
		response += "2. Cost Optimization\n"
		response += "   - Configure lifecycle policies to transition objects to cheaper storage classes\n"
		response += "   - Set up expiration rules for temporary data\n"
		response += "   - Monitor and clean up incomplete multipart uploads\n\n"
		
		response += "3. Performance\n"
		response += "   - Use appropriate storage class based on access patterns\n"
		response += "   - Consider request rate limitations for high-throughput workloads\n"
		response += "   - Use CloudFront for content distribution\n"
		
	case "aws_vpc":
		response += "VPC Best Practices:\n\n"
		response += "1. Architecture\n"
		response += "   - Design CIDR blocks carefully to avoid overlaps\n"
		response += "   - Create private and public subnets as needed\n"
		response += "   - Use Transit Gateway for complex connectivity\n\n"
		
		response += "2. Security\n"
		response += "   - Implement network ACLs and security groups\n"
		response += "   - Use Flow Logs for monitoring network traffic\n"
		response += "   - Minimize direct internet access for resources\n\n"
		
		response += "3. Connectivity\n"
		response += "   - Use VPC Endpoints for AWS services\n"
		response += "   - Configure proper routing tables\n"
		response += "   - Consider Direct Connect for stable, private connectivity\n"
		
	default:
		response += "General IaC Best Practices:\n\n"
		response += "1. Terraform Management\n"
		response += "   - Use remote state with locking\n"
		response += "   - Organize code into modules\n"
		response += "   - Use consistent naming conventions\n"
		response += "   - Document resources and variables\n\n"
		
		response += "2. Drift Prevention\n"
		response += "   - Run regular drift detection\n"
		response += "   - Implement CI/CD pipelines for Terraform changes\n"
		response += "   - Use Pull Requests to review infrastructure changes\n"
		response += "   - Lock critical resources to prevent manual changes\n"
	}
	
	return response, nil
}

// summarizeDriftPattern analyzes drift patterns across resources
func (i *Integrator) summarizeDriftPattern(ctx context.Context, driftReport drift.DriftReport, params map[string]string) (string, error) {
	// This would typically analyze multiple drift reports
	// For this example, we'll provide a simulated pattern analysis
	
	response := "Drift Pattern Analysis:\n\n"
	
	// Add simulated pattern based on drift type
	switch driftReport.DriftType {
	case drift.ResourceMissing:
		response += "Pattern: Missing Resource\n\n"
		response += "This pattern often indicates:\n"
		response += "- Manual deletion outside of Terraform workflow\n"
		response += "- Resource creation failure during past Terraform operations\n"
		response += "- Potential region or account misconfiguration\n\n"
		
		response += "Common root causes:\n"
		response += "1. Manual intervention in emergencies without updating Terraform\n"
		response += "2. Insufficient access controls on the AWS console\n"
		response += "3. Incomplete knowledge transfer between team members\n\n"
		
		response += "Recommended preventive measures:\n"
		response += "- Implement strict access controls through IAM\n"
		response += "- Document emergency procedures to include Terraform updates\n"
		response += "- Set up CloudTrail alerts for resource deletions\n"
		
	case drift.ResourceExtra:
		response += "Pattern: Extra Resource\n\n"
		response += "This pattern often indicates:\n"
		response += "- Resources created outside of Terraform\n"
		response += "- Failed terraform destroy operations\n"
		response += "- Resources imported but not properly tracked\n\n"
		
		response += "Common root causes:\n"
		response += "1. Shadow IT or unofficial resource provisioning\n"
		response += "2. Experimentation without cleanup\n"
		response += "3. Incomplete migration to Infrastructure as Code\n\n"
		
		response += "Recommended preventive measures:\n"
		response += "- Create a resource tagging policy to identify unmanaged resources\n"
		response += "- Implement AWS Service Control Policies to enforce Terraform usage\n"
		response += "- Regular cloud inventory reconciliation\n"
		
	case drift.AttributeDrift:
		response += "Pattern: Attribute Drift\n\n"
		response += "This pattern often indicates:\n"
		response += "- Manual updates to resource configurations\n"
		response += "- AWS auto-scaling or auto-healing modifying resources\n"
		response += "- Changes made by AWS automatically (security patches, etc.)\n\n"
		
		response += "Common root causes:\n"
		response += "1. Urgent changes made directly in AWS console\n"
		response += "2. Automated AWS processes modifying resources\n"
		response += "3. Misunderstanding of which attributes are managed by Terraform\n\n"
		
		response += "Recommended preventive measures:\n"
		response += "- Educate team on Terraform lifecycle blocks for auto-modified attributes\n"
		response += "- Implement change management processes\n"
		response += "- Regular drift detection and remediation\n"
		
	case drift.TagDrift:
		response += "Pattern: Tag Drift\n\n"
		response += "This pattern often indicates:\n"
		response += "- Inconsistent tagging practices\n"
		response += "- Multiple tagging systems (automated + manual)\n"
		response += "- Tags added for temporary purposes but not removed\n\n"
		
		response += "Common root causes:\n"
		response += "1. Lack of centralized tagging strategy\n"
		response += "2. Automated tools adding tags outside of Terraform\n"
		response += "3. Insufficient knowledge of existing tag schema\n\n"
		
		response += "Recommended preventive measures:\n"
		response += "- Develop a comprehensive tagging strategy\n"
		response += "- Use AWS Tag Policies to enforce standards\n"
		response += "- Consolidate tagging in Terraform\n"
	}
	
	return response, nil
}

// Helper function to format values
func formatValue(value interface{}) string {
	if value == nil {
		return "null"
	}
	
	switch v := value.(type) {
	case string:
		return fmt.Sprintf("\"%s\"", v)
	case bool, int, float64:
		return fmt.Sprintf("%v", v)
	default:
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(jsonBytes)
	}
}

// Helper function to format values for Terraform code
func terraformFormatValue(value interface{}) string {
	if value == nil {
		return "null"
	}
	
	switch v := value.(type) {
	case string:
		return fmt.Sprintf("\"%s\"", v)
	case bool:
		return fmt.Sprintf("%t", v)
	case int:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%g", v)
	case []interface{}:
		if len(v) == 0 {
			return "[]"
		}
		result := "[\n"
		for _, item := range v {
			result += fmt.Sprintf("    %s,\n", terraformFormatValue(item))
		}
		result += "  ]"
		return result
	case map[string]interface{}:
		if len(v) == 0 {
			return "{}"
		}
		result := "{\n"
		for key, val := range v {
			result += fmt.Sprintf("    %s = %s\n", key, terraformFormatValue(val))
		}
		result += "  }"
		return result
	default:
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(jsonBytes)
	}
}

// Helper function to sanitize resource names for Terraform
func sanitizeResourceName(name string) string {
	// Replace invalid characters with underscores
	result := strings.ReplaceAll(name, "-", "_")
	result = strings.ReplaceAll(result, ".", "_")
	result = strings.ReplaceAll(result, " ", "_")
	
	// Ensure it starts with a letter or underscore
	if len(result) > 0 && !((result[0] >= 'a' && result[0] <= 'z') || 
		                  (result[0] >= 'A' && result[0] <= 'Z') || 
		                  result[0] == '_') {
		result = "_" + result
	}
	
	return result
}

// Helper function to convert resource type to AWS service name
func resourceTypeToAWSService(resourceType string) string {
	// Extract service name from resource type
	parts := strings.Split(resourceType, "_")
	if len(parts) < 2 {
		return "resource"
	}
	
	// Map AWS service names
	switch parts[1] {
	case "instance":
		return "ec2"
	case "s3":
		return "s3"
	case "rds":
		return "rds"
	case "vpc", "subnet", "security", "route":
		return "ec2"
	default:
		return parts[1]
	}
}

// Helper function to convert resource type to AWS command
func resourceTypeToAWSCommand(resourceType string) string {
	parts := strings.Split(resourceType, "_")
	if len(parts) < 2 {
		return "resource"
	}
	
	// Map to CLI command names
	switch resourceType {
	case "aws_instance":
		return "instance"
	case "aws_s3_bucket":
		return "bucket"
	case "aws_vpc":
		return "vpc"
	case "aws_subnet":
		return "subnet"
	case "aws_security_group":
		return "security-group"
	case "aws_db_instance":
		return "db-instance"
	default:
		if len(parts) > 2 {
			return parts[2]
		}
		return "resource"
	}
}

// Helper function to check if an attribute is high risk
func isHighRiskAttribute(resourceType, attributePath string) bool {
	// Define high-risk attributes by resource type
	highRiskAttrs := map[string][]string{
		"aws_instance": {
			"subnet_id", "vpc_security_group_ids", "iam_instance_profile",
		},
		"aws_s3_bucket": {
			"acl", "policy", "bucket_policy", "cors_rule", "versioning", "logging",
		},
		"aws_security_group": {
			"ingress", "egress",
		},
		"aws_vpc": {
			"cidr_block", "enable_dns_support", "enable_dns_hostnames",
		},
	}
	
	// Check if attribute is in high-risk list
	if attrs, ok := highRiskAttrs[resourceType]; ok {
		for _, attr := range attrs {
			if attributePath == attr || strings.HasPrefix(attributePath, attr+".") {
				return true
			}
		}
	}
	
	return false
}

// Helper function to extract tags from drift differences
func extractTags(differences []drift.AttributeDifference) map[string]string {
	tags := make(map[string]string)
	
	for _, diff := range differences {
		// Check if this is a tag difference
		if strings.HasPrefix(diff.PropertyPath, "tags.") {
			tagKey := strings.TrimPrefix(diff.PropertyPath, "tags.")
			
			// Get actual cloud value if present
			if diff.ActualValue != nil {
				if strVal, ok := diff.ActualValue.(string); ok {
					tags[tagKey] = strVal
				}
			}
		}
	}
	
	return tags
}

// generateRemediationPlan generates a remediation plan from the ReAct steps
func (i *Integrator) generateRemediationPlan(driftReport drift.DriftReport, steps []ReActStep) (*RemediationPlan, error) {
	// Get the final step
	if len(steps) == 0 {
		return nil, fmt.Errorf("no ReAct steps available")
	}
	
	finalStep := steps[len(steps)-1]
	
	// Parse the remediation plan from the final action
	// This is a simple implementation - in practice, you might have more structured output
	lines := strings.Split(finalStep.Action, "\n")
	
	var description string
	var actions []string
	var risks []string
	var justification string
	var approvalNeeded bool
	
	currentSection := ""
	
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		
		// Skip empty lines
		if trimmedLine == "" {
			continue
		}
		
		// Check if this is a section header
		if strings.HasSuffix(trimmedLine, ":") {
			sectionName := strings.ToLower(strings.TrimSuffix(trimmedLine, ":"))
			
			switch {
			case strings.Contains(sectionName, "description"):
				currentSection = "description"
			case strings.Contains(sectionName, "action"):
				currentSection = "actions"
			case strings.Contains(sectionName, "risk"):
				currentSection = "risks"
			case strings.Contains(sectionName, "justification"):
				currentSection = "justification"
			case strings.Contains(sectionName, "approval"):
				currentSection = "approval"
			default:
				currentSection = ""
			}
			
			continue
		}
		
		// Process content based on current section
		switch currentSection {
		case "description":
			if description == "" {
				description = trimmedLine
			} else {
				description += " " + trimmedLine
			}
		case "actions":
			if strings.HasPrefix(trimmedLine, "-") || strings.HasPrefix(trimmedLine, "*") {
				action := strings.TrimPrefix(strings.TrimPrefix(trimmedLine, "-"), "*")
				actions = append(actions, strings.TrimSpace(action))
			} else if len(actions) > 0 {
				// Append to the last action
				actions[len(actions)-1] += " " + trimmedLine
			} else {
				actions = append(actions, trimmedLine)
			}
		case "risks":
			if strings.HasPrefix(trimmedLine, "-") || strings.HasPrefix(trimmedLine, "*") {
				risk := strings.TrimPrefix(strings.TrimPrefix(trimmedLine, "-"), "*")
				risks = append(risks, strings.TrimSpace(risk))
			} else if len(risks) > 0 {
				// Append to the last risk
				risks[len(risks)-1] += " " + trimmedLine
			} else {
				risks = append(risks, trimmedLine)
			}
		case "justification":
			if justification == "" {
				justification = trimmedLine
			} else {
				justification += " " + trimmedLine
			}
		case "approval":
			approvalNeeded = strings.Contains(strings.ToLower(trimmedLine), "yes") ||
				strings.Contains(strings.ToLower(trimmedLine), "required") ||
				strings.Contains(strings.ToLower(trimmedLine), "needed")
		}
	}
	
	// If no structured plan was found, use the entire action
	if description == "" {
		description = finalStep.Action
	}
	
	// Create the remediation plan
	plan := &RemediationPlan{
		DriftID:        driftReport.ID,
		Description:    description,
		Actions:        actions,
		Risks:          risks,
		Justification:  justification,
		ApprovalNeeded: approvalNeeded,
		CreatedAt:      time.Now(),
	}
	
	return plan, nil
}

// prettyFormatJSON formats a value as a pretty-printed JSON string
func prettyFormatJSON(v interface{}) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting JSON: %s", err)
	}
	return string(data)
}

// buildReActPrompt builds the initial prompt for the ReAct process
func buildReActPrompt(context string) string {
	return fmt.Sprintf(`You are an expert infrastructure engineer responsible for analyzing and remediating infrastructure drift. 
You use the ReAct (Reasoning & Acting) framework to think step by step and make decisions.

CONTEXT:
%s

INSTRUCTIONS:
1. Analyze the drift report provided in the context.
2. Think step by step about what caused this drift and what actions should be taken.
3. You can take actions to gather more information if needed.
4. Finally, create a remediation plan.

AVAILABLE ACTIONS:
- get_resource_details: Get detailed information about the resource
- get_drift_details: Get detailed information about the drift
- assess_impact: Assess the impact of this drift
- FINISH with a remediation plan

FORMAT YOUR RESPONSE LIKE THIS:
Thought: I need to understand the nature of the drift...
Action: [One of the available actions]

After receiving the result of your action, continue with:
Thought: Now I understand that...
Action: [Next action]

When you're ready to finish, use:
Thought: I've gathered enough information to create a remediation plan.
Action: FINISH
Remediation Plan:
Description: [Brief description of the drift and its impact]
Actions:
- [Action 1]
- [Action 2]
Risks:
- [Risk 1]
- [Risk 2]
Justification: [Why this remediation approach is recommended]
Approval Needed: [Yes/No]

BEGIN NOW:
Thought:`, context)
}