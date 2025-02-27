package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/internal/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/detector"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/workflow"
	"github.com/spf13/cobra"
)

var (
	configPath string
	format     string
	driftID    string
	resourceID string
	provider   string
	region     string
	tags       []string
)

func main() {
	// Root command
	rootCmd := &cobra.Command{
		Use:   "idc",
		Short: "Infrastructure Drift Controller CLI",
		Long:  `Command line interface for managing infrastructure drift detection and reconciliation`,
	}

	// Add global flags
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to configuration file")
	rootCmd.PersistentFlags().StringVar(&format, "format", "text", "Output format: text, json, yaml")

	// Add commands
	rootCmd.AddCommand(getDetectCmd())
	rootCmd.AddCommand(getResourcesCmd())
	rootCmd.AddCommand(getDriftsCmd())
	rootCmd.AddCommand(getWorkflowsCmd())
	rootCmd.AddCommand(getReconcileCmd())

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// loadConfig loads the application configuration
func loadConfig() (*config.Config, error) {
	// Override config path if specified
	if configPath != "" {
		os.Setenv("CONFIG_PATH", configPath)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %v", err)
	}

	return cfg, nil
}

// getDetectCmd returns the detect command
func getDetectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect infrastructure drift",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			// Initialize database connection
			db, err := database.New(cfg.Database)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %v", err)
			}
			defer db.Close()

			// Initialize drift detector
			driftDetector := detector.New(cfg.Detection, db)

			// Create filter from flags
			filter := models.ResourceFilter{
				Provider: models.ProviderType(provider),
				Region:   region,
			}

			// Parse tags
			if len(tags) > 0 {
				filter.Tags = make(models.Tags)
				for _, tag := range tags {
					// Parse "key=value" format
					var key, value string
					fmt.Sscanf(tag, "%s=%s", &key, &value)
					if key != "" {
						filter.Tags[key] = value
					}
				}
			}

			// Run detection
			fmt.Println("Starting drift detection...")
			if err := driftDetector.RunManualDetection(context.Background(), filter); err != nil {
				return fmt.Errorf("drift detection failed: %v", err)
			}

			fmt.Println("Drift detection completed successfully")
			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVar(&provider, "provider", "", "Provider to filter by (aws, azure, gcp)")
	cmd.Flags().StringVar(&region, "region", "", "Region to filter by")
	cmd.Flags().StringArrayVar(&tags, "tag", nil, "Tags to filter by (format: key=value)")

	return cmd
}

// getResourcesCmd returns the resources command
func getResourcesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "resources",
		Short: "Manage infrastructure resources",
	}

	// Add subcommands
	cmd.AddCommand(getListResourcesCmd())
	cmd.AddCommand(getGetResourceCmd())

	return cmd
}

// getListResourcesCmd returns the list resources command
func getListResourcesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List infrastructure resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			// Initialize database connection
			db, err := database.New(cfg.Database)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %v", err)
			}
			defer db.Close()

			// Create filter from flags
			filter := models.ResourceFilter{
				Provider: models.ProviderType(provider),
				Region:   region,
			}

			// Parse tags
			if len(tags) > 0 {
				filter.Tags = make(models.Tags)
				for _, tag := range tags {
					// Parse "key=value" format
					var key, value string
					fmt.Sscanf(tag, "%s=%s", &key, &value)
					if key != "" {
						filter.Tags[key] = value
					}
				}
			}

			// Get resources
			resources, err := db.GetResources(filter)
			if err != nil {
				return fmt.Errorf("failed to get resources: %v", err)
			}

			// Output results
			if format == "json" {
				jsonData, err := json.MarshalIndent(resources, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %v", err)
				}
				fmt.Println(string(jsonData))
			} else {
				fmt.Printf("Found %d resources:\n", len(resources))
				for i, resource := range resources {
					fmt.Printf("%d. %s (%s) - Type: %s, Provider: %s, Region: %s\n",
						i+1, resource.Name, resource.ID, resource.Type, resource.Provider, resource.Region)
				}
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVar(&provider, "provider", "", "Provider to filter by (aws, azure, gcp)")
	cmd.Flags().StringVar(&region, "region", "", "Region to filter by")
	cmd.Flags().StringArrayVar(&tags, "tag", nil, "Tags to filter by (format: key=value)")

	return cmd
}

// getGetResourceCmd returns the get resource command
func getGetResourceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [id]",
		Short: "Get a specific resource",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			// Initialize database connection
			db, err := database.New(cfg.Database)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %v", err)
			}
			defer db.Close()

			// Get resource ID from args
			resourceID := args[0]

			// Get resource
			resource, err := db.GetResource(resourceID)
			if err != nil {
				return fmt.Errorf("failed to get resource: %v", err)
			}

			// Output result
			if format == "json" {
				jsonData, err := json.MarshalIndent(resource, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %v", err)
				}
				fmt.Println(string(jsonData))
			} else {
				fmt.Printf("Resource: %s (%s)\n", resource.Name, resource.ID)
				fmt.Printf("  Type: %s\n", resource.Type)
				fmt.Printf("  Provider: %s\n", resource.Provider)
				fmt.Printf("  Region: %s\n", resource.Region)
				fmt.Printf("  IaC Type: %s\n", resource.IaCType)
				fmt.Printf("  Created: %s\n", resource.CreatedAt.Format(time.RFC3339))
				fmt.Printf("  Updated: %s\n", resource.UpdatedAt.Format(time.RFC3339))
				
				if len(resource.Tags) > 0 {
					fmt.Println("  Tags:")
					for k, v := range resource.Tags {
						fmt.Printf("    %s: %s\n", k, v)
					}
				}
			}

			return nil
		},
	}

	return cmd
}

// getDriftsCmd returns the drifts command
func getDriftsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "drifts",
		Short: "Manage infrastructure drifts",
	}

	// Add subcommands
	cmd.AddCommand(getListDriftsCmd())
	cmd.AddCommand(getGetDriftCmd())

	return cmd
}

// getListDriftsCmd returns the list drifts command
func getListDriftsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List infrastructure drifts",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			// Initialize database connection
			db, err := database.New(cfg.Database)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %v", err)
			}
			defer db.Close()

			// Create filter from flags
			filter := models.DriftFilter{
				ResourceID: resourceID,
				Provider:   models.ProviderType(provider),
				Region:     region,
			}

			// Get drifts
			drifts, err := db.GetDrifts(filter)
			if err != nil {
				return fmt.Errorf("failed to get drifts: %v", err)
			}

			// Output results
			if format == "json" {
				jsonData, err := json.MarshalIndent(drifts, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %v", err)
				}
				fmt.Println(string(jsonData))
			} else {
				fmt.Printf("Found %d drifts:\n", len(drifts))
				for i, drift := range drifts {
					fmt.Printf("%d. Drift ID: %s\n", i+1, drift.ID)
					fmt.Printf("   Resource: %s\n", drift.ResourceID)
					fmt.Printf("   Status: %s\n", drift.Status)
					fmt.Printf("   Severity: %s\n", drift.Severity)
					fmt.Printf("   Detected: %s\n", drift.DetectedAt.Format(time.RFC3339))
					fmt.Printf("   Changes: %d\n", len(drift.Changes))
					
					if drift.ResolvedAt != nil {
						fmt.Printf("   Resolved: %s\n", drift.ResolvedAt.Format(time.RFC3339))
					}
					
					fmt.Println()
				}
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVar(&resourceID, "resource", "", "Resource ID to filter by")
	cmd.Flags().StringVar(&provider, "provider", "", "Provider to filter by (aws, azure, gcp)")
	cmd.Flags().StringVar(&region, "region", "", "Region to filter by")

	return cmd
}

// getGetDriftCmd returns the get drift command
func getGetDriftCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [id]",
		Short: "Get a specific drift",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			// Initialize database connection
			db, err := database.New(cfg.Database)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %v", err)
			}
			defer db.Close()

			// Get drift ID from args
			driftID := args[0]

			// Get drift
			drift, err := db.GetDrift(driftID)
			if err != nil {
				return fmt.Errorf("failed to get drift: %v", err)
			}

			// Output result
			if format == "json" {
				jsonData, err := json.MarshalIndent(drift, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %v", err)
				}
				fmt.Println(string(jsonData))
			} else {
				fmt.Printf("Drift: %s\n", drift.ID)
				fmt.Printf("  Resource: %s\n", drift.ResourceID)
				fmt.Printf("  Status: %s\n", drift.Status)
				fmt.Printf("  Severity: %s\n", drift.Severity)
				fmt.Printf("  Detected: %s\n", drift.DetectedAt.Format(time.RFC3339))
				
				if drift.ResolvedAt != nil {
					fmt.Printf("  Resolved: %s\n", drift.ResolvedAt.Format(time.RFC3339))
					fmt.Printf("  Resolution Notes: %s\n", drift.ResolutionNotes)
				}
				
				if drift.WorkflowID != "" {
					fmt.Printf("  Workflow: %s\n", drift.WorkflowID)
				}
				
				fmt.Printf("  Changes: %d\n", len(drift.Changes))
				for i, change := range drift.Changes {
					fmt.Printf("    %d. Path: %s\n", i+1, change.PropertyPath)
					fmt.Printf("       Type: %s\n", change.ChangeType)
					fmt.Printf("       Expected: %v\n", change.ExpectedValue)
					fmt.Printf("       Actual: %v\n", change.ActualValue)
				}
			}

			return nil
		},
	}

	return cmd
}

// getWorkflowsCmd returns the workflows command
func getWorkflowsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workflows",
		Short: "Manage reconciliation workflows",
	}

	// Add subcommands
	cmd.AddCommand(getListWorkflowsCmd())
	cmd.AddCommand(getGetWorkflowCmd())

	return cmd
}

// getListWorkflowsCmd returns the list workflows command
func getListWorkflowsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List reconciliation workflows",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			// Initialize database connection
			db, err := database.New(cfg.Database)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %v", err)
			}
			defer db.Close()

			// Create filter from flags
			filter := models.WorkflowFilter{
				DriftID:    driftID,
				ResourceID: resourceID,
			}

			// Get workflows
			workflows, err := db.GetWorkflows(filter)
			if err != nil {
				return fmt.Errorf("failed to get workflows: %v", err)
			}

			// Output results
			if format == "json" {
				jsonData, err := json.MarshalIndent(workflows, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %v", err)
				}
				fmt.Println(string(jsonData))
			} else {
				fmt.Printf("Found %d workflows:\n", len(workflows))
				for i, workflow := range workflows {
					fmt.Printf("%d. Workflow: %s\n", i+1, workflow.Name)
					fmt.Printf("   ID: %s\n", workflow.ID)
					fmt.Printf("   Status: %s\n", workflow.Status)
					fmt.Printf("   Drift: %s\n", workflow.DriftID)
					fmt.Printf("   Resource: %s\n", workflow.ResourceID)
					fmt.Printf("   Created: %s\n", workflow.CreatedAt.Format(time.RFC3339))
					
					if workflow.StartedAt != nil {
						fmt.Printf("   Started: %s\n", workflow.StartedAt.Format(time.RFC3339))
					}
					
					if workflow.CompletedAt != nil {
						fmt.Printf("   Completed: %s\n", workflow.CompletedAt.Format(time.RFC3339))
					}
					
					fmt.Printf("   Actions: %d\n", len(workflow.Actions))
					fmt.Println()
				}
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVar(&driftID, "drift", "", "Drift ID to filter by")
	cmd.Flags().StringVar(&resourceID, "resource", "", "Resource ID to filter by")

	return cmd
}

// getGetWorkflowCmd returns the get workflow command
func getGetWorkflowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [id]",
		Short: "Get a specific workflow",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			// Initialize database connection
			db, err := database.New(cfg.Database)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %v", err)
			}
			defer db.Close()

			// Get workflow ID from args
			workflowID := args[0]

			// Get workflow
			workflow, err := db.GetWorkflow(workflowID)
			if err != nil {
				return fmt.Errorf("failed to get workflow: %v", err)
			}

			// Output result
			if format == "json" {
				jsonData, err := json.MarshalIndent(workflow, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %v", err)
				}
				fmt.Println(string(jsonData))
			} else {
				fmt.Printf("Workflow: %s\n", workflow.Name)
				fmt.Printf("  ID: %s\n", workflow.ID)
				fmt.Printf("  Description: %s\n", workflow.Description)
				fmt.Printf("  Status: %s\n", workflow.Status)
				fmt.Printf("  Drift: %s\n", workflow.DriftID)
				fmt.Printf("  Resource: %s\n", workflow.ResourceID)
				fmt.Printf("  Created: %s\n", workflow.CreatedAt.Format(time.RFC3339))
				
				if workflow.StartedAt != nil {
					fmt.Printf("  Started: %s\n", workflow.StartedAt.Format(time.RFC3339))
				}
				
				if workflow.CompletedAt != nil {
					fmt.Printf("  Completed: %s\n", workflow.CompletedAt.Format(time.RFC3339))
				}
				
				if workflow.ErrorMessage != "" {
					fmt.Printf("  Error: %s\n", workflow.ErrorMessage)
				}
				
				fmt.Printf("  Actions: %d\n", len(workflow.Actions))
				for i, action := range workflow.Actions {
					fmt.Printf("    %d. %s (%s)\n", i+1, action.Name, action.Type)
					fmt.Printf("       Status: %s\n", action.Status)
					
					if action.StartedAt != nil {
						fmt.Printf("       Started: %s\n", action.StartedAt.Format(time.RFC3339))
					}
					
					if action.CompletedAt != nil {
						fmt.Printf("       Completed: %s\n", action.CompletedAt.Format(time.RFC3339))
					}
					
					if action.ErrorMessage != "" {
						fmt.Printf("       Error: %s\n", action.ErrorMessage)
					}
				}
			}

			return nil
		},
	}

	return cmd
}

// getReconcileCmd returns the reconcile command
func getReconcileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reconcile [drift-id]",
		Short: "Reconcile a detected drift",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			// Initialize database connection
			db, err := database.New(cfg.Database)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %v", err)
			}
			defer db.Close()

			// Get drift ID from args
			driftID := args[0]

			// Get drift
			drift, err := db.GetDrift(driftID)
			if err != nil {
				return fmt.Errorf("failed to get drift: %v", err)
			}

			// Check if drift is already resolved
			if drift.Status == models.DriftStatusResolved {
				return fmt.Errorf("drift is already resolved")
			}

			// Get resource
			resource, err := db.GetResource(drift.ResourceID)
			if err != nil {
				return fmt.Errorf("failed to get resource: %v", err)
			}

			// Create reconciler
			reconciler := workflow.NewReconciler(db)

			// Create reconciliation plan
			fmt.Println("Creating reconciliation plan...")
			plan, err := reconciler.CreateRemediationPlan(drift, resource)
			if err != nil {
				return fmt.Errorf("failed to create remediation plan: %v", err)
			}

			// Output plan
			if format == "json" {
				jsonData, err := json.MarshalIndent(plan, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %v", err)
				}
				fmt.Println(string(jsonData))
			} else {
				fmt.Println("Reconciliation Plan:")
				
				if hasChanges, ok := plan["has_changes"].(bool); ok {
					fmt.Printf("  Has Changes: %v\n", hasChanges)
				}
				
				if output, ok := plan["plan_output"].(string); ok {
					fmt.Println("  Plan Output:")
					fmt.Println(output)
				}
			}

			// Ask for confirmation
			fmt.Print("Do you want to proceed with reconciliation? (y/n): ")
			var confirm string
			fmt.Scanln(&confirm)

			if confirm != "y" && confirm != "Y" {
				fmt.Println("Reconciliation aborted")
				return nil
			}

			// Perform reconciliation
			fmt.Println("Reconciling drift...")
			if err := reconciler.AutoRemediate(drift, resource); err != nil {
				return fmt.Errorf("reconciliation failed: %v", err)
			}

			// Update drift status
			drift.Status = models.DriftStatusResolved
			now := time.Now()
			drift.ResolvedAt = &now
			drift.ResolutionNotes = "Resolved via CLI reconciliation"

			if err := db.UpdateDrift(drift); err != nil {
				return fmt.Errorf("failed to update drift status: %v", err)
			}

			fmt.Println("Reconciliation completed successfully")
			return nil
		},
	}

	return cmd
}