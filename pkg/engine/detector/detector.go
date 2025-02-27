package detector

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jdaws97/infrastructure-drift-controller/internal/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/collector"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/parser"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/workflow"
)

// Detector is responsible for detecting drift between expected and actual states
type Detector struct {
	config        config.DetectionConfig
	db            *database.DB
	collector     *collector.StateCollector
	parser        *parser.UniversalParser
	workflowEngine *workflow.Engine
	
	// For managing the detection job
	jobMutex      sync.Mutex
	isRunning     bool
	stop          chan struct{}
	driftHistory  map[string]time.Time // Track when resources were last checked
}

// New creates a new drift detector
func New(config config.DetectionConfig, db *database.DB) *Detector {
	return &Detector{
		config:       config,
		db:           db,
		collector:    collector.New(db),
		parser:       parser.New(db),
		stop:         make(chan struct{}),
		driftHistory: make(map[string]time.Time),
	}
}

// SetWorkflowEngine sets the workflow engine for the detector
func (d *Detector) SetWorkflowEngine(engine *workflow.Engine) {
	d.workflowEngine = engine
}

// Start begins the periodic drift detection process
func (d *Detector) Start(ctx context.Context) {
	d.jobMutex.Lock()
	if d.isRunning {
		d.jobMutex.Unlock()
		return
	}
	d.isRunning = true
	d.jobMutex.Unlock()

	log.Println("Starting drift detection service")
	ticker := time.NewTicker(d.config.Interval)
	defer ticker.Stop()

	// Run an initial detection
	d.runDetection(ctx)

	for {
		select {
		case <-ticker.C:
			d.runDetection(ctx)
		case <-d.stop:
			log.Println("Stopping drift detection service")
			return
		case <-ctx.Done():
			log.Println("Context canceled, stopping drift detection service")
			return
		}
	}
}

// Stop stops the drift detection process
func (d *Detector) Stop() {
	d.jobMutex.Lock()
	defer d.jobMutex.Unlock()

	if !d.isRunning {
		return
	}

	d.isRunning = false
	close(d.stop)
}

// RunManualDetection runs a drift detection process on demand
func (d *Detector) RunManualDetection(ctx context.Context, filter models.ResourceFilter) error {
	log.Printf("Starting manual drift detection with filter: %+v", filter)
	return d.detectDrift(ctx, filter)
}

// runDetection runs a single drift detection cycle
func (d *Detector) runDetection(ctx context.Context) {
	log.Println("Starting scheduled drift detection")
	
	// Default to checking all resources
	filter := models.ResourceFilter{}
	
	if err := d.detectDrift(ctx, filter); err != nil {
		log.Printf("Error during drift detection: %v", err)
	}
	
	log.Println("Completed drift detection cycle")
}

// detectDrift is the main drift detection logic
func (d *Detector) detectDrift(ctx context.Context, filter models.ResourceFilter) error {
	// Get all resources matching the filter
	resources, err := d.db.GetResources(filter)
	if err != nil {
		return fmt.Errorf("failed to get resources: %w", err)
	}

	log.Printf("Checking drift for %d resources", len(resources))

	// Use a worker pool to process resources in parallel
	workerCount := d.config.Workers
	if workerCount <= 0 {
		workerCount = 10 // Default
	}

	// Channel for distributing work
	jobs := make(chan *models.Resource, len(resources))
	results := make(chan error, len(resources))

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for resource := range jobs {
				err := d.checkResourceDrift(ctx, resource)
				if err != nil {
					results <- fmt.Errorf("error checking drift for resource %s: %w", resource.ID, err)
				}
			}
		}(i)
	}

	// Send resources to workers
	// Prioritize resources that haven't been checked recently
	now := time.Now()
	prioritizedResources := make([]*models.Resource, 0, len(resources))
	
	// Add resources to the list
	for _, resource := range resources {
		// Check if we should force detection for this resource
		lastCheck, exists := d.driftHistory[resource.ID]
		
		// If we've never checked this resource or the jitter time has passed
		if !exists || now.Sub(lastCheck) > d.config.Interval {
			prioritizedResources = append(prioritizedResources, resource)
		}
	}
	
	// If we're not checking all resources due to timing, log it
	if len(prioritizedResources) < len(resources) {
		log.Printf("Only checking %d of %d resources based on timing", len(prioritizedResources), len(resources))
	}
	
	// Send prioritized resources to workers
	for _, resource := range prioritizedResources {
		jobs <- resource
		d.driftHistory[resource.ID] = now // Update last check time
	}
	
	close(jobs)

	// Wait for all workers to complete
	wg.Wait()
	close(results)

	// Collect errors
	var errs []error
	for err := range results {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("encountered %d errors during drift detection", len(errs))
	}

	return nil
}

// checkResourceDrift checks for drift in a single resource
func (d *Detector) checkResourceDrift(ctx context.Context, resource *models.Resource) error {
	log.Printf("Checking drift for resource %s (%s)", resource.Name, resource.ID)
	
	// Get the expected state from IaC source
	expectedState, err := d.db.GetLatestExpectedState(resource.ID)
	if err != nil {
		log.Printf("Failed to get expected state for %s, will attempt to collect: %v", resource.ID, err)
		
		// Try to refresh expected state from IaC source if available
		iacSourcePath, iacErr := d.db.GetResourceMetadata(resource.ID, fmt.Sprintf("%s_file_path", resource.IaCType))
		if iacErr == nil && iacSourcePath != "" {
			log.Printf("Attempting to refresh expected state from %s", iacSourcePath)
			// Parse the IaC file to update the expected state
			if parseErr := d.parser.ParseIaCFile(iacSourcePath, resource.IaCType); parseErr != nil {
				log.Printf("Failed to parse IaC file to update expected state: %v", parseErr)
			} else {
				// Retry getting the expected state
				expectedState, err = d.db.GetLatestExpectedState(resource.ID)
			}
		}
		
		// If we still can't get it, return error
		if err != nil {
			return fmt.Errorf("failed to get expected state: %w", err)
		}
	}

	// Get the actual state from cloud provider
	actualState, err := d.collector.CollectState(ctx, resource)
	if err != nil {
		return fmt.Errorf("failed to collect actual state: %w", err)
	}

	// Compare states to detect drift
	changes, err := compareStates(expectedState, actualState)
	if err != nil {
		return fmt.Errorf("failed to compare states: %w", err)
	}

	// If there are changes, record the drift
	if len(changes) > 0 {
		drift := &models.Drift{
			ID:             uuid.New().String(),
			ResourceID:     resource.ID,
			Resource:       resource,
			DetectedAt:     time.Now(),
			Status:         models.DriftStatusDetected,
			Changes:        changes,
			ExpectedStateID: expectedState.StateVersion,
			ActualStateID:  actualState.StateVersion,
		}

		// Calculate severity
		drift.Severity = models.CalculateSeverity(resource, changes)

		// Save the drift to the database
		if err := d.db.CreateDrift(drift); err != nil {
			return fmt.Errorf("failed to create drift record: %w", err)
		}

		log.Printf("Detected drift for resource %s (%s), severity: %s, changes: %d", 
			resource.Name, resource.ID, drift.Severity, len(changes))

		// If workflow engine is available, create a workflow
		if d.workflowEngine != nil {
			if err := d.workflowEngine.CreateWorkflowForDrift(drift); err != nil {
				log.Printf("Error creating workflow for drift %s: %v", drift.ID, err)
				// Continue execution - workflow creation is not critical
			} else {
				log.Printf("Created workflow for drift %s", drift.ID)
			}
		}
	} else {
		log.Printf("No drift detected for resource %s (%s)", resource.Name, resource.ID)
	}

	return nil
}

// compareStates compares expected and actual states to detect changes
func compareStates(expected *models.ResourceState, actual *models.ResourceState) ([]models.PropertyChange, error) {
	var changes []models.PropertyChange

	// This is a recursive comparison to handle nested structures
	compareProperties(expected.Properties, actual.Properties, "", &changes)
	
	return changes, nil
}

// compareProperties compares properties recursively
func compareProperties(expected, actual map[string]interface{}, prefix string, changes *[]models.PropertyChange) {
	// Check all expected properties
	for key, expectedValue := range expected {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		
		// Check if property exists in actual state
		actualValue, exists := actual[key]
		
		if !exists {
			// Property was removed
			*changes = append(*changes, models.PropertyChange{
				PropertyPath:  path,
				ExpectedValue: expectedValue,
				ActualValue:   nil,
				ChangeType:    models.ChangeTypeRemoved,
			})
			continue
		}
		
		// Handle different value types
		switch expectedTyped := expectedValue.(type) {
		case map[string]interface{}:
			// For nested objects, recurse
			if actualTyped, ok := actualValue.(map[string]interface{}); ok {
				compareProperties(expectedTyped, actualTyped, path, changes)
			} else {
				// Types don't match (expected object, got something else)
				*changes = append(*changes, models.PropertyChange{
					PropertyPath:  path,
					ExpectedValue: expectedValue,
					ActualValue:   actualValue,
					ChangeType:    models.ChangeTypeModified,
				})
			}
			
		case []interface{}:
			// For arrays, compare elements
			if actualTyped, ok := actualValue.([]interface{}); ok {
				compareArrays(expectedTyped, actualTyped, path, changes)
			} else {
				// Types don't match (expected array, got something else)
				*changes = append(*changes, models.PropertyChange{
					PropertyPath:  path,
					ExpectedValue: expectedValue,
					ActualValue:   actualValue,
					ChangeType:    models.ChangeTypeModified,
				})
			}
			
		default:
			// For primitive values, compare directly
			if !areValuesEqual(expectedValue, actualValue) {
				*changes = append(*changes, models.PropertyChange{
					PropertyPath:  path,
					ExpectedValue: expectedValue,
					ActualValue:   actualValue,
					ChangeType:    models.ChangeTypeModified,
				})
			}
		}
	}
	
	// Check for added properties
	for key, actualValue := range actual {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		
		if _, exists := expected[key]; !exists {
			*changes = append(*changes, models.PropertyChange{
				PropertyPath:  path,
				ExpectedValue: nil,
				ActualValue:   actualValue,
				ChangeType:    models.ChangeTypeAdded,
			})
		}
	}
}

// compareArrays compares array elements
func compareArrays(expected, actual []interface{}, path string, changes *[]models.PropertyChange) {
	// If lengths differ, that's a change
	if len(expected) != len(actual) {
		*changes = append(*changes, models.PropertyChange{
			PropertyPath:  path + ".length",
			ExpectedValue: len(expected),
			ActualValue:   len(actual),
			ChangeType:    models.ChangeTypeModified,
		})
	}
	
	// Compare the elements we can
	minLen := len(expected)
	if len(actual) < minLen {
		minLen = len(actual)
	}
	
	// For each element, compare
	for i := 0; i < minLen; i++ {
		itemPath := fmt.Sprintf("%s[%d]", path, i)
		
		// Handle different value types
		switch expectedTyped := expected[i].(type) {
		case map[string]interface{}:
			// For nested objects, recurse
			if actualTyped, ok := actual[i].(map[string]interface{}); ok {
				compareProperties(expectedTyped, actualTyped, itemPath, changes)
			} else {
				// Types don't match
				*changes = append(*changes, models.PropertyChange{
					PropertyPath:  itemPath,
					ExpectedValue: expected[i],
					ActualValue:   actual[i],
					ChangeType:    models.ChangeTypeModified,
				})
			}
			
		case []interface{}:
			// For nested arrays, recurse
			if actualTyped, ok := actual[i].([]interface{}); ok {
				compareArrays(expectedTyped, actualTyped, itemPath, changes)
			} else {
				// Types don't match
				*changes = append(*changes, models.PropertyChange{
					PropertyPath:  itemPath,
					ExpectedValue: expected[i],
					ActualValue:   actual[i],
					ChangeType:    models.ChangeTypeModified,
				})
			}
			
		default:
			// For primitive values, compare directly
			if !areValuesEqual(expected[i], actual[i]) {
				*changes = append(*changes, models.PropertyChange{
					PropertyPath:  itemPath,
					ExpectedValue: expected[i],
					ActualValue:   actual[i],
					ChangeType:    models.ChangeTypeModified,
				})
			}
		}
	}
	
	// Items in expected but not in actual
	for i := minLen; i < len(expected); i++ {
		*changes = append(*changes, models.PropertyChange{
			PropertyPath:  fmt.Sprintf("%s[%d]", path, i),
			ExpectedValue: expected[i],
			ActualValue:   nil,
			ChangeType:    models.ChangeTypeRemoved,
		})
	}
	
	// Items in actual but not in expected
	for i := minLen; i < len(actual); i++ {
		*changes = append(*changes, models.PropertyChange{
			PropertyPath:  fmt.Sprintf("%s[%d]", path, i),
			ExpectedValue: nil,
			ActualValue:   actual[i],
			ChangeType:    models.ChangeTypeAdded,
		})
	}
}

// areValuesEqual compares two property values for equality
func areValuesEqual(expected, actual interface{}) bool {
	// Handle nil values
	if expected == nil && actual == nil {
		return true
	}
	
	if expected == nil || actual == nil {
		return false
	}
	
	// Special handling for types that don't compare well with ==
	switch e := expected.(type) {
	case float64:
		// For floating point, use approximate comparison
		if a, ok := actual.(float64); ok {
			diff := e - a
			if diff < 0 {
				diff = -diff
			}
			return diff < 0.000001 // Small epsilon for float comparison
		}
		
	case string:
		// For strings, do exact comparison
		if a, ok := actual.(string); ok {
			return e == a
		}
		
	case bool:
		// For booleans, do exact comparison
		if a, ok := actual.(bool); ok {
			return e == a
		}
		
	case int:
		// For integers, handle potential type conversion from JSON
		if a, ok := actual.(int); ok {
			return e == a
		}
		// JSON numbers are often deserialized as float64
		if a, ok := actual.(float64); ok {
			return float64(e) == a
		}
		
	case int64:
		if a, ok := actual.(int64); ok {
			return e == a
		}
		if a, ok := actual.(float64); ok {
			return float64(e) == a
		}
		
	case []interface{}:
		// For arrays, check if actual is also an array
		a, ok := actual.([]interface{})
		if !ok || len(e) != len(a) {
			return false
		}
		
		// Compare each element
		for i := range e {
			if !areValuesEqual(e[i], a[i]) {
				return false
			}
		}
		return true
		
	case map[string]interface{}:
		// For objects, check if actual is also an object
		a, ok := actual.(map[string]interface{})
		if !ok || len(e) != len(a) {
			return false
		}
		
		// Compare each key-value pair
		for k, v := range e {
			av, exists := a[k]
			if !exists || !areValuesEqual(v, av) {
				return false
			}
		}
		return true
	}
	
	// For other types, use basic equality
	return fmt.Sprintf("%v", expected) == fmt.Sprintf("%v", actual)
}