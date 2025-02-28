package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"text/template"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/internal/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	_ "github.com/lib/pq"
)

// DB handles database operations
type DB struct {
	conn *sql.DB
}

// New creates a new database connection
func New(cfg config.DatabaseConfig) (*DB, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode)

	conn, err := sql.Open(cfg.Driver, connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test connection
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Set connection parameters
	conn.SetMaxIdleConns(10)
	conn.SetMaxOpenConns(50)
	conn.SetConnMaxLifetime(time.Hour)

	return &DB{conn: conn}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// GetResource retrieves a resource by ID
func (db *DB) GetResource(id string) (*models.Resource, error) {
	query := `SELECT id, name, type, provider, iac_type, region, account, project, 
              properties, tags, created_at, updated_at 
              FROM resources WHERE id = $1`

	var resource models.Resource
	var propertiesJSON, tagsJSON []byte

	err := db.conn.QueryRow(query, id).Scan(
		&resource.ID,
		&resource.Name,
		&resource.Type,
		&resource.Provider,
		&resource.IaCType,
		&resource.Region,
		&resource.Account,
		&resource.Project,
		&propertiesJSON,
		&tagsJSON,
		&resource.CreatedAt,
		&resource.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("resource not found: %s", id)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Parse JSON fields
	if err := json.Unmarshal(propertiesJSON, &resource.Properties); err != nil {
		return nil, fmt.Errorf("failed to parse properties: %w", err)
	}

	if err := json.Unmarshal(tagsJSON, &resource.Tags); err != nil {
		return nil, fmt.Errorf("failed to parse tags: %w", err)
	}

	return &resource, nil
}

// CreateResource creates a new resource
func (db *DB) CreateResource(resource *models.Resource) error {
	query := `INSERT INTO resources 
              (id, name, type, provider, iac_type, region, account, project, properties, tags, created_at, updated_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	propertiesJSON, err := json.Marshal(resource.Properties)
	if err != nil {
		return fmt.Errorf("failed to marshal properties: %w", err)
	}

	tagsJSON, err := json.Marshal(resource.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	_, err = db.conn.Exec(query,
		resource.ID,
		resource.Name,
		resource.Type,
		resource.Provider,
		resource.IaCType,
		resource.Region,
		resource.Account,
		resource.Project,
		propertiesJSON,
		tagsJSON,
		resource.CreatedAt,
		resource.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// UpdateResource updates an existing resource
func (db *DB) UpdateResource(resource *models.Resource) error {
	query := `UPDATE resources 
              SET name = $2, type = $3, provider = $4, iac_type = $5, 
                  region = $6, account = $7, project = $8, properties = $9, 
                  tags = $10, updated_at = $11
              WHERE id = $1`

	propertiesJSON, err := json.Marshal(resource.Properties)
	if err != nil {
		return fmt.Errorf("failed to marshal properties: %w", err)
	}

	tagsJSON, err := json.Marshal(resource.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	result, err := db.conn.Exec(query,
		resource.ID,
		resource.Name,
		resource.Type,
		resource.Provider,
		resource.IaCType,
		resource.Region,
		resource.Account,
		resource.Project,
		propertiesJSON,
		tagsJSON,
		resource.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("resource not found: %s", resource.ID)
	}

	return nil
}

// DeleteResource deletes a resource
func (db *DB) DeleteResource(id string) error {
	query := `DELETE FROM resources WHERE id = $1`

	result, err := db.conn.Exec(query, id)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("resource not found: %s", id)
	}

	return nil
}

// GetResources retrieves resources based on a filter
func (db *DB) GetResources(filter models.ResourceFilter) ([]*models.Resource, error) {
	query := `SELECT id, name, type, provider, iac_type, region, account, project, 
              properties, tags, created_at, updated_at 
              FROM resources WHERE 1=1`

	var args []interface{}
	argCounter := 1

	// Add filter conditions
	if filter.Provider != "" {
		query += fmt.Sprintf(" AND provider = $%d", argCounter)
		args = append(args, filter.Provider)
		argCounter++
	}

	if filter.IaCType != "" {
		query += fmt.Sprintf(" AND iac_type = $%d", argCounter)
		args = append(args, filter.IaCType)
		argCounter++
	}

	if filter.Region != "" {
		query += fmt.Sprintf(" AND region = $%d", argCounter)
		args = append(args, filter.Region)
		argCounter++
	}

	if filter.Account != "" {
		query += fmt.Sprintf(" AND account = $%d", argCounter)
		args = append(args, filter.Account)
		argCounter++
	}

	if filter.Project != "" {
		query += fmt.Sprintf(" AND project = $%d", argCounter)
		args = append(args, filter.Project)
		argCounter++
	}

	// Filter by updated_after if specified
	if filter.UpdatedAfter != nil {
		query += fmt.Sprintf(" AND updated_at > $%d", argCounter)
		args = append(args, *filter.UpdatedAfter)
		argCounter++
	}

	// Execute the query
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var resources []*models.Resource

	for rows.Next() {
		var resource models.Resource
		var propertiesJSON, tagsJSON []byte

		err := rows.Scan(
			&resource.ID,
			&resource.Name,
			&resource.Type,
			&resource.Provider,
			&resource.IaCType,
			&resource.Region,
			&resource.Account,
			&resource.Project,
			&propertiesJSON,
			&tagsJSON,
			&resource.CreatedAt,
			&resource.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		// Parse JSON fields
		if err := json.Unmarshal(propertiesJSON, &resource.Properties); err != nil {
			return nil, fmt.Errorf("failed to parse properties: %w", err)
		}

		if err := json.Unmarshal(tagsJSON, &resource.Tags); err != nil {
			return nil, fmt.Errorf("failed to parse tags: %w", err)
		}

		// Apply tag filter if present
		if len(filter.Tags) > 0 {
			match := true
			for k, v := range filter.Tags {
				if resourceV, exists := resource.Tags[k]; !exists || resourceV != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		// Apply resource type filter if present
		if len(filter.Types) > 0 {
			match := false
			for _, t := range filter.Types {
				if resource.Type == t {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		resources = append(resources, &resource)
	}

	return resources, nil
}

// SaveResourceState saves a resource state
func (db *DB) SaveResourceState(state *models.ResourceState) error {
	query := `INSERT INTO resource_states 
              (resource_id, state_type, properties, captured_at, state_version, source)
              VALUES ($1, $2, $3, $4, $5, $6)`

	propertiesJSON, err := json.Marshal(state.Properties)
	if err != nil {
		return fmt.Errorf("failed to marshal properties: %w", err)
	}

	_, err = db.conn.Exec(query,
		state.ResourceID,
		state.StateType,
		propertiesJSON,
		state.CapturedAt,
		state.StateVersion,
		state.Source,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// GetLatestExpectedState retrieves the latest expected state for a resource
func (db *DB) GetLatestExpectedState(resourceID string) (*models.ResourceState, error) {
	query := `SELECT resource_id, state_type, properties, captured_at, state_version, source
              FROM resource_states 
              WHERE resource_id = $1 AND state_type = $2
              ORDER BY captured_at DESC LIMIT 1`

	var state models.ResourceState
	var propertiesJSON []byte

	err := db.conn.QueryRow(query, resourceID, models.StateTypeExpected).Scan(
		&state.ResourceID,
		&state.StateType,
		&propertiesJSON,
		&state.CapturedAt,
		&state.StateVersion,
		&state.Source,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no expected state found for resource: %s", resourceID)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Parse JSON fields
	if err := json.Unmarshal(propertiesJSON, &state.Properties); err != nil {
		return nil, fmt.Errorf("failed to parse properties: %w", err)
	}

	return &state, nil
}

// GetLatestActualState retrieves the latest actual state for a resource
func (db *DB) GetLatestActualState(resourceID string) (*models.ResourceState, error) {
	query := `SELECT resource_id, state_type, properties, captured_at, state_version, source
              FROM resource_states 
              WHERE resource_id = $1 AND state_type = $2
              ORDER BY captured_at DESC LIMIT 1`

	var state models.ResourceState
	var propertiesJSON []byte

	err := db.conn.QueryRow(query, resourceID, models.StateTypeActual).Scan(
		&state.ResourceID,
		&state.StateType,
		&propertiesJSON,
		&state.CapturedAt,
		&state.StateVersion,
		&state.Source,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no actual state found for resource: %s", resourceID)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Parse JSON fields
	if err := json.Unmarshal(propertiesJSON, &state.Properties); err != nil {
		return nil, fmt.Errorf("failed to parse properties: %w", err)
	}

	return &state, nil
}

// CreateDrift creates a new drift record
func (db *DB) CreateDrift(drift *models.Drift) error {
	query := `INSERT INTO drifts 
              (id, resource_id, detected_at, status, severity, changes, 
              expected_state_id, actual_state_id, workflow_id, resolved_at, resolution_notes)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	changesJSON, err := json.Marshal(drift.Changes)
	if err != nil {
		return fmt.Errorf("failed to marshal changes: %w", err)
	}

	_, err = db.conn.Exec(query,
		drift.ID,
		drift.ResourceID,
		drift.DetectedAt,
		drift.Status,
		drift.Severity,
		changesJSON,
		drift.ExpectedStateID,
		drift.ActualStateID,
		drift.WorkflowID,
		drift.ResolvedAt,
		drift.ResolutionNotes,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// GetDrift retrieves a drift by ID
func (db *DB) GetDrift(id string) (*models.Drift, error) {
	query := `SELECT id, resource_id, detected_at, status, severity, changes, 
              expected_state_id, actual_state_id, workflow_id, resolved_at, resolution_notes
              FROM drifts WHERE id = $1`

	var drift models.Drift
	var changesJSON []byte
	var resolvedAt sql.NullTime
	var workflowID, resolutionNotes sql.NullString

	err := db.conn.QueryRow(query, id).Scan(
		&drift.ID,
		&drift.ResourceID,
		&drift.DetectedAt,
		&drift.Status,
		&drift.Severity,
		&changesJSON,
		&drift.ExpectedStateID,
		&drift.ActualStateID,
		&workflowID,
		&resolvedAt,
		&resolutionNotes,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("drift not found: %s", id)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Handle null values
	if workflowID.Valid {
		drift.WorkflowID = workflowID.String
	}
	if resolvedAt.Valid {
		drift.ResolvedAt = &resolvedAt.Time
	}
	if resolutionNotes.Valid {
		drift.ResolutionNotes = resolutionNotes.String
	}

	// Parse JSON fields
	if err := json.Unmarshal(changesJSON, &drift.Changes); err != nil {
		return nil, fmt.Errorf("failed to parse changes: %w", err)
	}

	// Get the associated resource
	resource, err := db.GetResource(drift.ResourceID)
	if err == nil {
		drift.Resource = resource
	}

	return &drift, nil
}

// UpdateDrift updates an existing drift
func (db *DB) UpdateDrift(drift *models.Drift) error {
	query := `UPDATE drifts 
              SET status = $2, workflow_id = $3, resolved_at = $4, resolution_notes = $5
              WHERE id = $1`

	_, err := db.conn.Exec(query,
		drift.ID,
		drift.Status,
		drift.WorkflowID,
		drift.ResolvedAt,
		drift.ResolutionNotes,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// GetDrifts retrieves drifts based on a filter
func (db *DB) GetDrifts(filter models.DriftFilter) ([]*models.Drift, error) {
	query := `SELECT id, resource_id, detected_at, status, severity, changes, 
              expected_state_id, actual_state_id, workflow_id, resolved_at, resolution_notes
              FROM drifts WHERE 1=1`

	var args []interface{}
	argCounter := 1

	// Add filter conditions
	if filter.ResourceID != "" {
		query += fmt.Sprintf(" AND resource_id = $%d", argCounter)
		args = append(args, filter.ResourceID)
		argCounter++
	}

	if filter.Provider != "" || filter.Region != "" || filter.Account != "" || filter.Project != "" || len(filter.ResourceTypes) > 0 {
		// Get resource IDs matching the resource filters
		resourceQuery := `SELECT id FROM resources WHERE 1=1`
		var resourceArgs []interface{}
		resourceArgCounter := 1

		if filter.Provider != "" {
			resourceQuery += fmt.Sprintf(" AND provider = $%d", resourceArgCounter)
			resourceArgs = append(resourceArgs, filter.Provider)
			resourceArgCounter++
		}

		if filter.Region != "" {
			resourceQuery += fmt.Sprintf(" AND region = $%d", resourceArgCounter)
			resourceArgs = append(resourceArgs, filter.Region)
			resourceArgCounter++
		}

		if filter.Account != "" {
			resourceQuery += fmt.Sprintf(" AND account = $%d", resourceArgCounter)
			resourceArgs = append(resourceArgs, filter.Account)
			resourceArgCounter++
		}

		if filter.Project != "" {
			resourceQuery += fmt.Sprintf(" AND project = $%d", resourceArgCounter)
			resourceArgs = append(resourceArgs, filter.Project)
			resourceArgCounter++
		}

		if len(filter.ResourceTypes) > 0 {
			placeholders := make([]string, len(filter.ResourceTypes))
			for i := range filter.ResourceTypes {
				placeholders[i] = fmt.Sprintf("$%d", resourceArgCounter)
				resourceArgs = append(resourceArgs, filter.ResourceTypes[i])
				resourceArgCounter++
			}
			resourceQuery += fmt.Sprintf(" AND type IN (%s)", joinStrings(placeholders, ","))
		}

		resourceRows, err := db.conn.Query(resourceQuery, resourceArgs...)
		if err != nil {
			return nil, fmt.Errorf("database error querying resources: %w", err)
		}
		defer resourceRows.Close()

		var resourceIDs []string
		for resourceRows.Next() {
			var id string
			if err := resourceRows.Scan(&id); err != nil {
				return nil, fmt.Errorf("error scanning resource ID: %w", err)
			}
			resourceIDs = append(resourceIDs, id)
		}

		if len(resourceIDs) == 0 {
			// No matching resources found, return empty result
			return []*models.Drift{}, nil
		}

		// Add resource IDs to the main query
		placeholders := make([]string, len(resourceIDs))
		for i := range resourceIDs {
			placeholders[i] = fmt.Sprintf("$%d", argCounter)
			args = append(args, resourceIDs[i])
			argCounter++
		}
		query += fmt.Sprintf(" AND resource_id IN (%s)", joinStrings(placeholders, ","))
	}

	if len(filter.Status) > 0 {
		placeholders := make([]string, len(filter.Status))
		for i := range filter.Status {
			placeholders[i] = fmt.Sprintf("$%d", argCounter)
			args = append(args, filter.Status[i])
			argCounter++
		}
		query += fmt.Sprintf(" AND status IN (%s)", joinStrings(placeholders, ","))
	}

	if len(filter.Severity) > 0 {
		placeholders := make([]string, len(filter.Severity))
		for i := range filter.Severity {
			placeholders[i] = fmt.Sprintf("$%d", argCounter)
			args = append(args, filter.Severity[i])
			argCounter++
		}
		query += fmt.Sprintf(" AND severity IN (%s)", joinStrings(placeholders, ","))
	}

	if filter.DetectedAfter != nil {
		query += fmt.Sprintf(" AND detected_at > $%d", argCounter)
		args = append(args, *filter.DetectedAfter)
		argCounter++
	}

	if filter.DetectedBefore != nil {
		query += fmt.Sprintf(" AND detected_at < $%d", argCounter)
		args = append(args, *filter.DetectedBefore)
		argCounter++
	}

	if filter.HasWorkflow != nil {
		if *filter.HasWorkflow {
			query += " AND workflow_id IS NOT NULL"
		} else {
			query += " AND workflow_id IS NULL"
		}
	}

	// Add order by
	query += " ORDER BY detected_at DESC"

	// Execute the query
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var drifts []*models.Drift

	for rows.Next() {
		var drift models.Drift
		var changesJSON []byte
		var resolvedAt sql.NullTime
		var workflowID, resolutionNotes sql.NullString

		err := rows.Scan(
			&drift.ID,
			&drift.ResourceID,
			&drift.DetectedAt,
			&drift.Status,
			&drift.Severity,
			&changesJSON,
			&drift.ExpectedStateID,
			&drift.ActualStateID,
			&workflowID,
			&resolvedAt,
			&resolutionNotes,
		)

		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		// Handle null values
		if workflowID.Valid {
			drift.WorkflowID = workflowID.String
		}
		if resolvedAt.Valid {
			drift.ResolvedAt = &resolvedAt.Time
		}
		if resolutionNotes.Valid {
			drift.ResolutionNotes = resolutionNotes.String
		}

		// Parse JSON fields
		if err := json.Unmarshal(changesJSON, &drift.Changes); err != nil {
			return nil, fmt.Errorf("failed to parse changes: %w", err)
		}

		drifts = append(drifts, &drift)
	}

	return drifts, nil
}

// GetDriftsByResource retrieves drifts for a specific resource
func (db *DB) GetDriftsByResource(resourceID string, statuses []models.DriftStatus) ([]*models.Drift, error) {
	query := `SELECT id, resource_id, detected_at, status, severity, changes, 
              expected_state_id, actual_state_id, workflow_id, resolved_at, resolution_notes
              FROM drifts WHERE resource_id = $1`

	args := []interface{}{resourceID}
	argCounter := 2

	if len(statuses) > 0 {
		placeholders := make([]string, len(statuses))
		for i := range statuses {
			placeholders[i] = fmt.Sprintf("$%d", argCounter)
			args = append(args, statuses[i])
			argCounter++
		}
		query += fmt.Sprintf(" AND status IN (%s)", joinStrings(placeholders, ","))
	}

	query += " ORDER BY detected_at DESC"

	// Execute the query
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var drifts []*models.Drift

	for rows.Next() {
		var drift models.Drift
		var changesJSON []byte
		var resolvedAt sql.NullTime
		var workflowID, resolutionNotes sql.NullString

		err := rows.Scan(
			&drift.ID,
			&drift.ResourceID,
			&drift.DetectedAt,
			&drift.Status,
			&drift.Severity,
			&changesJSON,
			&drift.ExpectedStateID,
			&drift.ActualStateID,
			&workflowID,
			&resolvedAt,
			&resolutionNotes,
		)

		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		// Handle null values
		if workflowID.Valid {
			drift.WorkflowID = workflowID.String
		}
		if resolvedAt.Valid {
			drift.ResolvedAt = &resolvedAt.Time
		}
		if resolutionNotes.Valid {
			drift.ResolutionNotes = resolutionNotes.String
		}

		// Parse JSON fields
		if err := json.Unmarshal(changesJSON, &drift.Changes); err != nil {
			return nil, fmt.Errorf("failed to parse changes: %w", err)
		}

		drifts = append(drifts, &drift)
	}

	return drifts, nil
}

// CreateWorkflow creates a new workflow
func (db *DB) CreateWorkflow(workflow *models.Workflow) error {
	query := `INSERT INTO workflows 
              (id, name, description, template_id, status, created_at, started_at, 
              completed_at, drift_id, resource_id, current_action, error_message)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := db.conn.Exec(query,
		workflow.ID,
		workflow.Name,
		workflow.Description,
		workflow.TemplateID,
		workflow.Status,
		workflow.CreatedAt,
		workflow.StartedAt,
		workflow.CompletedAt,
		workflow.DriftID,
		workflow.ResourceID,
		workflow.CurrentAction,
		workflow.ErrorMessage,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	// Insert workflow actions
	for _, action := range workflow.Actions {
		if err := db.createWorkflowAction(&action); err != nil {
			return fmt.Errorf("failed to create workflow action: %w", err)
		}
	}

	return nil
}

// createWorkflowAction creates a workflow action
func (db *DB) createWorkflowAction(action *models.WorkflowAction) error {
	query := `INSERT INTO workflow_actions 
              (id, workflow_id, type, name, description, status, 
              "order", config, started_at, completed_at, result, error_message)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	configJSON, err := json.Marshal(action.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	var resultJSON []byte
	if action.Result != nil {
		resultJSON, err = json.Marshal(action.Result)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
	}

	_, err = db.conn.Exec(query,
		action.ID,
		action.WorkflowID,
		action.Type,
		action.Name,
		action.Description,
		action.Status,
		action.Order,
		configJSON,
		action.StartedAt,
		action.CompletedAt,
		resultJSON,
		action.ErrorMessage,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// GetWorkflow retrieves a workflow by ID
func (db *DB) GetWorkflow(id string) (*models.Workflow, error) {
	query := `SELECT id, name, description, template_id, status, created_at, started_at, 
              completed_at, drift_id, resource_id, current_action, error_message
              FROM workflows WHERE id = $1`

	var workflow models.Workflow
	var templateID, errorMessage sql.NullString
	var startedAt, completedAt sql.NullTime

	err := db.conn.QueryRow(query, id).Scan(
		&workflow.ID,
		&workflow.Name,
		&workflow.Description,
		&templateID,
		&workflow.Status,
		&workflow.CreatedAt,
		&startedAt,
		&completedAt,
		&workflow.DriftID,
		&workflow.ResourceID,
		&workflow.CurrentAction,
		&errorMessage,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("workflow not found: %s", id)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Handle null values
	if templateID.Valid {
		workflow.TemplateID = templateID.String
	}
	if startedAt.Valid {
		workflow.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		workflow.CompletedAt = &completedAt.Time
	}
	if errorMessage.Valid {
		workflow.ErrorMessage = errorMessage.String
	}

	// Get workflow actions
	actionsQuery := `SELECT id, workflow_id, type, name, description, status, 
                     "order", config, started_at, completed_at, result, error_message
                     FROM workflow_actions WHERE workflow_id = $1 ORDER BY "order" ASC`

	actionRows, err := db.conn.Query(actionsQuery, id)
	if err != nil {
		return nil, fmt.Errorf("error querying workflow actions: %w", err)
	}
	defer actionRows.Close()

	for actionRows.Next() {
		var action models.WorkflowAction
		var configJSON, resultJSON []byte
		var startedAt, completedAt sql.NullTime
		var errorMessage sql.NullString

		err := actionRows.Scan(
			&action.ID,
			&action.WorkflowID,
			&action.Type,
			&action.Name,
			&action.Description,
			&action.Status,
			&action.Order,
			&configJSON,
			&startedAt,
			&completedAt,
			&resultJSON,
			&errorMessage,
		)

		if err != nil {
			return nil, fmt.Errorf("error scanning action row: %w", err)
		}

		// Handle null values
		if startedAt.Valid {
			action.StartedAt = &startedAt.Time
		}
		if completedAt.Valid {
			action.CompletedAt = &completedAt.Time
		}
		if errorMessage.Valid {
			action.ErrorMessage = errorMessage.String
		}

		// Parse JSON fields
		if err := json.Unmarshal(configJSON, &action.Config); err != nil {
			return nil, fmt.Errorf("failed to parse action config: %w", err)
		}

		if resultJSON != nil && len(resultJSON) > 0 {
			if err := json.Unmarshal(resultJSON, &action.Result); err != nil {
				return nil, fmt.Errorf("failed to parse action result: %w", err)
			}
		}

		workflow.Actions = append(workflow.Actions, action)
	}

	return &workflow, nil
}

// UpdateWorkflow updates an existing workflow
func (db *DB) UpdateWorkflow(workflow *models.Workflow) error {
	query := `UPDATE workflows 
              SET name = $2, description = $3, template_id = $4, status = $5, 
                  started_at = $6, completed_at = $7, drift_id = $8, 
                  resource_id = $9, current_action = $10, error_message = $11
              WHERE id = $1`

	_, err := db.conn.Exec(query,
		workflow.ID,
		workflow.Name,
		workflow.Description,
		workflow.TemplateID,
		workflow.Status,
		workflow.StartedAt,
		workflow.CompletedAt,
		workflow.DriftID,
		workflow.ResourceID,
		workflow.CurrentAction,
		workflow.ErrorMessage,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	// Update actions (optional, could be separate method)
	for _, action := range workflow.Actions {
		if err := db.updateWorkflowAction(&action); err != nil {
			return fmt.Errorf("failed to update workflow action: %w", err)
		}
	}

	return nil
}

// updateWorkflowAction updates a workflow action
func (db *DB) updateWorkflowAction(action *models.WorkflowAction) error {
	query := `UPDATE workflow_actions 
              SET type = $3, name = $4, description = $5, status = $6, 
                  "order" = $7, config = $8, started_at = $9, 
                  completed_at = $10, result = $11, error_message = $12
              WHERE id = $1 AND workflow_id = $2`

	configJSON, err := json.Marshal(action.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	var resultJSON []byte
	if action.Result != nil {
		resultJSON, err = json.Marshal(action.Result)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
	}

	_, err = db.conn.Exec(query,
		action.ID,
		action.WorkflowID,
		action.Type,
		action.Name,
		action.Description,
		action.Status,
		action.Order,
		configJSON,
		action.StartedAt,
		action.CompletedAt,
		resultJSON,
		action.ErrorMessage,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// DeleteWorkflow deletes a workflow
func (db *DB) DeleteWorkflow(id string) error {
	// Start a transaction
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete workflow actions first
	_, err = tx.Exec("DELETE FROM workflow_actions WHERE workflow_id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete workflow actions: %w", err)
	}

	// Delete the workflow
	result, err := tx.Exec("DELETE FROM workflows WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	// Check if workflow existed
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("workflow not found: %s", id)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetWorkflows retrieves workflows based on a filter
func (db *DB) GetWorkflows(filter models.WorkflowFilter) ([]*models.Workflow, error) {
	query := `SELECT id, name, description, template_id, status, created_at, started_at, 
              completed_at, drift_id, resource_id, current_action, error_message
              FROM workflows WHERE 1=1`

	var args []interface{}
	argCounter := 1

	// Add filter conditions
	if filter.DriftID != "" {
		query += fmt.Sprintf(" AND drift_id = $%d", argCounter)
		args = append(args, filter.DriftID)
		argCounter++
	}

	if filter.ResourceID != "" {
		query += fmt.Sprintf(" AND resource_id = $%d", argCounter)
		args = append(args, filter.ResourceID)
		argCounter++
	}

	if len(filter.Status) > 0 {
		placeholders := make([]string, len(filter.Status))
		for i := range filter.Status {
			placeholders[i] = fmt.Sprintf("$%d", argCounter)
			args = append(args, filter.Status[i])
			argCounter++
		}
		query += fmt.Sprintf(" AND status IN (%s)", joinStrings(placeholders, ","))
	}

	if filter.CreatedAfter != nil {
		query += fmt.Sprintf(" AND created_at > $%d", argCounter)
		args = append(args, *filter.CreatedAfter)
		argCounter++
	}

	if filter.CreatedBefore != nil {
		query += fmt.Sprintf(" AND created_at < $%d", argCounter)
		args = append(args, *filter.CreatedBefore)
		argCounter++
	}

	// Add order by
	query += " ORDER BY created_at DESC"

	// Execute the query
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var workflows []*models.Workflow

	for rows.Next() {
		var workflow models.Workflow
		var templateID, errorMessage sql.NullString
		var startedAt, completedAt sql.NullTime

		err := rows.Scan(
			&workflow.ID,
			&workflow.Name,
			&workflow.Description,
			&templateID,
			&workflow.Status,
			&workflow.CreatedAt,
			&startedAt,
			&completedAt,
			&workflow.DriftID,
			&workflow.ResourceID,
			&workflow.CurrentAction,
			&errorMessage,
		)

		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		// Handle null values
		if templateID.Valid {
			workflow.TemplateID = templateID.String
		}
		if startedAt.Valid {
			workflow.StartedAt = &startedAt.Time
		}
		if completedAt.Valid {
			workflow.CompletedAt = &completedAt.Time
		}
		if errorMessage.Valid {
			workflow.ErrorMessage = errorMessage.String
		}

		workflows = append(workflows, &workflow)
	}

	return workflows, nil
}

// CreateWorkflowTemplate creates a new workflow template
func (db *DB) CreateWorkflowTemplate(template *models.WorkflowTemplate) error {
	query := `INSERT INTO workflow_templates 
              (id, name, description, created_at, updated_at, is_default, 
               resource_types, providers, tags)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	resourceTypesJSON, err := json.Marshal(template.ResourceTypes)
	if err != nil {
		return fmt.Errorf("failed to marshal resource types: %w", err)
	}

	providersJSON, err := json.Marshal(template.Providers)
	if err != nil {
		return fmt.Errorf("failed to marshal providers: %w", err)
	}

	tagsJSON, err := json.Marshal(template.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	_, err = db.conn.Exec(query,
		template.ID,
		template.Name,
		template.Description,
		template.CreatedAt,
		template.UpdatedAt,
		template.IsDefault,
		resourceTypesJSON,
		providersJSON,
		tagsJSON,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	// Insert template actions
	for _, action := range template.Actions {
		if err := db.createWorkflowActionTemplate(template.ID, &action); err != nil {
			return fmt.Errorf("failed to create workflow action template: %w", err)
		}
	}

	return nil
}

// createWorkflowActionTemplate creates a workflow action template
func (db *DB) createWorkflowActionTemplate(templateID string, action *models.WorkflowActionTemplate) error {
	query := `INSERT INTO workflow_action_templates 
              (template_id, type, name, description, "order", config)
              VALUES ($1, $2, $3, $4, $5, $6)`

	configJSON, err := json.Marshal(action.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	_, err = db.conn.Exec(query,
		templateID,
		action.Type,
		action.Name,
		action.Description,
		action.Order,
		configJSON,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// GetWorkflowTemplate retrieves a workflow template by ID
func (db *DB) GetWorkflowTemplate(id string) (*models.WorkflowTemplate, error) {
	query := `SELECT id, name, description, created_at, updated_at, is_default, 
              resource_types, providers, tags
              FROM workflow_templates WHERE id = $1`

	var template models.WorkflowTemplate
	var resourceTypesJSON, providersJSON, tagsJSON []byte

	err := db.conn.QueryRow(query, id).Scan(
		&template.ID,
		&template.Name,
		&template.Description,
		&template.CreatedAt,
		&template.UpdatedAt,
		&template.IsDefault,
		&resourceTypesJSON,
		&providersJSON,
		&tagsJSON,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("workflow template not found: %s", id)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Parse JSON fields
	if err := json.Unmarshal(resourceTypesJSON, &template.ResourceTypes); err != nil {
		return nil, fmt.Errorf("failed to parse resource types: %w", err)
	}

	if err := json.Unmarshal(providersJSON, &template.Providers); err != nil {
		return nil, fmt.Errorf("failed to parse providers: %w", err)
	}

	if err := json.Unmarshal(tagsJSON, &template.Tags); err != nil {
		return nil, fmt.Errorf("failed to parse tags: %w", err)
	}

	// Get template actions
	actionsQuery := `SELECT template_id, type, name, description, "order", config
                     FROM workflow_action_templates 
                     WHERE template_id = $1 ORDER BY "order" ASC`

	actionRows, err := db.conn.Query(actionsQuery, id)
	if err != nil {
		return nil, fmt.Errorf("error querying workflow action templates: %w", err)
	}
	defer actionRows.Close()

	for actionRows.Next() {
		var action models.WorkflowActionTemplate
		var templateID string
		var configJSON []byte

		err := actionRows.Scan(
			&templateID,
			&action.Type,
			&action.Name,
			&action.Description,
			&action.Order,
			&configJSON,
		)

		if err != nil {
			return nil, fmt.Errorf("error scanning action template row: %w", err)
		}

		// Parse JSON fields
		if err := json.Unmarshal(configJSON, &action.Config); err != nil {
			return nil, fmt.Errorf("failed to parse action config: %w", err)
		}

		template.Actions = append(template.Actions, action)
	}

	return &template, nil
}

// UpdateWorkflowTemplate updates an existing workflow template
func (db *DB) UpdateWorkflowTemplate(template *models.WorkflowTemplate) error {
	// Start a transaction
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Update the template
	query := `UPDATE workflow_templates 
              SET name = $2, description = $3, updated_at = $4, is_default = $5, 
                  resource_types = $6, providers = $7, tags = $8
              WHERE id = $1`

	resourceTypesJSON, err := json.Marshal(template.ResourceTypes)
	if err != nil {
		return fmt.Errorf("failed to marshal resource types: %w", err)
	}

	providersJSON, err := json.Marshal(template.Providers)
	if err != nil {
		return fmt.Errorf("failed to marshal providers: %w", err)
	}

	tagsJSON, err := json.Marshal(template.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	_, err = tx.Exec(query,
		template.ID,
		template.Name,
		template.Description,
		template.UpdatedAt,
		template.IsDefault,
		resourceTypesJSON,
		providersJSON,
		tagsJSON,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	// Delete existing action templates
	_, err = tx.Exec("DELETE FROM workflow_action_templates WHERE template_id = $1", template.ID)
	if err != nil {
		return fmt.Errorf("failed to delete existing action templates: %w", err)
	}

	// Insert updated action templates
	for _, action := range template.Actions {
		configJSON, err := json.Marshal(action.Config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		_, err = tx.Exec(
			`INSERT INTO workflow_action_templates 
             (template_id, type, name, description, "order", config)
             VALUES ($1, $2, $3, $4, $5, $6)`,
			template.ID,
			action.Type,
			action.Name,
			action.Description,
			action.Order,
			configJSON,
		)

		if err != nil {
			return fmt.Errorf("failed to insert action template: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteWorkflowTemplate deletes a workflow template
func (db *DB) DeleteWorkflowTemplate(id string) error {
	// Start a transaction
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete template actions first
	_, err = tx.Exec("DELETE FROM workflow_action_templates WHERE template_id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete workflow action templates: %w", err)
	}

	// Delete the template
	result, err := tx.Exec("DELETE FROM workflow_templates WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	// Check if template existed
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("workflow template not found: %s", id)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetWorkflowTemplates retrieves all workflow templates
func (db *DB) GetWorkflowTemplates() ([]*models.WorkflowTemplate, error) {
	query := `SELECT id, name, description, created_at, updated_at, is_default, 
              resource_types, providers, tags
              FROM workflow_templates ORDER BY name ASC`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var templates []*models.WorkflowTemplate

	for rows.Next() {
		var template models.WorkflowTemplate
		var resourceTypesJSON, providersJSON, tagsJSON []byte

		err := rows.Scan(
			&template.ID,
			&template.Name,
			&template.Description,
			&template.CreatedAt,
			&template.UpdatedAt,
			&template.IsDefault,
			&resourceTypesJSON,
			&providersJSON,
			&tagsJSON,
		)

		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		// Parse JSON fields
		if err := json.Unmarshal(resourceTypesJSON, &template.ResourceTypes); err != nil {
			return nil, fmt.Errorf("failed to parse resource types: %w", err)
		}

		if err := json.Unmarshal(providersJSON, &template.Providers); err != nil {
			return nil, fmt.Errorf("failed to parse providers: %w", err)
		}

		if err := json.Unmarshal(tagsJSON, &template.Tags); err != nil {
			return nil, fmt.Errorf("failed to parse tags: %w", err)
		}

		templates = append(templates, &template)
	}

	return templates, nil
}

// CreateApprovalRequest creates a new approval request
func (db *DB) CreateApprovalRequest(request *ApprovalRequest) error {
	query := `INSERT INTO approval_requests 
              (id, workflow_id, action_id, status, created_at, expires_at, 
               approvers, min_approvals, drift_id, resource_id)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	approversJSON, err := json.Marshal(request.Approvers)
	if err != nil {
		return fmt.Errorf("failed to marshal approvers: %w", err)
	}

	_, err = db.conn.Exec(query,
		request.ID,
		request.WorkflowID,
		request.ActionID,
		request.Status,
		request.CreatedAt,
		request.ExpiresAt,
		approversJSON,
		request.MinApprovals,
		request.DriftID,
		request.ResourceID,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// GetApprovalRequest retrieves an approval request by ID
func (db *DB) GetApprovalRequest(id string) (*ApprovalRequest, error) {
	query := `SELECT id, workflow_id, action_id, status, created_at, expires_at, 
              approvers, min_approvals, drift_id, resource_id, approvals
              FROM approval_requests WHERE id = $1`

	var request ApprovalRequest
	var approversJSON, approvalsJSON []byte
	var expiresAt sql.NullTime

	err := db.conn.QueryRow(query, id).Scan(
		&request.ID,
		&request.WorkflowID,
		&request.ActionID,
		&request.Status,
		&request.CreatedAt,
		&expiresAt,
		&approversJSON,
		&request.MinApprovals,
		&request.DriftID,
		&request.ResourceID,
		&approvalsJSON,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("approval request not found: %s", id)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Handle null values
	if expiresAt.Valid {
		request.ExpiresAt = &expiresAt.Time
	}

	// Parse JSON fields
	if err := json.Unmarshal(approversJSON, &request.Approvers); err != nil {
		return nil, fmt.Errorf("failed to parse approvers: %w", err)
	}

	if approvalsJSON != nil && len(approvalsJSON) > 0 {
		if err := json.Unmarshal(approvalsJSON, &request.Approvals); err != nil {
			return nil, fmt.Errorf("failed to parse approvals: %w", err)
		}
	}

	return &request, nil
}

// UpdateApprovalRequest updates an approval request
func (db *DB) UpdateApprovalRequest(request *ApprovalRequest) error {
	query := `UPDATE approval_requests 
              SET status = $2, approvals = $3
              WHERE id = $1`

	approvalsJSON, err := json.Marshal(request.Approvals)
	if err != nil {
		return fmt.Errorf("failed to marshal approvals: %w", err)
	}

	_, err = db.conn.Exec(query,
		request.ID,
		request.Status,
		approvalsJSON,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// GetApprovalRequests retrieves approval requests based on filters
func (db *DB) GetApprovalRequests(workflowID, actionID, resourceID string, status ApprovalStatus) ([]*ApprovalRequest, error) {
	query := `SELECT id, workflow_id, action_id, status, created_at, expires_at, 
              approvers, min_approvals, drift_id, resource_id, approvals
              FROM approval_requests WHERE 1=1`

	var args []interface{}
	argCounter := 1

	// Add filter conditions
	if workflowID != "" {
		query += fmt.Sprintf(" AND workflow_id = $%d", argCounter)
		args = append(args, workflowID)
		argCounter++
	}

	if actionID != "" {
		query += fmt.Sprintf(" AND action_id = $%d", argCounter)
		args = append(args, actionID)
		argCounter++
	}

	if resourceID != "" {
		query += fmt.Sprintf(" AND resource_id = $%d", argCounter)
		args = append(args, resourceID)
		argCounter++
	}

	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argCounter)
		args = append(args, status)
		argCounter++
	}

	// Add order by
	query += " ORDER BY created_at DESC"

	// Execute the query
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var requests []*ApprovalRequest

	for rows.Next() {
		var request ApprovalRequest
		var approversJSON, approvalsJSON []byte
		var expiresAt sql.NullTime

		err := rows.Scan(
			&request.ID,
			&request.WorkflowID,
			&request.ActionID,
			&request.Status,
			&request.CreatedAt,
			&expiresAt,
			&approversJSON,
			&request.MinApprovals,
			&request.DriftID,
			&request.ResourceID,
			&approvalsJSON,
		)

		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		// Handle null values
		if expiresAt.Valid {
			request.ExpiresAt = &expiresAt.Time
		}

		// Parse JSON fields
		if err := json.Unmarshal(approversJSON, &request.Approvers); err != nil {
			return nil, fmt.Errorf("failed to parse approvers: %w", err)
		}

		if approvalsJSON != nil && len(approvalsJSON) > 0 {
			if err := json.Unmarshal(approvalsJSON, &request.Approvals); err != nil {
				return nil, fmt.Errorf("failed to parse approvals: %w", err)
			}
		}

		requests = append(requests, &request)
	}

	return requests, nil
}

// GetResourceMetadata retrieves resource metadata by key
func (db *DB) GetResourceMetadata(resourceID, key string) (string, error) {
	query := `SELECT value FROM resource_metadata WHERE resource_id = $1 AND key = $2`

	var value string
	err := db.conn.QueryRow(query, resourceID, key).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("metadata not found for resource %s, key %s", resourceID, key)
		}
		return "", fmt.Errorf("database error: %w", err)
	}

	return value, nil
}

// SetResourceMetadata sets resource metadata
func (db *DB) SetResourceMetadata(resourceID, key, value string) error {
	// Check if metadata exists
	query := `SELECT 1 FROM resource_metadata WHERE resource_id = $1 AND key = $2`
	var exists bool
	err := db.conn.QueryRow(query, resourceID, key).Scan(&exists)

	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("database error: %w", err)
	}

	if err == sql.ErrNoRows {
		// Insert new metadata
		query = `INSERT INTO resource_metadata (resource_id, key, value) VALUES ($1, $2, $3)`
		_, err = db.conn.Exec(query, resourceID, key, value)
	} else {
		// Update existing metadata
		query = `UPDATE resource_metadata SET value = $3 WHERE resource_id = $1 AND key = $2`
		_, err = db.conn.Exec(query, resourceID, key, value)
	}

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// GetNotificationChannel retrieves a notification channel
func (db *DB) GetNotificationChannel(id string) (*NotificationChannel, error) {
	query := `SELECT id, name, type, config, created_at, updated_at
              FROM notification_channels WHERE id = $1`

	var channel NotificationChannel
	var configJSON []byte

	err := db.conn.QueryRow(query, id).Scan(
		&channel.ID,
		&channel.Name,
		&channel.Type,
		&configJSON,
		&channel.CreatedAt,
		&channel.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("notification channel not found: %s", id)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Parse JSON fields
	if configJSON != nil {
		if err := json.Unmarshal(configJSON, &channel.Config); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}
	} else {
		channel.Config = make(map[string]interface{})
	}

	return &channel, nil
}

func (t *NotificationTemplate) New(name string) (*template.Template, error) {
	return template.New(name), nil
}

// GetNotificationRecipient retrieves a notification recipient
func (db *DB) GetNotificationRecipient(id string) (*NotificationRecipient, error) {
	query := `SELECT id, name, email, channels, groups, created_at, updated_at
              FROM notification_recipients WHERE id = $1`

	var recipient NotificationRecipient
	var channelsJSON, groupsJSON []byte

	err := db.conn.QueryRow(query, id).Scan(
		&recipient.ID,
		&recipient.Name,
		&recipient.Email,
		&channelsJSON,
		&groupsJSON,
		&recipient.CreatedAt,
		&recipient.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("notification recipient not found: %s", id)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Parse JSON fields
	if channelsJSON != nil {
		if err := json.Unmarshal(channelsJSON, &recipient.Channels); err != nil {
			return nil, fmt.Errorf("failed to parse channels: %w", err)
		}
	}

	if groupsJSON != nil {
		if err := json.Unmarshal(groupsJSON, &recipient.Groups); err != nil {
			return nil, fmt.Errorf("failed to parse groups: %w", err)
		}
	}

	return &recipient, nil
}

func (db *DB) GetGroupRecipients(groupID string) ([]string, error) {
	// First, get the group to make sure it exists
	query := `SELECT recipients FROM notification_groups WHERE id = $1`

	var recipientsJSON []byte
	err := db.conn.QueryRow(query, groupID).Scan(&recipientsJSON)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("notification group not found: %s", groupID)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Parse JSON field
	var recipients []string
	if recipientsJSON != nil {
		if err := json.Unmarshal(recipientsJSON, &recipients); err != nil {
			return nil, fmt.Errorf("failed to parse recipients: %w", err)
		}
	}

	return recipients, nil
}

// GetNotificationTemplate retrieves a notification template
func (db *DB) GetNotificationTemplate(id string) (*NotificationTemplate, error) {
	query := `SELECT id, name, content, created_at, updated_at
              FROM notification_templates WHERE id = $1`

	var template NotificationTemplate

	err := db.conn.QueryRow(query, id).Scan(
		&template.ID,
		&template.Name,
		&template.Content,
		&template.CreatedAt,
		&template.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("notification template not found: %s", id)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	return &template, nil
}

func (db *DB) DeleteNotificationTemplate(id string) error {
	query := `DELETE FROM notification_templates WHERE id = $1`

	result, err := db.conn.Exec(query, id)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("notification template not found: %s", id)
	}

	return nil
}

func (db *DB) UpdateNotificationGroup(group *NotificationGroup) error {
	query := `UPDATE notification_groups
              SET name = $2, description = $3, recipients = $4, updated_at = $5
              WHERE id = $1`

	// Update timestamp
	group.UpdatedAt = time.Now()

	recipientsJSON, err := json.Marshal(group.Recipients)
	if err != nil {
		return fmt.Errorf("failed to marshal recipients: %w", err)
	}

	result, err := db.conn.Exec(query,
		group.ID,
		group.Name,
		group.Description,
		recipientsJSON,
		group.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("notification group not found: %s", group.ID)
	}

	return nil
}

// GetNotificationGroups retrieves all notification groups
func (db *DB) GetNotificationGroups() ([]*NotificationGroup, error) {
	query := `SELECT id, name, description, recipients, created_at, updated_at
              FROM notification_groups ORDER BY name ASC`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var groups []*NotificationGroup

	for rows.Next() {
		var group NotificationGroup
		var recipientsJSON []byte

		err := rows.Scan(
			&group.ID,
			&group.Name,
			&group.Description,
			&recipientsJSON,
			&group.CreatedAt,
			&group.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		// Parse JSON fields
		if recipientsJSON != nil {
			if err := json.Unmarshal(recipientsJSON, &group.Recipients); err != nil {
				return nil, fmt.Errorf("failed to parse recipients: %w", err)
			}
		}

		groups = append(groups, &group)
	}

	return groups, nil
}

// GetNotificationGroup retrieves a notification group by ID
func (db *DB) GetNotificationGroup(id string) (*NotificationGroup, error) {
	query := `SELECT id, name, description, recipients, created_at, updated_at
              FROM notification_groups WHERE id = $1`

	var group NotificationGroup
	var recipientsJSON []byte

	err := db.conn.QueryRow(query, id).Scan(
		&group.ID,
		&group.Name,
		&group.Description,
		&recipientsJSON,
		&group.CreatedAt,
		&group.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("notification group not found: %s", id)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Parse JSON fields
	if recipientsJSON != nil {
		if err := json.Unmarshal(recipientsJSON, &group.Recipients); err != nil {
			return nil, fmt.Errorf("failed to parse recipients: %w", err)
		}
	}

	return &group, nil
}

func (db *DB) UpdateNotificationTemplate(template *NotificationTemplate) error {
	query := `UPDATE notification_templates 
              SET name = $2, content = $3, updated_at = $4
              WHERE id = $1`

	// Update timestamp
	template.UpdatedAt = time.Now()

	result, err := db.conn.Exec(query,
		template.ID,
		template.Name,
		template.Content,
		template.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("notification template not found: %s", template.ID)
	}

	return nil
}

// GetNotificationTemplates retrieves all notification templates
func (db *DB) GetNotificationTemplates() ([]*NotificationTemplate, error) {
	query := `SELECT id, name, content, created_at, updated_at
              FROM notification_templates ORDER BY name ASC`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var templates []*NotificationTemplate

	for rows.Next() {
		var template NotificationTemplate

		err := rows.Scan(
			&template.ID,
			&template.Name,
			&template.Content,
			&template.CreatedAt,
			&template.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		templates = append(templates, &template)
	}

	return templates, nil
}

// DiscoverResources discovers resources from providers
func (db *DB) DiscoverResources(ctx context.Context, filter models.ResourceFilter) ([]*models.Resource, error) {
	// This is a pass-through method to the collector
	// The actual implementation depends on the collector implementation
	// For now, we'll add a placeholder that returns an empty slice
	return []*models.Resource{}, nil
}

// Helper types and functions

// NotificationTemplate represents a notification template
type NotificationTemplate struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NotificationChannel represents a notification channel
type NotificationChannel struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	Config    map[string]interface{} `json:"config"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// NotificationRecipient represents a notification recipient
type NotificationRecipient struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Channels  []string  `json:"channels"`
	Groups    []string  `json:"groups"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NotificationGroup represents a group of notification recipients
type NotificationGroup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Recipients  []string  `json:"recipients"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ApprovalRequest represents an approval request
type ApprovalRequest struct {
	ID           string         `json:"id"`
	WorkflowID   string         `json:"workflow_id"`
	ActionID     string         `json:"action_id"`
	Status       ApprovalStatus `json:"status"`
	CreatedAt    time.Time      `json:"created_at"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	Approvers    []string       `json:"approvers"`
	MinApprovals int            `json:"min_approvals"`
	Approvals    []Approval     `json:"approvals,omitempty"`
	DriftID      string         `json:"drift_id"`
	ResourceID   string         `json:"resource_id"`
}

// ApprovalStatus represents the status of an approval request
type ApprovalStatus string

// Approval status constants
const (
	ApprovalStatusPending  ApprovalStatus = "pending"
	ApprovalStatusApproved ApprovalStatus = "approved"
	ApprovalStatusRejected ApprovalStatus = "rejected"
	ApprovalStatusExpired  ApprovalStatus = "expired"
)

// Approval represents an approval
type Approval struct {
	ApproverID string    `json:"approver_id"`
	ApprovedAt time.Time `json:"approved_at"`
	Comment    string    `json:"comment,omitempty"`
}

// Helper function to join strings with a separator
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}

	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}

	return result
}

func (db *DB) CreateNotificationGroup(group *NotificationGroup) error {
	query := `INSERT INTO notification_groups
              (id, name, description, recipients, created_at, updated_at)
              VALUES ($1, $2, $3, $4, $5, $6)`

	// Set timestamps if not already set
	now := time.Now()
	if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	if group.UpdatedAt.IsZero() {
		group.UpdatedAt = now
	}

	recipientsJSON, err := json.Marshal(group.Recipients)
	if err != nil {
		return fmt.Errorf("failed to marshal recipients: %w", err)
	}

	_, err = db.conn.Exec(query,
		group.ID,
		group.Name,
		group.Description,
		recipientsJSON,
		group.CreatedAt,
		group.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create notification group: %w", err)
	}

	return nil
}

// CreateNotificationTemplate creates a new notification template
func (db *DB) CreateNotificationTemplate(template *NotificationTemplate) error {
	query := `INSERT INTO notification_templates
              (id, name, content, created_at, updated_at)
              VALUES ($1, $2, $3, $4, $5)`

	// Set timestamps if not already set
	now := time.Now()
	if template.CreatedAt.IsZero() {
		template.CreatedAt = now
	}
	if template.UpdatedAt.IsZero() {
		template.UpdatedAt = now
	}

	_, err := db.conn.Exec(query,
		template.ID,
		template.Name,
		template.Content,
		template.CreatedAt,
		template.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create notification template: %w", err)
	}

	return nil
}
