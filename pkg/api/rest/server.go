package rest

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jdaws97/infrastructure-drift-controller/internal/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/detector"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
)

// Server is the REST API server
type Server struct {
	config        config.APIConfig
	db            *database.DB
	driftDetector *detector.Detector
	router        chi.Router
}

// NewServer creates a new REST API server
func NewServer(config config.APIConfig, db *database.DB, detector *detector.Detector) *Server {
	server := &Server{
		config:        config,
		db:            db,
		driftDetector: detector,
	}
	
	// Initialize router
	server.setupRouter()
	
	return server
}

// Router returns the HTTP router
func (s *Server) Router() chi.Router {
	return s.router
}

// setupRouter configures the HTTP router
func (s *Server) setupRouter() {
	r := chi.NewRouter()
	
	// Add middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	
	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	
	// API routes
	r.Route("/api", func(r chi.Router) {
		// Health check
		r.Get("/health", s.handleHealthCheck)
		
		// Resources
		r.Route("/resources", func(r chi.Router) {
			r.Get("/", s.handleListResources)
			r.Post("/", s.handleCreateResource)
			r.Get("/{id}", s.handleGetResource)
			r.Put("/{id}", s.handleUpdateResource)
			r.Delete("/{id}", s.handleDeleteResource)
			r.Get("/{id}/state", s.handleGetResourceState)
			r.Post("/discover", s.handleDiscoverResources)
		})
		
		// Drifts
		r.Route("/drifts", func(r chi.Router) {
			r.Get("/", s.handleListDrifts)
			r.Get("/{id}", s.handleGetDrift)
			r.Put("/{id}", s.handleUpdateDrift)
			r.Post("/detect", s.handleDetectDrift)
			r.Get("/resource/{resourceId}", s.handleGetResourceDrifts)
		})
		
		// Workflows
		r.Route("/workflows", func(r chi.Router) {
			r.Get("/", s.handleListWorkflows)
			r.Post("/", s.handleCreateWorkflow)
			r.Get("/{id}", s.handleGetWorkflow)
			r.Put("/{id}", s.handleUpdateWorkflow)
			r.Delete("/{id}", s.handleDeleteWorkflow)
		})
		
		// Templates
		r.Route("/templates", func(r chi.Router) {
			r.Get("/", s.handleListTemplates)
			r.Post("/", s.handleCreateTemplate)
			r.Get("/{id}", s.handleGetTemplate)
			r.Put("/{id}", s.handleUpdateTemplate)
			r.Delete("/{id}", s.handleDeleteTemplate)
		})
		
		// Approvals
		r.Route("/approvals", func(r chi.Router) {
			r.Get("/", s.handleListApprovals)
			r.Get("/{id}", s.handleGetApproval)
			r.Post("/{id}/approve", s.handleApprove)
			r.Post("/{id}/reject", s.handleReject)
		})
	})
	
	s.router = r
}

// Response is a standardized API response
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// writeSuccessResponse writes a successful response
func writeSuccessResponse(w http.ResponseWriter, message string, data interface{}) {
	response := Response{
		Success: true,
		Message: message,
		Data:    data,
	}
	writeJSON(w, http.StatusOK, response)
}

// writeErrorResponse writes an error response
func writeErrorResponse(w http.ResponseWriter, status int, message string, err error) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	
	response := Response{
		Success: false,
		Message: message,
		Error:   errMsg,
	}
	writeJSON(w, status, response)
}

// handleHealthCheck handles the health check endpoint
func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":  "ok",
		"time":    time.Now(),
		"version": "0.1.0",
	}
	writeSuccessResponse(w, "Service is healthy", health)
}

// Resource handlers
func (s *Server) handleListResources(w http.ResponseWriter, r *http.Request) {
	filter := models.ResourceFilter{}
	
	// Parse query parameters for filtering
	if r.URL.Query().Get("provider") != "" {
		filter.Provider = models.ProviderType(r.URL.Query().Get("provider"))
	}
	if r.URL.Query().Get("iac_type") != "" {
		filter.IaCType = models.IaCType(r.URL.Query().Get("iac_type"))
	}
	if r.URL.Query().Get("region") != "" {
		filter.Region = r.URL.Query().Get("region")
	}
	if r.URL.Query().Get("account") != "" {
		filter.Account = r.URL.Query().Get("account")
	}
	if r.URL.Query().Get("project") != "" {
		filter.Project = r.URL.Query().Get("project")
	}
	
	// Get resources from database
	resources, err := s.db.GetResources(filter)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to list resources", err)
		return
	}
	
	writeSuccessResponse(w, fmt.Sprintf("Retrieved %d resources", len(resources)), resources)
}

func (s *Server) handleCreateResource(w http.ResponseWriter, r *http.Request) {
	var resource models.Resource
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&resource); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Set timestamps
	now := time.Now()
	resource.CreatedAt = now
	resource.UpdatedAt = now
	
	// Create resource in database
	if err := s.db.CreateResource(&resource); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create resource", err)
		return
	}
	
	writeSuccessResponse(w, "Resource created successfully", resource)
}

func (s *Server) handleGetResource(w http.ResponseWriter, r *http.Request) {
	// Get resource ID from URL
	resourceID := chi.URLParam(r, "id")
	
	// Get resource from database
	resource, err := s.db.GetResource(resourceID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Resource not found", err)
		return
	}
	
	writeSuccessResponse(w, "Resource retrieved successfully", resource)
}

func (s *Server) handleUpdateResource(w http.ResponseWriter, r *http.Request) {
	// Get resource ID from URL
	resourceID := chi.URLParam(r, "id")
	
	// Check if resource exists
	existing, err := s.db.GetResource(resourceID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Resource not found", err)
		return
	}
	
	// Parse request body
	var resource models.Resource
	if err := json.NewDecoder(r.Body).Decode(&resource); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Ensure ID matches
	resource.ID = resourceID
	
	// Preserve creation timestamp
	resource.CreatedAt = existing.CreatedAt
	resource.UpdatedAt = time.Now()
	
	// Update resource in database
	if err := s.db.UpdateResource(&resource); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to update resource", err)
		return
	}
	
	writeSuccessResponse(w, "Resource updated successfully", resource)
}

func (s *Server) handleDeleteResource(w http.ResponseWriter, r *http.Request) {
	// Get resource ID from URL
	resourceID := chi.URLParam(r, "id")
	
	// Delete resource from database
	if err := s.db.DeleteResource(resourceID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete resource", err)
		return
	}
	
	writeSuccessResponse(w, "Resource deleted successfully", nil)
}

func (s *Server) handleGetResourceState(w http.ResponseWriter, r *http.Request) {
	// Get resource ID from URL
	resourceID := chi.URLParam(r, "id")
	
	// Get state type from query parameter (expected or actual)
	stateType := models.StateTypeActual // Default
	if r.URL.Query().Get("type") == "expected" {
		stateType = models.StateTypeExpected
	}
	
	// Get resource state from database
	var state *models.ResourceState
	var err error
	
	if stateType == models.StateTypeExpected {
		state, err = s.db.GetLatestExpectedState(resourceID)
	} else {
		state, err = s.db.GetLatestActualState(resourceID)
	}
	
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Resource state not found", err)
		return
	}
	
	writeSuccessResponse(w, "Resource state retrieved successfully", state)
}

func (s *Server) handleDiscoverResources(w http.ResponseWriter, r *http.Request) {
	// Parse request body for resource filter
	var filter models.ResourceFilter
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Call discovery method
	// In a real implementation, this would be in a background task
	// with progress updates
	resources, err := s.db.DiscoverResources(r.Context(), filter)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Resource discovery failed", err)
		return
	}
	
	writeSuccessResponse(w, fmt.Sprintf("Discovered %d resources", len(resources)), resources)
}

// Drift handlers
func (s *Server) handleListDrifts(w http.ResponseWriter, r *http.Request) {
	filter := models.DriftFilter{}
	
	// Parse query parameters for filtering
	if r.URL.Query().Get("resource_id") != "" {
		filter.ResourceID = r.URL.Query().Get("resource_id")
	}
	if r.URL.Query().Get("provider") != "" {
		filter.Provider = models.ProviderType(r.URL.Query().Get("provider"))
	}
	if r.URL.Query().Get("region") != "" {
		filter.Region = r.URL.Query().Get("region")
	}
	
	// Parse status filter
	if statusParam := r.URL.Query().Get("status"); statusParam != "" {
		statuses := []models.DriftStatus{models.DriftStatus(statusParam)}
		filter.Status = statuses
	}
	
	// Get drifts from database
	drifts, err := s.db.GetDrifts(filter)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to list drifts", err)
		return
	}
	
	writeSuccessResponse(w, fmt.Sprintf("Retrieved %d drifts", len(drifts)), drifts)
}

func (s *Server) handleGetDrift(w http.ResponseWriter, r *http.Request) {
	// Get drift ID from URL
	driftID := chi.URLParam(r, "id")
	
	// Get drift from database
	drift, err := s.db.GetDrift(driftID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Drift not found", err)
		return
	}
	
	writeSuccessResponse(w, "Drift retrieved successfully", drift)
}

func (s *Server) handleUpdateDrift(w http.ResponseWriter, r *http.Request) {
	// Get drift ID from URL
	driftID := chi.URLParam(r, "id")
	
	// Check if drift exists
	existing, err := s.db.GetDrift(driftID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Drift not found", err)
		return
	}
	
	// Parse request body
	var update struct {
		Status          *models.DriftStatus `json:"status,omitempty"`
		ResolutionNotes *string            `json:"resolution_notes,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Apply updates
	if update.Status != nil {
		existing.Status = *update.Status
		
		// If resolving, set the resolved time
		if *update.Status == models.DriftStatusResolved {
			now := time.Now()
			existing.ResolvedAt = &now
		}
	}
	if update.ResolutionNotes != nil {
		existing.ResolutionNotes = *update.ResolutionNotes
	}
	
	// Update drift in database
	if err := s.db.UpdateDrift(existing); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to update drift", err)
		return
	}
	
	writeSuccessResponse(w, "Drift updated successfully", existing)
}

func (s *Server) handleDetectDrift(w http.ResponseWriter, r *http.Request) {
	// Parse request body for resource filter
	var filter models.ResourceFilter
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Start drift detection
	// In a real implementation, this would be in a background task
	err := s.driftDetector.RunManualDetection(r.Context(), filter)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Drift detection failed", err)
		return
	}
	
	writeSuccessResponse(w, "Drift detection initiated", nil)
}

func (s *Server) handleGetResourceDrifts(w http.ResponseWriter, r *http.Request) {
	// Get resource ID from URL
	resourceID := chi.URLParam(r, "resourceId")
	
	// Parse status query parameter
	var statuses []models.DriftStatus
	if statusParam := r.URL.Query().Get("status"); statusParam != "" {
		statuses = append(statuses, models.DriftStatus(statusParam))
	}
	
	// Get drifts for the resource
	drifts, err := s.db.GetDriftsByResource(resourceID, statuses)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get resource drifts", err)
		return
	}
	
	writeSuccessResponse(w, fmt.Sprintf("Retrieved %d drifts for resource", len(drifts)), drifts)
}

// Workflow handlers
func (s *Server) handleListWorkflows(w http.ResponseWriter, r *http.Request) {
	filter := models.WorkflowFilter{}
	
	// Parse query parameters for filtering
	if r.URL.Query().Get("drift_id") != "" {
		filter.DriftID = r.URL.Query().Get("drift_id")
	}
	if r.URL.Query().Get("resource_id") != "" {
		filter.ResourceID = r.URL.Query().Get("resource_id")
	}
	
	// Parse status filter
	if statusParam := r.URL.Query().Get("status"); statusParam != "" {
		statuses := []models.WorkflowStatus{models.WorkflowStatus(statusParam)}
		filter.Status = statuses
	}
	
	// Get workflows from database
	workflows, err := s.db.GetWorkflows(filter)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to list workflows", err)
		return
	}
	
	writeSuccessResponse(w, fmt.Sprintf("Retrieved %d workflows", len(workflows)), workflows)
}

func (s *Server) handleCreateWorkflow(w http.ResponseWriter, r *http.Request) {
	var workflow models.Workflow
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&workflow); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Set timestamps
	workflow.CreatedAt = time.Now()
	
	// Create workflow in database
	if err := s.db.CreateWorkflow(&workflow); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create workflow", err)
		return
	}
	
	writeSuccessResponse(w, "Workflow created successfully", workflow)
}

func (s *Server) handleGetWorkflow(w http.ResponseWriter, r *http.Request) {
	// Get workflow ID from URL
	workflowID := chi.URLParam(r, "id")
	
	// Get workflow from database
	workflow, err := s.db.GetWorkflow(workflowID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Workflow not found", err)
		return
	}
	
	writeSuccessResponse(w, "Workflow retrieved successfully", workflow)
}

func (s *Server) handleUpdateWorkflow(w http.ResponseWriter, r *http.Request) {
	// Get workflow ID from URL
	workflowID := chi.URLParam(r, "id")
	
	// Check if workflow exists
	existing, err := s.db.GetWorkflow(workflowID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Workflow not found", err)
		return
	}
	
	// Parse request body
	var update struct {
		Status       *models.WorkflowStatus `json:"status,omitempty"`
		ErrorMessage *string               `json:"error_message,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Apply updates
	if update.Status != nil {
		existing.Status = *update.Status
		
		// If completing, set the completed time
		if *update.Status == models.WorkflowStatusCompleted || 
		   *update.Status == models.WorkflowStatusFailed ||
		   *update.Status == models.WorkflowStatusCancelled {
			now := time.Now()
			existing.CompletedAt = &now
		}
	}
	
	if update.ErrorMessage != nil {
		existing.ErrorMessage = *update.ErrorMessage
	}
	
	// Update workflow in database
	if err := s.db.UpdateWorkflow(existing); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to update workflow", err)
		return
	}
	
	writeSuccessResponse(w, "Workflow updated successfully", existing)
}

func (s *Server) handleDeleteWorkflow(w http.ResponseWriter, r *http.Request) {
	// Get workflow ID from URL
	workflowID := chi.URLParam(r, "id")
	
	// Delete workflow from database
	if err := s.db.DeleteWorkflow(workflowID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete workflow", err)
		return
	}
	
	writeSuccessResponse(w, "Workflow deleted successfully", nil)
}

// Template handlers
func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	// Get templates from database
	templates, err := s.db.GetWorkflowTemplates()
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to list templates", err)
		return
	}
	
	writeSuccessResponse(w, fmt.Sprintf("Retrieved %d templates", len(templates)), templates)
}

func (s *Server) handleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	var template models.WorkflowTemplate
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&template); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Set timestamps
	now := time.Now()
	template.CreatedAt = now
	template.UpdatedAt = now
	
	// Create template in database
	if err := s.db.CreateWorkflowTemplate(&template); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create template", err)
		return
	}
	
	writeSuccessResponse(w, "Template created successfully", template)
}

func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	// Get template ID from URL
	templateID := chi.URLParam(r, "id")
	
	// Get template from database
	template, err := s.db.GetWorkflowTemplate(templateID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Template not found", err)
		return
	}
	
	writeSuccessResponse(w, "Template retrieved successfully", template)
}

func (s *Server) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	// Get template ID from URL
	templateID := chi.URLParam(r, "id")
	
	// Check if template exists
	existing, err := s.db.GetWorkflowTemplate(templateID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Template not found", err)
		return
	}
	
	// Parse request body
	var template models.WorkflowTemplate
	if err := json.NewDecoder(r.Body).Decode(&template); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Ensure ID matches
	template.ID = templateID
	
	// Preserve creation timestamp
	template.CreatedAt = existing.CreatedAt
	template.UpdatedAt = time.Now()
	
	// Update template in database
	if err := s.db.UpdateWorkflowTemplate(&template); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to update template", err)
		return
	}
	
	writeSuccessResponse(w, "Template updated successfully", template)
}

func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	// Get template ID from URL
	templateID := chi.URLParam(r, "id")
	
	// Delete template from database
	if err := s.db.DeleteWorkflowTemplate(templateID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete template", err)
		return
	}
	
	writeSuccessResponse(w, "Template deleted successfully", nil)
}

// Approval request type (should be in models package in production)
type ApprovalRequest struct {
	ID           string        `json:"id"`
	WorkflowID   string        `json:"workflow_id"`
	ActionID     string        `json:"action_id"`
	Status       ApprovalStatus `json:"status"`
	CreatedAt    time.Time     `json:"created_at"`
	ExpiresAt    *time.Time    `json:"expires_at,omitempty"`
	Approvers    []string      `json:"approvers"`
	MinApprovals int           `json:"min_approvals"`
	Approvals    []Approval    `json:"approvals,omitempty"`
	DriftID      string        `json:"drift_id"`
	ResourceID   string        `json:"resource_id"`
}

type ApprovalStatus string

const (
	ApprovalStatusPending  ApprovalStatus = "pending"
	ApprovalStatusApproved ApprovalStatus = "approved"
	ApprovalStatusRejected ApprovalStatus = "rejected"
	ApprovalStatusExpired  ApprovalStatus = "expired"
)

type Approval struct {
	ApproverID  string    `json:"approver_id"`
	ApprovedAt  time.Time `json:"approved_at"`
	Comment     string    `json:"comment,omitempty"`
}

// Approval handlers
func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters for filtering
	var workflowID, actionID, resourceID string
	var status database.ApprovalStatus
	
	if r.URL.Query().Get("workflow_id") != "" {
		workflowID = r.URL.Query().Get("workflow_id")
	}
	if r.URL.Query().Get("action_id") != "" {
		actionID = r.URL.Query().Get("action_id")
	}
	if r.URL.Query().Get("resource_id") != "" {
		resourceID = r.URL.Query().Get("resource_id")
	}
	if r.URL.Query().Get("status") != "" {
		status = database.ApprovalStatus(r.URL.Query().Get("status"))
	}
	
	// Get approvals from database
	// In a real implementation, this would filter based on params
	approvals, err := s.db.GetApprovalRequests(workflowID, actionID, resourceID, status)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to list approval requests", err)
		return
	}
	
	writeSuccessResponse(w, fmt.Sprintf("Retrieved %d approval requests", len(approvals)), approvals)
}

func (s *Server) handleGetApproval(w http.ResponseWriter, r *http.Request) {
	// Get approval ID from URL
	approvalID := chi.URLParam(r, "id")
	
	// Get approval from database
	approval, err := s.db.GetApprovalRequest(approvalID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Approval request not found", err)
		return
	}
	
	writeSuccessResponse(w, "Approval request retrieved successfully", approval)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	// Get approval ID from URL
	approvalID := chi.URLParam(r, "id")
	
	// Get approval request
	approval, err := s.db.GetApprovalRequest(approvalID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Approval request not found", err)
		return
	}
	
	// Parse request body
	var approveRequest struct {
		ApproverID string `json:"approver_id"`
		Comment    string `json:"comment,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&approveRequest); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Verify approver is authorized
	authorized := false
	for _, approver := range approval.Approvers {
		if approver == approveRequest.ApproverID {
			authorized = true
			break
		}
	}
	
	if !authorized {
		writeErrorResponse(w, http.StatusForbidden, "Not authorized to approve this request", nil)
		return
	}
	
	// Check if already approved by this approver
	for _, a := range approval.Approvals {
		if a.ApproverID == approveRequest.ApproverID {
			writeErrorResponse(w, http.StatusBadRequest, "Already approved by this approver", nil)
			return
		}
	}
	
	// Add approval
	approval.Approvals = append(approval.Approvals, database.Approval{
		ApproverID:  approveRequest.ApproverID,
		ApprovedAt:  time.Now(),
		Comment:     approveRequest.Comment,
	})
	
	// Check if we have enough approvals
	if len(approval.Approvals) >= approval.MinApprovals {
		approval.Status = database.ApprovalStatusApproved
	}
	
	// Update approval in database
	if err := s.db.UpdateApprovalRequest(approval); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to update approval request", err)
		return
	}
	
	writeSuccessResponse(w, "Approval request approved", approval)
}

func (s *Server) handleReject(w http.ResponseWriter, r *http.Request) {
	// Get approval ID from URL
	approvalID := chi.URLParam(r, "id")
	
	// Get approval request
	approval, err := s.db.GetApprovalRequest(approvalID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "Approval request not found", err)
		return
	}
	
	// Parse request body
	var rejectRequest struct {
		ApproverID string `json:"approver_id"`
		Reason     string `json:"reason,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&rejectRequest); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Verify approver is authorized
	authorized := false
	for _, approver := range approval.Approvers {
		if approver == rejectRequest.ApproverID {
			authorized = true
			break
		}
	}
	
	if !authorized {
		writeErrorResponse(w, http.StatusForbidden, "Not authorized to reject this request", nil)
		return
	}
	
	// Reject the approval
	approval.Status = database.ApprovalStatusRejected
	
	// Update approval in database
	if err := s.db.UpdateApprovalRequest(approval); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to update approval request", err)
		return
	}
	
	writeSuccessResponse(w, "Approval request rejected", approval)
}