package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/collector/aws"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/collector/azure"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/engine/collector/gcp"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
)

// StateCollector orchestrates the collection of actual infrastructure state
type StateCollector struct {
	db       *database.DB
	providers map[models.ProviderType]Provider
}

// Provider is the interface for provider-specific state collectors
type Provider interface {
	CollectState(ctx context.Context, resource *models.Resource) (*models.ResourceState, error)
	ListResources(ctx context.Context, filter models.ResourceFilter) ([]*models.Resource, error)
}

// New creates a new state collector
func New(db *database.DB) *StateCollector {
	sc := &StateCollector{
		db:       db,
		providers: make(map[models.ProviderType]Provider),
	}

	// Register providers
	sc.providers[models.ProviderAWS] = aws.NewProvider(db)
	sc.providers[models.ProviderAzure] = azure.NewProvider(db)
	sc.providers[models.ProviderGCP] = gcp.NewProvider(db)
	
	return sc
}

// RegisterProvider registers a new provider
func (c *StateCollector) RegisterProvider(providerType models.ProviderType, provider Provider) {
	c.providers[providerType] = provider
}

// CollectState collects the current state of a resource from its provider
func (c *StateCollector) CollectState(ctx context.Context, resource *models.Resource) (*models.ResourceState, error) {
	provider, exists := c.providers[resource.Provider]
	if !exists {
		return nil, fmt.Errorf("unsupported provider: %s", resource.Provider)
	}

	// Collect the resource state from the provider
	state, err := provider.CollectState(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("failed to collect state: %w", err)
	}

	// Save the state to the database
	if err := c.db.SaveResourceState(state); err != nil {
		return nil, fmt.Errorf("failed to save resource state: %w", err)
	}

	return state, nil
}

// DiscoverResources discovers resources from providers
func (c *StateCollector) DiscoverResources(ctx context.Context, filter models.ResourceFilter) ([]*models.Resource, error) {
	var allResources []*models.Resource

	// If a specific provider is specified, only use that provider
	if filter.Provider != "" {
		provider, exists := c.providers[filter.Provider]
		if !exists {
			return nil, fmt.Errorf("unsupported provider: %s", filter.Provider)
		}

		resources, err := provider.ListResources(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("failed to list resources for provider %s: %w", filter.Provider, err)
		}
		allResources = append(allResources, resources...)
	} else {
		// Otherwise, discover from all registered providers
		for providerType, provider := range c.providers {
			providerFilter := filter
			providerFilter.Provider = providerType

			resources, err := provider.ListResources(ctx, providerFilter)
			if err != nil {
				return nil, fmt.Errorf("failed to list resources for provider %s: %w", providerType, err)
			}
			allResources = append(allResources, resources...)
		}
	}

	// Save discovered resources to the database
	for _, resource := range allResources {
		// Check if resource already exists
		existing, err := c.db.GetResource(resource.ID)
		if err == nil && existing != nil {
			// Update existing resource
			resource.CreatedAt = existing.CreatedAt
			resource.UpdatedAt = time.Now()
			if err := c.db.UpdateResource(resource); err != nil {
				return nil, fmt.Errorf("failed to update resource %s: %w", resource.ID, err)
			}
		} else {
			// Create new resource
			resource.CreatedAt = time.Now()
			resource.UpdatedAt = time.Now()
			if err := c.db.CreateResource(resource); err != nil {
				return nil, fmt.Errorf("failed to create resource %s: %w", resource.ID, err)
			}
		}
	}

	return allResources, nil
}