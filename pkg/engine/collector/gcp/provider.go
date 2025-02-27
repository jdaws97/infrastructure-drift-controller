package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/google/uuid"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
)

// Provider implements the provider interface for GCP
type Provider struct {
	db         *database.DB
	projects   []string
	credential *google.Credentials
}

// NewProvider creates a new GCP provider
func NewProvider(db *database.DB) *Provider {
	return &Provider{
		db: db,
	}
}

// Initialize sets up the GCP credentials and target projects
func (p *Provider) Initialize(projects []string) error {
	// Get default credentials
	cred, err := google.FindDefaultCredentials(context.Background(), 
		compute.CloudPlatformScope,
		storage.CloudPlatformScope)
	if err != nil {
		return fmt.Errorf("failed to get GCP credentials: %w", err)
	}
	
	p.credential = cred
	p.projects = projects
	
	return nil
}

// CollectState collects the current state of a GCP resource
func (p *Provider) CollectState(ctx context.Context, resource *models.Resource) (*models.ResourceState, error) {
	// Determine the resource type and collect appropriate state
	var properties models.Properties
	var err error
	var stateSource models.StateSource = models.StateSourceGCP

	switch resource.Type {
	case models.ResourceTypeGCPInstance:
		properties, err = p.collectComputeInstanceState(ctx, resource)
	case "gcp_storage_bucket":
		properties, err = p.collectStorageBucketState(ctx, resource)
	case "gcp_network":
		properties, err = p.collectNetworkState(ctx, resource)
	case "gcp_firewall":
		properties, err = p.collectFirewallState(ctx, resource)
	default:
		return nil, fmt.Errorf("unsupported GCP resource type: %s", resource.Type)
	}

	if err != nil {
		return nil, err
	}

	// Create and return the resource state
	state := &models.ResourceState{
		ResourceID:   resource.ID,
		StateType:    models.StateTypeActual,
		Properties:   properties,
		CapturedAt:   time.Now(),
		StateVersion: uuid.New().String(),
		Source:       stateSource,
	}

	return state, nil
}

// ListResources discovers GCP resources based on the filter
func (p *Provider) ListResources(ctx context.Context, filter models.ResourceFilter) ([]*models.Resource, error) {
	var resources []*models.Resource

	// Determine which project(s) to scan
	projects := p.projects
	
	// If a specific project is provided in the filter, use only that one
	if filter.Project != "" {
		// Check if the requested project is in our allowed list
		found := false
		for _, proj := range p.projects {
			if proj == filter.Project {
				found = true
				break
			}
		}
		
		if !found {
			return nil, fmt.Errorf("project %s not authorized", filter.Project)
		}
		
		projects = []string{filter.Project}
	}
	
	// Scan each project
	for _, projectID := range projects {
		// Discover resources based on filter.Types
		// If no specific types are requested, discover all supported types
		resourceTypes := []string{
			string(models.ResourceTypeGCPInstance),
			"gcp_storage_bucket",
			"gcp_network",
			"gcp_firewall",
		}
		
		if len(filter.Types) > 0 {
			// Convert filter.Types to string array
			resourceTypes = make([]string, 0, len(filter.Types))
			for _, t := range filter.Types {
				resourceTypes = append(resourceTypes, string(t))
			}
		}
		
		// Discover resources for each type
		for _, resourceType := range resourceTypes {
			var typeResources []*models.Resource
			var err error
			
			switch resourceType {
			case string(models.ResourceTypeGCPInstance):
				typeResources, err = p.discoverComputeInstances(ctx, projectID, filter)
			case "gcp_storage_bucket":
				typeResources, err = p.discoverStorageBuckets(ctx, projectID, filter)
			case "gcp_network":
				typeResources, err = p.discoverNetworks(ctx, projectID, filter)
			case "gcp_firewall":
				typeResources, err = p.discoverFirewalls(ctx, projectID, filter)
			default:
				continue // Skip unsupported types
			}
			
			if err != nil {
				return nil, fmt.Errorf("error discovering %s resources in project %s: %w", resourceType, projectID, err)
			}
			
			resources = append(resources, typeResources...)
		}
	}

	return resources, nil
}

// discoverFirewalls discovers GCP firewall rules
func (p *Provider) discoverFirewalls(ctx context.Context, projectID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create compute service client
	computeService, err := compute.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service client: %w", err)
	}
	
	var resources []*models.Resource
	
	// List firewalls in the project
	firewalls, err := computeService.Firewalls.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list firewalls in project %s: %w", projectID, err)
	}
	
	for _, firewall := range firewalls.Items {
		// Create resource from firewall
		resource := &models.Resource{
			ID:       fmt.Sprintf("%d", firewall.Id),
			Name:     firewall.Name,
			Type:     "gcp_firewall",
			Provider: models.ProviderGCP,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
			Project:  projectID,
			Tags:     make(models.Tags),
		}
		
		// Firewalls are global resources
		resource.Region = "global"
		
		// Add some firewall attributes as tags for filtering
		resource.Tags["network"] = getShortNetworkName(firewall.Network)
		resource.Tags["direction"] = firewall.Direction
		
		if firewall.Disabled {
			resource.Tags["disabled"] = "true"
		} else {
			resource.Tags["disabled"] = "false"
		}
		
		// Add priority as tag
		if firewall.Priority != 0 {
			resource.Tags["priority"] = fmt.Sprintf("%d", firewall.Priority)
		}
		
		// Apply tag filter if specified
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
		
		resources = append(resources, resource)
	}
	
	return resources, nil
}

// Helper functions

// getZone extracts the zone from a resource
func getZone(resource *models.Resource) string {
	// Extract from resource Region (which stores the zone for GCP compute instances)
	if resource.Region != "" {
		// If it's already a full zone URL, extract the name
		if strings.Contains(resource.Region, "/") {
			parts := strings.Split(resource.Region, "/")
			return parts[len(parts)-1]
		}
		return resource.Region
	}
	
	// Try to extract from ID which might contain zone information
	if strings.Contains(resource.ID, "zones/") {
		parts := strings.Split(resource.ID, "/")
		for i, part := range parts {
			if part == "zones" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	
	// Try to get from metadata
	// In a real implementation, you might have zone information in metadata
	
	return ""
}

// getShortMachineType extracts the machine type name from URL
func getShortMachineType(machineTypeURL string) string {
	parts := strings.Split(machineTypeURL, "/")
	return parts[len(parts)-1]
}

// getShortZone extracts the zone name from URL
func getShortZone(zoneURL string) string {
	parts := strings.Split(zoneURL, "/")
	return parts[len(parts)-1]
}

// getShortNetworkName extracts the network name from URL
func getShortNetworkName(networkURL string) string {
	parts := strings.Split(networkURL, "/")
	return parts[len(parts)-1]
}

// getShortSubnetworkName extracts the subnetwork name from URL
func getShortSubnetworkName(subnetworkURL string) string {
	parts := strings.Split(subnetworkURL, "/")
	return parts[len(parts)-1]
}

// getShortRegionName extracts the region name from URL
func getShortRegionName(regionURL string) string {
	parts := strings.Split(regionURL, "/")
	return parts[len(parts)-1]
}

// getShortDiskName extracts the disk name from URL
func getShortDiskName(diskURL string) string {
	parts := strings.Split(diskURL, "/")
	return parts[len(parts)-1]
}

// collectComputeInstanceState collects the state of a GCP Compute Engine instance
func (p *Provider) collectComputeInstanceState(ctx context.Context, resource *models.Resource) (models.Properties, error) {
	// Extract resource details
	projectID := resource.Project
	zone := getZone(resource)
	instanceName := resource.Name
	
	// Create compute service client
	computeService, err := compute.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service client: %w", err)
	}
	
	// Get instance details
	instance, err := computeService.Instances.Get(projectID, zone, instanceName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get instance details: %w", err)
	}
	
	// Build properties map
	properties := models.Properties{
		"id":            instance.Id,
		"name":          instance.Name,
		"machine_type":  getShortMachineType(instance.MachineType),
		"zone":          getShortZone(instance.Zone),
		"status":        instance.Status,
		"creation_timestamp": instance.CreationTimestamp,
	}
	
	// Add network interfaces
	if len(instance.NetworkInterfaces) > 0 {
		networkInterfaces := make([]map[string]interface{}, 0, len(instance.NetworkInterfaces))
		
		for _, ni := range instance.NetworkInterfaces {
			niMap := map[string]interface{}{
				"name":       ni.Name,
				"network":    getShortNetworkName(ni.Network),
				"subnetwork": getShortNetworkName(ni.Subnetwork),
				"network_ip": ni.NetworkIP,
			}
			
			// Add access configs (public IPs)
			if len(ni.AccessConfigs) > 0 {
				accessConfigs := make([]map[string]interface{}, 0, len(ni.AccessConfigs))
				
				for _, ac := range ni.AccessConfigs {
					accessConfigs = append(accessConfigs, map[string]interface{}{
						"type":        ac.Type,
						"name":        ac.Name,
						"nat_ip":      ac.NatIP,
						"external_ip": ac.ExternalIp,
					})
				}
				
				niMap["access_configs"] = accessConfigs
			}
			
			networkInterfaces = append(networkInterfaces, niMap)
		}
		
		properties["network_interfaces"] = networkInterfaces
	}
	
	// Add disks
	if len(instance.Disks) > 0 {
		disks := make([]map[string]interface{}, 0, len(instance.Disks))
		
		for _, disk := range instance.Disks {
			diskMap := map[string]interface{}{
				"auto_delete": disk.AutoDelete,
				"boot":        disk.Boot,
				"device_name": disk.DeviceName,
				"source":      getShortDiskName(disk.Source),
				"mode":        disk.Mode,
				"type":        disk.Type,
			}
			
			disks = append(disks, diskMap)
		}
		
		properties["disks"] = disks
	}
	
	// Add service accounts
	if len(instance.ServiceAccounts) > 0 {
		serviceAccounts := make([]map[string]interface{}, 0, len(instance.ServiceAccounts))
		
		for _, sa := range instance.ServiceAccounts {
			serviceAccounts = append(serviceAccounts, map[string]interface{}{
				"email":  sa.Email,
				"scopes": sa.Scopes,
			})
		}
		
		properties["service_accounts"] = serviceAccounts
	}
	
	// Add scheduling
	if instance.Scheduling != nil {
		properties["scheduling"] = map[string]interface{}{
			"automatic_restart":   instance.Scheduling.AutomaticRestart,
			"on_host_maintenance": instance.Scheduling.OnHostMaintenance,
			"preemptible":         instance.Scheduling.Preemptible,
		}
	}
	
	// Add tags
	if instance.Labels != nil {
		properties["labels"] = instance.Labels
	}
	
	// Add network tags
	if instance.Tags != nil && len(instance.Tags.Items) > 0 {
		properties["network_tags"] = instance.Tags.Items
	}
	
	// Add metadata
	if instance.Metadata != nil && len(instance.Metadata.Items) > 0 {
		metadata := make(map[string]string)
		
		for _, item := range instance.Metadata.Items {
			if item.Key != "" && item.Value != nil {
				metadata[item.Key] = *item.Value
			}
		}
		
		properties["metadata"] = metadata
	}
	
	return properties, nil
}

// collectStorageBucketState collects the state of a GCP Storage bucket
func (p *Provider) collectStorageBucketState(ctx context.Context, resource *models.Resource) (models.Properties, error) {
	// Extract resource details
	projectID := resource.Project
	bucketName := resource.Name
	
	// Create storage service client
	storageService, err := storage.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Storage service client: %w", err)
	}
	
	// Get bucket details
	bucket, err := storageService.Buckets.Get(bucketName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get bucket details: %w", err)
	}
	
	// Build properties map
	properties := models.Properties{
		"id":                bucket.Id,
		"name":              bucket.Name,
		"location":          bucket.Location,
		"location_type":     bucket.LocationType,
		"storage_class":     bucket.StorageClass,
		"time_created":      bucket.TimeCreated,
		"project_number":    bucket.ProjectNumber,
	}
	
	// Add bucket ACL if available
	if bucket.Acl != nil {
		acls := make([]map[string]interface{}, 0, len(bucket.Acl))
		
		for _, acl := range bucket.Acl {
			acls = append(acls, map[string]interface{}{
				"entity": acl.Entity,
				"role":   acl.Role,
			})
		}
		
		properties["acl"] = acls
	}
	
	// Add default object ACL if available
	if bucket.DefaultObjectAcl != nil {
		defaultObjectAcl := make([]map[string]interface{}, 0, len(bucket.DefaultObjectAcl))
		
		for _, acl := range bucket.DefaultObjectAcl {
			defaultObjectAcl = append(defaultObjectAcl, map[string]interface{}{
				"entity": acl.Entity,
				"role":   acl.Role,
			})
		}
		
		properties["default_object_acl"] = defaultObjectAcl
	}
	
	// Add lifecycle configuration if available
	if bucket.Lifecycle != nil && bucket.Lifecycle.Rule != nil {
		lifecycleRules := make([]map[string]interface{}, 0, len(bucket.Lifecycle.Rule))
		
		for _, rule := range bucket.Lifecycle.Rule {
			ruleMap := map[string]interface{}{
				"action": map[string]interface{}{
					"type":          rule.Action.Type,
					"storage_class": rule.Action.StorageClass,
				},
			}
			
			// Add condition if available
			if rule.Condition != nil {
				conditionMap := map[string]interface{}{}
				
				if rule.Condition.Age != nil {
					conditionMap["age"] = *rule.Condition.Age
				}
				
				if rule.Condition.CreatedBefore != "" {
					conditionMap["created_before"] = rule.Condition.CreatedBefore
				}
				
				if rule.Condition.NumNewerVersions != nil {
					conditionMap["num_newer_versions"] = *rule.Condition.NumNewerVersions
				}
				
				if rule.Condition.IsLive != nil {
					conditionMap["is_live"] = *rule.Condition.IsLive
				}
				
				if len(rule.Condition.MatchesStorageClass) > 0 {
					conditionMap["matches_storage_class"] = rule.Condition.MatchesStorageClass
				}
				
				ruleMap["condition"] = conditionMap
			}
			
			lifecycleRules = append(lifecycleRules, ruleMap)
		}
		
		properties["lifecycle_rules"] = lifecycleRules
	}
	
	// Add versioning if available
	if bucket.Versioning != nil {
		properties["versioning_enabled"] = bucket.Versioning.Enabled
	}
	
	// Add CORS configuration if available
	if bucket.Cors != nil && len(bucket.Cors) > 0 {
		cors := make([]map[string]interface{}, 0, len(bucket.Cors))
		
		for _, corsConfig := range bucket.Cors {
			cors = append(cors, map[string]interface{}{
				"max_age_seconds":  corsConfig.MaxAgeSeconds,
				"method":           corsConfig.Method,
				"origin":           corsConfig.Origin,
				"response_header":  corsConfig.ResponseHeader,
			})
		}
		
		properties["cors"] = cors
	}
	
	// Add encryption if available
	if bucket.Encryption != nil && bucket.Encryption.DefaultKmsKeyName != "" {
		properties["encryption"] = map[string]interface{}{
			"default_kms_key_name": bucket.Encryption.DefaultKmsKeyName,
		}
	}
	
	// Add labels
	if bucket.Labels != nil {
		properties["labels"] = bucket.Labels
	}
	
	return properties, nil
}

// collectNetworkState collects the state of a GCP network
func (p *Provider) collectNetworkState(ctx context.Context, resource *models.Resource) (models.Properties, error) {
	// Extract resource details
	projectID := resource.Project
	networkName := resource.Name
	
	// Create compute service client
	computeService, err := compute.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service client: %w", err)
	}
	
	// Get network details
	network, err := computeService.Networks.Get(projectID, networkName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get network details: %w", err)
	}
	
	// Build properties map
	properties := models.Properties{
		"id":                    network.Id,
		"name":                  network.Name,
		"description":           network.Description,
		"auto_create_subnetworks": network.AutoCreateSubnetworks,
		"creation_timestamp":    network.CreationTimestamp,
		"routing_mode":          network.RoutingConfig.RoutingMode,
	}
	
	// Add subnets
	if len(network.Subnetworks) > 0 {
		subnetworks := make([]string, 0, len(network.Subnetworks))
		
		for _, subnet := range network.Subnetworks {
			subnetworks = append(subnetworks, getShortSubnetworkName(subnet))
		}
		
		properties["subnetworks"] = subnetworks
		
		// Fetch detailed subnet information
		subnetDetails := make([]map[string]interface{}, 0, len(network.Subnetworks))
		
		for _, subnet := range network.Subnetworks {
			// Extract region and subnet name from URL
			parts := strings.Split(subnet, "/")
			if len(parts) < 2 {
				continue
			}
			
			regionIdx := -1
			for i, part := range parts {
				if part == "regions" && i+1 < len(parts) {
					regionIdx = i + 1
					break
				}
			}
			
			if regionIdx == -1 || regionIdx+2 >= len(parts) {
				continue
			}
			
			region := parts[regionIdx]
			subnetName := parts[len(parts)-1]
			
			// Get subnet details
			subnetDetail, err := computeService.Subnetworks.Get(projectID, region, subnetName).Do()
			if err != nil {
				continue
			}
			
			subnetDetails = append(subnetDetails, map[string]interface{}{
				"name":                subnetDetail.Name,
				"region":              getShortRegionName(subnetDetail.Region),
				"ip_cidr_range":       subnetDetail.IpCidrRange,
				"private_ip_google_access": subnetDetail.PrivateIpGoogleAccess,
				"purpose":             subnetDetail.Purpose,
				"network":             getShortNetworkName(subnetDetail.Network),
			})
		}
		
		properties["subnet_details"] = subnetDetails
	}
	
	// Get peering connections
	if network.Peerings != nil && len(network.Peerings) > 0 {
		peerings := make([]map[string]interface{}, 0, len(network.Peerings))
		
		for _, peering := range network.Peerings {
			peeringMap := map[string]interface{}{
				"name":                       peering.Name,
				"network":                    peering.Network,
				"state":                      peering.State,
				"auto_create_routes":         peering.AutoCreateRoutes,
				"exchange_subnet_routes":     peering.ExchangeSubnetRoutes,
				"export_custom_routes":       peering.ExportCustomRoutes,
				"import_custom_routes":       peering.ImportCustomRoutes,
				"export_subnet_routes_with_public_ip": peering.ExportSubnetRoutesWithPublicIp,
				"import_subnet_routes_with_public_ip": peering.ImportSubnetRoutesWithPublicIp,
			}
			
			peerings = append(peerings, peeringMap)
		}
		
		properties["peerings"] = peerings
	}
	
	return properties, nil
}

// collectFirewallState collects the state of a GCP firewall rule
func (p *Provider) collectFirewallState(ctx context.Context, resource *models.Resource) (models.Properties, error) {
	// Extract resource details
	projectID := resource.Project
	firewallName := resource.Name
	
	// Create compute service client
	computeService, err := compute.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service client: %w", err)
	}
	
	// Get firewall details
	firewall, err := computeService.Firewalls.Get(projectID, firewallName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get firewall details: %w", err)
	}
	
	// Build properties map
	properties := models.Properties{
		"id":                 firewall.Id,
		"name":               firewall.Name,
		"description":        firewall.Description,
		"network":            getShortNetworkName(firewall.Network),
		"priority":           firewall.Priority,
		"direction":          firewall.Direction,
		"disabled":           firewall.Disabled,
		"creation_timestamp": firewall.CreationTimestamp,
	}
	
	// Add source ranges
	if firewall.SourceRanges != nil && len(firewall.SourceRanges) > 0 {
		properties["source_ranges"] = firewall.SourceRanges
	}
	
	// Add destination ranges
	if firewall.DestinationRanges != nil && len(firewall.DestinationRanges) > 0 {
		properties["destination_ranges"] = firewall.DestinationRanges
	}
	
	// Add source tags
	if firewall.SourceTags != nil && len(firewall.SourceTags) > 0 {
		properties["source_tags"] = firewall.SourceTags
	}
	
	// Add target tags
	if firewall.TargetTags != nil && len(firewall.TargetTags) > 0 {
		properties["target_tags"] = firewall.TargetTags
	}
	
	// Add source service accounts
	if firewall.SourceServiceAccounts != nil && len(firewall.SourceServiceAccounts) > 0 {
		properties["source_service_accounts"] = firewall.SourceServiceAccounts
	}
	
	// Add target service accounts
	if firewall.TargetServiceAccounts != nil && len(firewall.TargetServiceAccounts) > 0 {
		properties["target_service_accounts"] = firewall.TargetServiceAccounts
	}
	
	// Add allowed rules
	if firewall.Allowed != nil && len(firewall.Allowed) > 0 {
		allowed := make([]map[string]interface{}, 0, len(firewall.Allowed))
		
		for _, rule := range firewall.Allowed {
			allowed = append(allowed, map[string]interface{}{
				"ip_protocol": rule.IPProtocol,
				"ports":       rule.Ports,
			})
		}
		
		properties["allowed"] = allowed
	}
	
	// Add denied rules
	if firewall.Denied != nil && len(firewall.Denied) > 0 {
		denied := make([]map[string]interface{}, 0, len(firewall.Denied))
		
		for _, rule := range firewall.Denied {
			denied = append(denied, map[string]interface{}{
				"ip_protocol": rule.IPProtocol,
				"ports":       rule.Ports,
			})
		}
		
		properties["denied"] = denied
	}
	
	// Add log config
	if firewall.LogConfig != nil {
		properties["log_config"] = map[string]interface{}{
			"enable": firewall.LogConfig.Enable,
		}
	}
	
	return properties, nil
}

// discoverComputeInstances discovers GCP Compute Engine instances
func (p *Provider) discoverComputeInstances(ctx context.Context, projectID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create compute service client
	computeService, err := compute.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service client: %w", err)
	}
	
	var resources []*models.Resource
	
	// If zone is specified, list instances in that zone
	if filter.Region != "" {
		// In GCP, regions contain zones, so we need to get all zones in the region
		regionName := filter.Region
		if !strings.Contains(regionName, "/") {
			regionName = fmt.Sprintf("regions/%s", regionName)
		}
		
		// List zones in the region
		zoneList, err := computeService.Zones.List(projectID).Filter(fmt.Sprintf("region=%s", regionName)).Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list zones in region %s: %w", regionName, err)
		}
		
		// For each zone, list instances
		for _, zone := range zoneList.Items {
			instances, err := computeService.Instances.List(projectID, zone.Name).Do()
			if err != nil {
				return nil, fmt.Errorf("failed to list instances in zone %s: %w", zone.Name, err)
			}
			
			for _, instance := range instances.Items {
				// Create resource from instance
				resource := &models.Resource{
					ID:       fmt.Sprintf("%d", instance.Id),
					Name:     instance.Name,
					Type:     models.ResourceTypeGCPInstance,
					Provider: models.ProviderGCP,
					IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
					Region:   getShortZone(instance.Zone),
					Project:  projectID,
					Tags:     make(models.Tags),
				}
				
				// Add labels as tags
				if instance.Labels != nil {
					for k, v := range instance.Labels {
						resource.Tags[k] = v
					}
				}
				
				// Apply tag filter if specified
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
				
				resources = append(resources, resource)
			}
		}
	} else {
		// List instances across all zones
		// We need to list zones first
		zoneList, err := computeService.Zones.List(projectID).Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list zones: %w", err)
		}
		
		for _, zone := range zoneList.Items {
			instances, err := computeService.Instances.List(projectID, zone.Name).Do()
			if err != nil {
				return nil, fmt.Errorf("failed to list instances in zone %s: %w", zone.Name, err)
			}
			
			for _, instance := range instances.Items {
				// Create resource from instance
				resource := &models.Resource{
					ID:       fmt.Sprintf("%d", instance.Id),
					Name:     instance.Name,
					Type:     models.ResourceTypeGCPInstance,
					Provider: models.ProviderGCP,
					IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
					Region:   getShortZone(instance.Zone),
					Project:  projectID,
					Tags:     make(models.Tags),
				}
				
				// Add labels as tags
				if instance.Labels != nil {
					for k, v := range instance.Labels {
						resource.Tags[k] = v
					}
				}
				
				// Apply tag filter if specified
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
				
				// Apply region filter if specified
				if filter.Region != "" && !strings.Contains(resource.Region, filter.Region) {
					continue
				}
				
				resources = append(resources, resource)
			}
		}
	}
	
	return resources, nil
}

// discoverStorageBuckets discovers GCP Storage buckets
func (p *Provider) discoverStorageBuckets(ctx context.Context, projectID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create storage service client
	storageService, err := storage.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Storage service client: %w", err)
	}
	
	var resources []*models.Resource
	
	// List buckets in the project
	buckets, err := storageService.Buckets.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets in project %s: %w", projectID, err)
	}
	
	for _, bucket := range buckets.Items {
		// Create resource from bucket
		resource := &models.Resource{
			ID:       bucket.Id,
			Name:     bucket.Name,
			Type:     "gcp_storage_bucket",
			Provider: models.ProviderGCP,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
			Region:   bucket.Location,
			Project:  projectID,
			Tags:     make(models.Tags),
		}
		
		// Add labels as tags
		if bucket.Labels != nil {
			for k, v := range bucket.Labels {
				resource.Tags[k] = v
			}
		}
		
		// Apply tag filter if specified
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
		
		// Apply region filter if specified
		if filter.Region != "" && bucket.Location != filter.Region {
			continue
		}
		
		resources = append(resources, resource)
	}
	
	return resources, nil
}

// discoverNetworks discovers GCP networks
func (p *Provider) discoverNetworks(ctx context.Context, projectID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create compute service client
	computeService, err := compute.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service client: %w", err)
	}
	
	var resources []*models.Resource
	
	// List networks in the project
	networks, err := computeService.Networks.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list networks in project %s: %w", projectID, err)