package gcp

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/bigquery/v2"
	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/pubsub/v1"
	"google.golang.org/api/sqladmin/v1"
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

	// If no projects are configured, return an empty list
	if len(projects) == 0 {
		log.Printf("No GCP projects configured, skipping resource discovery")
		return resources, nil
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
			"gcp_sql_instance",
			"gcp_pubsub_topic",
			"gcp_cloudfunctions_function",
			"gcp_container_cluster",
			"gcp_bigquery_dataset",
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
			case "gcp_sql_instance":
				typeResources, err = p.discoverDatabaseInstances(ctx, projectID, filter)
			case "gcp_pubsub_topic":
				typeResources, err = p.discoverPubSubTopics(ctx, projectID, filter)
			case "gcp_cloudfunctions_function":
				typeResources, err = p.discoverCloudFunctions(ctx, projectID, filter)
			case "gcp_container_cluster":
				typeResources, err = p.discoverGKEClusters(ctx, projectID, filter)
			case "gcp_bigquery_dataset":
				typeResources, err = p.discoverBigQueryDatasets(ctx, projectID, filter)
			default:
				continue // Skip unsupported types
			}

			if err != nil {
				log.Printf("Error discovering %s resources in project %s: %v", resourceType, projectID, err)
				continue // Continue with other resource types despite errors
			}

			resources = append(resources, typeResources...)
		}
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

	return ""
}

// getShortMachineType extracts the machine type name from URL
func getShortMachineType(machineTypeURL string) string {
	if machineTypeURL == "" {
		return ""
	}
	parts := strings.Split(machineTypeURL, "/")
	return parts[len(parts)-1]
}

// getShortZone extracts the zone name from URL
func getShortZone(zoneURL string) string {
	if zoneURL == "" {
		return ""
	}
	parts := strings.Split(zoneURL, "/")
	return parts[len(parts)-1]
}

// getShortNetworkName extracts the network name from URL
func getShortNetworkName(networkURL string) string {
	if networkURL == "" {
		return ""
	}
	parts := strings.Split(networkURL, "/")
	return parts[len(parts)-1]
}

// getShortSubnetworkName extracts the subnetwork name from URL
func getShortSubnetworkName(subnetworkURL string) string {
	if subnetworkURL == "" {
		return ""
	}
	parts := strings.Split(subnetworkURL, "/")
	return parts[len(parts)-1]
}

// getShortRegionName extracts the region name from URL
func getShortRegionName(regionURL string) string {
	if regionURL == "" {
		return ""
	}
	parts := strings.Split(regionURL, "/")
	return parts[len(parts)-1]
}

// getShortDiskName extracts the disk name from URL
func getShortDiskName(diskURL string) string {
	if diskURL == "" {
		return ""
	}
	parts := strings.Split(diskURL, "/")
	return parts[len(parts)-1]
}

// collectComputeInstanceState collects the state of a GCP Compute Engine instance
func (p *Provider) collectComputeInstanceState(ctx context.Context, resource *models.Resource) (models.Properties, error) {
	// Extract resource details
	projectID := resource.Project
	zone := getZone(resource)
	instanceName := resource.Name

	if projectID == "" {
		return nil, fmt.Errorf("project ID is required for GCP resources")
	}

	if zone == "" {
		return nil, fmt.Errorf("zone is required for GCP compute instances")
	}

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
		"id":           fmt.Sprintf("%d", instance.Id),
		"name":         instance.Name,
		"machine_type": getShortMachineType(instance.MachineType),
		"zone":         getShortZone(instance.Zone),
		"status":       instance.Status,
	}

	if instance.CreationTimestamp != "" {
		properties["creation_timestamp"] = instance.CreationTimestamp
	}

	// Add network interfaces
	if len(instance.NetworkInterfaces) > 0 {
		networkInterfaces := make([]map[string]interface{}, 0, len(instance.NetworkInterfaces))

		for _, ni := range instance.NetworkInterfaces {
			niMap := map[string]interface{}{
				"name":       ni.Name,
				"network":    getShortNetworkName(ni.Network),
				"network_ip": ni.NetworkIP,
			}

			if ni.Subnetwork != "" {
				niMap["subnetwork"] = getShortSubnetworkName(ni.Subnetwork)
			}

			// Add access configs (public IPs)
			if len(ni.AccessConfigs) > 0 {
				accessConfigs := make([]map[string]interface{}, 0, len(ni.AccessConfigs))

				for _, ac := range ni.AccessConfigs {
					accessConfig := map[string]interface{}{
						"type": ac.Type,
						"name": ac.Name,
					}

					if ac.NatIP != "" {
						accessConfig["nat_ip"] = ac.NatIP
					}

					accessConfigs = append(accessConfigs, accessConfig)
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
				"mode":        disk.Mode,
				"type":        disk.Type,
			}

			if disk.Source != "" {
				diskMap["source"] = getShortDiskName(disk.Source)
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
		schedulingMap := map[string]interface{}{}

		if instance.Scheduling.AutomaticRestart != nil {
			schedulingMap["automatic_restart"] = *instance.Scheduling.AutomaticRestart
		}

		if instance.Scheduling.OnHostMaintenance != "" {
			schedulingMap["on_host_maintenance"] = instance.Scheduling.OnHostMaintenance
		}

		if instance.Scheduling.Preemptible {
			schedulingMap["preemptible"] = instance.Scheduling.Preemptible
		}

		properties["scheduling"] = schedulingMap
	}

	// Add labels
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

		if len(metadata) > 0 {
			properties["metadata"] = metadata
		}
	}

	return properties, nil
}

// collectStorageBucketState collects the state of a GCP Storage bucket
func (p *Provider) collectStorageBucketState(ctx context.Context, resource *models.Resource) (models.Properties, error) {
	// Extract resource details
	projectID := resource.Project
	bucketName := resource.Name

	if projectID == "" {
		return nil, fmt.Errorf("project ID is required for GCP resources")
	}

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
		"id":            bucket.Id,
		"name":          bucket.Name,
		"location":      bucket.Location,
		"storage_class": bucket.StorageClass,
	}

	if bucket.LocationType != "" {
		properties["location_type"] = bucket.LocationType
	}

	if bucket.TimeCreated != "" {
		properties["time_created"] = bucket.TimeCreated
	}

	if bucket.ProjectNumber > 0 {
		properties["project_number"] = bucket.ProjectNumber
	}

	// Add bucket ACL if available
	if bucket.Acl != nil && len(bucket.Acl) > 0 {
		acls := make([]map[string]interface{}, 0, len(bucket.Acl))

		for _, acl := range bucket.Acl {
			aclMap := map[string]interface{}{}

			if acl.Entity != "" {
				aclMap["entity"] = acl.Entity
			}

			if acl.Role != "" {
				aclMap["role"] = acl.Role
			}

			if len(aclMap) > 0 {
				acls = append(acls, aclMap)
			}
		}

		if len(acls) > 0 {
			properties["acl"] = acls
		}
	}

	// Add default object ACL if available
	if bucket.DefaultObjectAcl != nil && len(bucket.DefaultObjectAcl) > 0 {
		defaultObjectAcl := make([]map[string]interface{}, 0, len(bucket.DefaultObjectAcl))

		for _, acl := range bucket.DefaultObjectAcl {
			aclMap := map[string]interface{}{}

			if acl.Entity != "" {
				aclMap["entity"] = acl.Entity
			}

			if acl.Role != "" {
				aclMap["role"] = acl.Role
			}

			if len(aclMap) > 0 {
				defaultObjectAcl = append(defaultObjectAcl, aclMap)
			}
		}

		if len(defaultObjectAcl) > 0 {
			properties["default_object_acl"] = defaultObjectAcl
		}
	}

	// Add lifecycle configuration if available
	if bucket.Lifecycle != nil && bucket.Lifecycle.Rule != nil && len(bucket.Lifecycle.Rule) > 0 {
		lifecycleRules := make([]map[string]interface{}, 0, len(bucket.Lifecycle.Rule))

		for _, rule := range bucket.Lifecycle.Rule {
			ruleMap := map[string]interface{}{}

			if rule.Action != nil {
				actionMap := map[string]interface{}{}

				if rule.Action.Type != "" {
					actionMap["type"] = rule.Action.Type
				}

				if rule.Action.StorageClass != "" {
					actionMap["storage_class"] = rule.Action.StorageClass
				}

				if len(actionMap) > 0 {
					ruleMap["action"] = actionMap
				}
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

				if rule.Condition.NumNewerVersions != 0 {
					conditionMap["num_newer_versions"] = rule.Condition.NumNewerVersions
				}

				if rule.Condition.IsLive != nil {
					conditionMap["is_live"] = *rule.Condition.IsLive
				}

				if len(rule.Condition.MatchesStorageClass) > 0 {
					conditionMap["matches_storage_class"] = rule.Condition.MatchesStorageClass
				}

				if len(conditionMap) > 0 {
					ruleMap["condition"] = conditionMap
				}
			}

			if len(ruleMap) > 0 {
				lifecycleRules = append(lifecycleRules, ruleMap)
			}
		}

		if len(lifecycleRules) > 0 {
			properties["lifecycle_rules"] = lifecycleRules
		}
	}

	// Add versioning if available
	if bucket.Versioning != nil && bucket.Versioning.Enabled {
		properties["versioning_enabled"] = bucket.Versioning.Enabled
	}

	// Add CORS configuration if available
	if bucket.Cors != nil && len(bucket.Cors) > 0 {
		cors := make([]map[string]interface{}, 0, len(bucket.Cors))

		for _, corsConfig := range bucket.Cors {
			corsMap := map[string]interface{}{}

			if corsConfig.MaxAgeSeconds > 0 {
				corsMap["max_age_seconds"] = corsConfig.MaxAgeSeconds
			}

			if len(corsConfig.Method) > 0 {
				corsMap["method"] = corsConfig.Method
			}

			if len(corsConfig.Origin) > 0 {
				corsMap["origin"] = corsConfig.Origin
			}

			if len(corsConfig.ResponseHeader) > 0 {
				corsMap["response_header"] = corsConfig.ResponseHeader
			}

			if len(corsMap) > 0 {
				cors = append(cors, corsMap)
			}
		}

		if len(cors) > 0 {
			properties["cors"] = cors
		}
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

	if projectID == "" {
		return nil, fmt.Errorf("project ID is required for GCP resources")
	}

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
		"id":                      fmt.Sprintf("%d", network.Id),
		"name":                    network.Name,
		"auto_create_subnetworks": network.AutoCreateSubnetworks,
	}

	if network.Description != "" {
		properties["description"] = network.Description
	}

	if network.CreationTimestamp != "" {
		properties["creation_timestamp"] = network.CreationTimestamp
	}

	if network.RoutingConfig != nil && network.RoutingConfig.RoutingMode != "" {
		properties["routing_mode"] = network.RoutingConfig.RoutingMode
	}

	// Add subnets
	if len(network.Subnetworks) > 0 {
		subnetworks := make([]string, 0, len(network.Subnetworks))

		for _, subnet := range network.Subnetworks {
			if subnet != "" {
				subnetworks = append(subnetworks, getShortSubnetworkName(subnet))
			}
		}

		if len(subnetworks) > 0 {
			properties["subnetworks"] = subnetworks
		}

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
				log.Printf("Failed to get subnet details for %s: %v", subnetName, err)
				continue
			}

			subnetMap := map[string]interface{}{
				"name":   subnetDetail.Name,
				"region": getShortRegionName(subnetDetail.Region),
			}

			if subnetDetail.IpCidrRange != "" {
				subnetMap["ip_cidr_range"] = subnetDetail.IpCidrRange
			}

			if subnetDetail.Network != "" {
				subnetMap["network"] = getShortNetworkName(subnetDetail.Network)
			}

			subnetMap["private_ip_google_access"] = subnetDetail.PrivateIpGoogleAccess

			if subnetDetail.Purpose != "" {
				subnetMap["purpose"] = subnetDetail.Purpose
			}

			subnetDetails = append(subnetDetails, subnetMap)
		}

		if len(subnetDetails) > 0 {
			properties["subnet_details"] = subnetDetails
		}
	}

	// Get peering connections
	if network.Peerings != nil && len(network.Peerings) > 0 {
		peerings := make([]map[string]interface{}, 0, len(network.Peerings))

		for _, peering := range network.Peerings {
			peeringMap := map[string]interface{}{}

			if peering.Name != "" {
				peeringMap["name"] = peering.Name
			}

			if peering.Network != "" {
				peeringMap["network"] = peering.Network
			}

			if peering.State != "" {
				peeringMap["state"] = peering.State
			}

			if peering.AutoCreateRoutes {
				peeringMap["auto_create_routes"] = peering.AutoCreateRoutes
			}

			if peering.ExchangeSubnetRoutes {
				peeringMap["exchange_subnet_routes"] = peering.ExchangeSubnetRoutes
			}

			if peering.ExportCustomRoutes {
				peeringMap["export_custom_routes"] = peering.ExportCustomRoutes
			}

			if peering.ImportCustomRoutes {
				peeringMap["import_custom_routes"] = peering.ImportCustomRoutes
			}

			if peering.ExportSubnetRoutesWithPublicIp {
				peeringMap["export_subnet_routes_with_public_ip"] = peering.ExportSubnetRoutesWithPublicIp
			}

			if peering.ImportSubnetRoutesWithPublicIp {
				peeringMap["import_subnet_routes_with_public_ip"] = peering.ImportSubnetRoutesWithPublicIp
			}

			if len(peeringMap) > 0 {
				peerings = append(peerings, peeringMap)
			}
		}

		if len(peerings) > 0 {
			properties["peerings"] = peerings
		}
	}

	return properties, nil
}

// collectFirewallState collects the state of a GCP firewall rule
func (p *Provider) collectFirewallState(ctx context.Context, resource *models.Resource) (models.Properties, error) {
	// Extract resource details
	projectID := resource.Project
	firewallName := resource.Name

	if projectID == "" {
		return nil, fmt.Errorf("project ID is required for GCP resources")
	}

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
		"id":        fmt.Sprintf("%d", firewall.Id),
		"name":      firewall.Name,
		"direction": firewall.Direction,
		"disabled":  firewall.Disabled,
	}

	if firewall.Network != "" {
		properties["network"] = getShortNetworkName(firewall.Network)
	}

	if firewall.Description != "" {
		properties["description"] = firewall.Description
	}

	if firewall.Priority != 0 {
		properties["priority"] = firewall.Priority
	}

	if firewall.CreationTimestamp != "" {
		properties["creation_timestamp"] = firewall.CreationTimestamp
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
			allowedRule := map[string]interface{}{
				"ip_protocol": rule.IPProtocol,
			}

			if rule.Ports != nil && len(rule.Ports) > 0 {
				allowedRule["ports"] = rule.Ports
			}

			// Completing the collectFirewallState function that was cut off
			allowed = append(allowed, allowedRule)
		}

		properties["allowed"] = allowed
	}

	// Add denied rules
	if firewall.Denied != nil && len(firewall.Denied) > 0 {
		denied := make([]map[string]interface{}, 0, len(firewall.Denied))

		for _, rule := range firewall.Denied {
			deniedRule := map[string]interface{}{
				"ip_protocol": rule.IPProtocol,
			}

			if rule.Ports != nil && len(rule.Ports) > 0 {
				deniedRule["ports"] = rule.Ports
			}

			denied = append(denied, deniedRule)
		}

		properties["denied"] = denied
	}

	// Add log_config
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

	// If a specific zone is provided in the filter, use only that one
	if filter.Region != "" {
		// Try to list instances in this specific zone
		instances, err := computeService.Instances.List(projectID, filter.Region).Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list instances in zone %s: %w", filter.Region, err)
		}

		for _, instance := range instances.Items {
			resource := &models.Resource{
				ID:       fmt.Sprintf("%d", instance.Id),
				Name:     instance.Name,
				Type:     models.ResourceTypeGCPInstance,
				Provider: models.ProviderGCP,
				IaCType:  models.IaCTypeTerraform, // Assume Terraform as default
				Region:   getShortZone(instance.Zone),
				Project:  projectID,
				Tags:     make(models.Tags),
			}

			// Extract labels as tags
			if instance.Labels != nil {
				for k, v := range instance.Labels {
					resource.Tags[k] = v
				}
			}

			// Apply tag filter if specified
			if len(filter.Tags) > 0 {
				match := true
				for k, v := range filter.Tags {
					if resourceValue, exists := resource.Tags[k]; !exists || resourceValue != v {
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
	} else {
		// List zones first
		zoneList, err := computeService.Zones.List(projectID).Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list zones: %w", err)
		}

		// Iterate through all zones
		for _, zone := range zoneList.Items {
			instances, err := computeService.Instances.List(projectID, zone.Name).Do()
			if err != nil {
				log.Printf("Failed to list instances in zone %s: %v", zone.Name, err)
				continue
			}

			for _, instance := range instances.Items {
				resource := &models.Resource{
					ID:       fmt.Sprintf("%d", instance.Id),
					Name:     instance.Name,
					Type:     models.ResourceTypeGCPInstance,
					Provider: models.ProviderGCP,
					IaCType:  models.IaCTypeTerraform, // Assume Terraform as default
					Region:   getShortZone(instance.Zone),
					Project:  projectID,
					Tags:     make(models.Tags),
				}

				// Extract labels as tags
				if instance.Labels != nil {
					for k, v := range instance.Labels {
						resource.Tags[k] = v
					}
				}

				// Apply tag filter if specified
				if len(filter.Tags) > 0 {
					match := true
					for k, v := range filter.Tags {
						if resourceValue, exists := resource.Tags[k]; !exists || resourceValue != v {
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

	// List buckets
	buckets, err := storageService.Buckets.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list storage buckets: %w", err)
	}

	var resources []*models.Resource

	for _, bucket := range buckets.Items {
		// Apply region filter if specified
		if filter.Region != "" && bucket.Location != filter.Region {
			continue
		}

		resource := &models.Resource{
			ID:       bucket.Id,
			Name:     bucket.Name,
			Type:     "gcp_storage_bucket",
			Provider: models.ProviderGCP,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform as default
			Region:   bucket.Location,
			Project:  projectID,
			Tags:     make(models.Tags),
		}

		// Extract labels as tags
		if bucket.Labels != nil {
			for k, v := range bucket.Labels {
				resource.Tags[k] = v
			}
		}

		// Apply tag filter if specified
		if len(filter.Tags) > 0 {
			match := true
			for k, v := range filter.Tags {
				if resourceValue, exists := resource.Tags[k]; !exists || resourceValue != v {
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

// discoverNetworks discovers GCP VPC networks
func (p *Provider) discoverNetworks(ctx context.Context, projectID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create compute service client
	computeService, err := compute.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service client: %w", err)
	}

	// List networks
	networks, err := computeService.Networks.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	var resources []*models.Resource

	for _, network := range networks.Items {
		resource := &models.Resource{
			ID:       fmt.Sprintf("%d", network.Id),
			Name:     network.Name,
			Type:     "gcp_network",
			Provider: models.ProviderGCP,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform as default
			Project:  projectID,
			Tags:     make(models.Tags),
		}

		// For VPC networks, there's usually no region-specific filtering
		// But apply tag filter if specified
		if len(filter.Tags) > 0 {
			match := true
			for k, v := range filter.Tags {
				if resourceValue, exists := resource.Tags[k]; !exists || resourceValue != v {
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

// discoverFirewalls discovers GCP firewall rules
func (p *Provider) discoverFirewalls(ctx context.Context, projectID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create compute service client
	computeService, err := compute.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service client: %w", err)
	}

	// List firewalls
	firewalls, err := computeService.Firewalls.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list firewalls: %w", err)
	}

	var resources []*models.Resource

	for _, firewall := range firewalls.Items {
		resource := &models.Resource{
			ID:       fmt.Sprintf("%d", firewall.Id),
			Name:     firewall.Name,
			Type:     "gcp_firewall",
			Provider: models.ProviderGCP,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform as default
			Project:  projectID,
			Tags:     make(models.Tags),
		}

		// Firewall rules don't have labels, so tag filtering won't apply
		// But we maintain the same pattern for consistency
		if len(filter.Tags) > 0 {
			continue // Skip if tag filter is applied since firewalls don't have tags
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

// discoverDatabaseInstances discovers GCP Cloud SQL instances
func (p *Provider) discoverDatabaseInstances(ctx context.Context, projectID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create SQL admin service client
	sqlService, err := sqladmin.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud SQL service client: %w", err)
	}

	// List database instances
	instances, err := sqlService.Instances.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list database instances: %w", err)
	}

	var resources []*models.Resource

	for _, instance := range instances.Items {
		// Apply region filter if specified
		if filter.Region != "" && instance.Region != filter.Region {
			continue
		}

		resource := &models.Resource{
			ID:       instance.Name, // Using name as ID since it's unique for SQL instances
			Name:     instance.Name,
			Type:     "gcp_sql_instance",
			Provider: models.ProviderGCP,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform as default
			Region:   instance.Region,
			Project:  projectID,
			Tags:     make(models.Tags),
		}

		// Extract settings.userLabels as tags if available
		if instance.Settings != nil && instance.Settings.UserLabels != nil {
			for k, v := range instance.Settings.UserLabels {
				resource.Tags[k] = v
			}
		}

		// Apply tag filter if specified
		if len(filter.Tags) > 0 {
			match := true
			for k, v := range filter.Tags {
				if resourceValue, exists := resource.Tags[k]; !exists || resourceValue != v {
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

// discoverPubSubTopics discovers GCP Pub/Sub topics
func (p *Provider) discoverPubSubTopics(ctx context.Context, projectID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create Pub/Sub service client
	pubsubService, err := pubsub.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Pub/Sub service client: %w", err)
	}

	// List topics
	topics, err := pubsubService.Projects.Topics.List(fmt.Sprintf("projects/%s", projectID)).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list topics: %w", err)
	}

	var resources []*models.Resource

	for _, topic := range topics.Topics {
		// Extract topic name from the full path
		// Format: projects/{project}/topics/{topic}
		parts := strings.Split(topic.Name, "/")
		if len(parts) < 4 {
			continue
		}
		topicName := parts[3]

		resource := &models.Resource{
			ID:       topic.Name,
			Name:     topicName,
			Type:     "gcp_pubsub_topic",
			Provider: models.ProviderGCP,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform as default
			Project:  projectID,
			Tags:     make(models.Tags),
		}

		// Pub/Sub topics don't have labels in the API response by default
		// We would need to get each topic's metadata to check labels
		// For performance reasons, we'll skip that here unless needed

		// Apply tag filter if specified
		if len(filter.Tags) > 0 {
			continue // Skip if tag filter is applied since we're not fetching topic labels
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

// discoverCloudFunctions discovers GCP Cloud Functions
func (p *Provider) discoverCloudFunctions(ctx context.Context, projectID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create Cloud Functions service client
	functionsService, err := cloudfunctions.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Functions service client: %w", err)
	}

	// Cloud Functions are organized by location
	if filter.Region == "" {
		// If no region specified, default to us-central1
		filter.Region = "us-central1"
	}

	// List functions in the specified region
	functionsList, err := functionsService.Projects.Locations.Functions.List(
		fmt.Sprintf("projects/%s/locations/%s", projectID, filter.Region)).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list cloud functions: %w", err)
	}

	var resources []*models.Resource

	for _, function := range functionsList.Functions {
		// Extract function name from the full path
		// Format: projects/{project}/locations/{location}/functions/{function}
		parts := strings.Split(function.Name, "/")
		if len(parts) < 6 {
			continue
		}
		functionName := parts[5]
		location := parts[3]

		resource := &models.Resource{
			ID:       function.Name,
			Name:     functionName,
			Type:     "gcp_cloudfunctions_function",
			Provider: models.ProviderGCP,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform as default
			Region:   location,
			Project:  projectID,
			Tags:     make(models.Tags),
		}

		// Extract labels as tags if available
		if function.Labels != nil {
			for k, v := range function.Labels {
				resource.Tags[k] = v
			}
		}

		// Apply tag filter if specified
		if len(filter.Tags) > 0 {
			match := true
			for k, v := range filter.Tags {
				if resourceValue, exists := resource.Tags[k]; !exists || resourceValue != v {
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

// discoverGKEClusters discovers GCP GKE clusters
func (p *Provider) discoverGKEClusters(ctx context.Context, projectID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create GKE service client
	gkeService, err := container.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create GKE service client: %w", err)
	}

	// List clusters
	clusters, err := gkeService.Projects.Locations.Clusters.List(
		fmt.Sprintf("projects/%s/locations/-", projectID)).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list GKE clusters: %w", err)
	}

	var resources []*models.Resource

	for _, cluster := range clusters.Clusters {
		// Extract location from the cluster
		location := cluster.Location

		// Apply region filter if specified
		if filter.Region != "" && location != filter.Region {
			continue
		}

		resource := &models.Resource{
			ID:       cluster.SelfLink,
			Name:     cluster.Name,
			Type:     "gcp_container_cluster",
			Provider: models.ProviderGCP,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform as default
			Region:   location,
			Project:  projectID,
			Tags:     make(models.Tags),
		}

		// Extract resource labels as tags
		if cluster.ResourceLabels != nil {
			for k, v := range cluster.ResourceLabels {
				resource.Tags[k] = v
			}
		}

		// Apply tag filter if specified
		if len(filter.Tags) > 0 {
			match := true
			for k, v := range filter.Tags {
				if resourceValue, exists := resource.Tags[k]; !exists || resourceValue != v {
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

// discoverBigQueryDatasets discovers GCP BigQuery datasets
func (p *Provider) discoverBigQueryDatasets(ctx context.Context, projectID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create BigQuery service client
	bqService, err := bigquery.NewService(ctx, option.WithCredentials(p.credential))
	if err != nil {
		return nil, fmt.Errorf("failed to create BigQuery service client: %w", err)
	}

	// List datasets
	datasets, err := bqService.Datasets.List(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list BigQuery datasets: %w", err)
	}

	var resources []*models.Resource

	for _, dataset := range datasets.Datasets {
		// Extract dataset location
		datasetRef := dataset.DatasetReference
		if datasetRef == nil {
			continue
		}

		// Get dataset details to get location
		datasetDetail, err := bqService.Datasets.Get(projectID, datasetRef.DatasetId).Do()
		if err != nil {
			log.Printf("Failed to get dataset details for %s: %v", datasetRef.DatasetId, err)
			continue
		}

		// Apply region filter if specified
		if filter.Region != "" && datasetDetail.Location != filter.Region {
			continue
		}

		resource := &models.Resource{
			ID:       fmt.Sprintf("%s:%s", projectID, datasetRef.DatasetId),
			Name:     datasetRef.DatasetId,
			Type:     "gcp_bigquery_dataset",
			Provider: models.ProviderGCP,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform as default
			Region:   datasetDetail.Location,
			Project:  projectID,
			Tags:     make(models.Tags),
		}

		// Extract labels as tags if available
		if datasetDetail.Labels != nil {
			for k, v := range datasetDetail.Labels {
				resource.Tags[k] = v
			}
		}

		// Apply tag filter if specified
		if len(filter.Tags) > 0 {
			match := true
			for k, v := range filter.Tags {
				if resourceValue, exists := resource.Tags[k]; !exists || resourceValue != v {
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
