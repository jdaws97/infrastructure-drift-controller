package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/google/uuid"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
)

// Provider implements the provider interface for Azure
type Provider struct {
	db            *database.DB
	cred          *azidentity.DefaultAzureCredential
	subscriptions []string
}

// NewProvider creates a new Azure provider
func NewProvider(db *database.DB) *Provider {
	return &Provider{
		db: db,
	}
}

// Initialize sets up the Azure credentials
func (p *Provider) Initialize(subscriptions []string) error {
	// Create default Azure credential
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to get Azure credentials: %w", err)
	}
	
	p.cred = cred
	p.subscriptions = subscriptions
	
	return nil
}

// CollectState collects the current state of an Azure resource
func (p *Provider) CollectState(ctx context.Context, resource *models.Resource) (*models.ResourceState, error) {
	// Determine the resource type and collect appropriate state
	var properties models.Properties
	var err error
	var stateSource models.StateSource = models.StateSourceAzure

	switch resource.Type {
	case models.ResourceTypeAzureVM:
		properties, err = p.collectVMState(ctx, resource)
	case "azure_storage_account":
		properties, err = p.collectStorageAccountState(ctx, resource)
	case "azure_virtual_network":
		properties, err = p.collectVNetState(ctx, resource)
	case "azure_network_security_group":
		properties, err = p.collectNSGState(ctx, resource)
	default:
		return nil, fmt.Errorf("unsupported Azure resource type: %s", resource.Type)
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

// ListResources discovers Azure resources based on the filter
func (p *Provider) ListResources(ctx context.Context, filter models.ResourceFilter) ([]*models.Resource, error) {
	var resources []*models.Resource

	// Determine which subscription(s) to scan
	subscriptions := p.subscriptions
	
	// If a specific subscription ID is provided in the filter, use only that one
	if filter.Account != "" {
		// Check if the requested subscription is in our allowed list
		found := false
		for _, sub := range p.subscriptions {
			if sub == filter.Account {
				found = true
				break
			}
		}
		
		if !found {
			return nil, fmt.Errorf("subscription %s not authorized", filter.Account)
		}
		
		subscriptions = []string{filter.Account}
	}
	
	// Scan each subscription
	for _, subscriptionID := range subscriptions {
		// Discover resources based on filter.Types
		// If no specific types are requested, discover all supported types
		resourceTypes := []string{
			string(models.ResourceTypeAzureVM),
			"azure_storage_account",
			"azure_virtual_network",
			"azure_network_security_group",
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
			case string(models.ResourceTypeAzureVM):
				typeResources, err = p.discoverVMs(ctx, subscriptionID, filter)
			case "azure_storage_account":
				typeResources, err = p.discoverStorageAccounts(ctx, subscriptionID, filter)
			case "azure_virtual_network":
				typeResources, err = p.discoverVirtualNetworks(ctx, subscriptionID, filter)
			case "azure_network_security_group":
				typeResources, err = p.discoverNetworkSecurityGroups(ctx, subscriptionID, filter)
			default:
				continue // Skip unsupported types
			}
			
			if err != nil {
				return nil, fmt.Errorf("error discovering %s resources in subscription %s: %w", resourceType, subscriptionID, err)
			}
			
			resources = append(resources, typeResources...)
		}
	}

	return resources, nil
}

// collectVMState collects the state of an Azure virtual machine
func (p *Provider) collectVMState(ctx context.Context, resource *models.Resource) (models.Properties, error) {
	// Extract resource details
	subscriptionID := resource.Account
	resourceGroup := getResourceGroup(resource)
	vmName := resource.Name
	
	// Create VM client
	vmClient, err := armcompute.NewVirtualMachinesClient(subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM client: %w", err)
	}
	
	// Get VM details
	vm, err := vmClient.Get(ctx, resourceGroup, vmName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get VM details: %w", err)
	}
	
	// Build properties map
	properties := models.Properties{
		"id":            *vm.ID,
		"name":          *vm.Name,
		"location":      *vm.Location,
		"vm_size":       *vm.Properties.HardwareProfile.VMSize,
		"os_type":       getOSType(&vm.VirtualMachine),
		"admin_username": getAdminUsername(&vm.VirtualMachine),
		"network_interfaces": getNICs(&vm.VirtualMachine),
		"boot_diagnostics_enabled": isBootDiagnosticsEnabled(&vm.VirtualMachine),
	}
	
	// Add OS disk details
	if vm.Properties.StorageProfile.OSDisk != nil {
		osDisk := vm.Properties.StorageProfile.OSDisk
		properties["os_disk"] = map[string]interface{}{
			"name":       *osDisk.Name,
			"disk_size":  osDisk.DiskSizeGB,
			"caching":    string(*osDisk.Caching),
			"managed":    osDisk.ManagedDisk != nil,
			"os_type":    string(*osDisk.OSType),
		}
	}
	
	// Add data disks
	if vm.Properties.StorageProfile.DataDisks != nil && len(vm.Properties.StorageProfile.DataDisks) > 0 {
		dataDisks := make([]map[string]interface{}, 0, len(vm.Properties.StorageProfile.DataDisks))
		
		for _, disk := range vm.Properties.StorageProfile.DataDisks {
			diskInfo := map[string]interface{}{
				"name":       *disk.Name,
				"lun":        *disk.Lun,
				"disk_size":  disk.DiskSizeGB,
				"caching":    string(*disk.Caching),
				"managed":    disk.ManagedDisk != nil,
			}
			dataDisks = append(dataDisks, diskInfo)
		}
		
		properties["data_disks"] = dataDisks
	}
	
	// Add tags
	if vm.Tags != nil {
		tags := make(map[string]string)
		for k, v := range vm.Tags {
			if v != nil {
				tags[k] = *v
			}
		}
		properties["tags"] = tags
	}
	
	// Get VM status
	instanceView, err := vmClient.InstanceView(ctx, resourceGroup, vmName, nil)
	if err == nil {
		// Extract the VM status
		var powerState string
		for _, status := range instanceView.Statuses {
			if status.Code != nil && len(*status.Code) > 0 {
				code := *status.Code
				if len(code) > 10 && code[0:10] == "PowerState" {
					powerState = code[11:] // Skip "PowerState/"
					break
				}
			}
		}
		properties["power_state"] = powerState
	}
	
	return properties, nil
}

// collectStorageAccountState collects the state of an Azure storage account
func (p *Provider) collectStorageAccountState(ctx context.Context, resource *models.Resource) (models.Properties, error) {
	// Extract resource details
	subscriptionID := resource.Account
	resourceGroup := getResourceGroup(resource)
	accountName := resource.Name
	
	// Create storage accounts client
	storageClient, err := armstorage.NewAccountsClient(subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}
	
	// Get storage account details
	account, err := storageClient.GetProperties(ctx, resourceGroup, accountName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get storage account: %w", err)
	}
	
	// Build properties map
	properties := models.Properties{
		"id":                      *account.ID,
		"name":                    *account.Name,
		"location":                *account.Location,
		"kind":                    string(*account.Kind),
		"access_tier":             string(*account.Properties.AccessTier),
		"https_only":              *account.Properties.EnableHTTPSTrafficOnly,
		"provisioning_state":      *account.Properties.ProvisioningState,
		"primary_location":        *account.Properties.PrimaryLocation,
		"status_of_primary":       *account.Properties.StatusOfPrimary,
		"creation_time":           account.Properties.CreationTime.Format(time.RFC3339),
	}
	
	// Add SKU details
	if account.SKU != nil {
		properties["sku"] = map[string]interface{}{
			"name":     string(*account.SKU.Name),
			"tier":     string(*account.SKU.Tier),
		}
	}
	
	// Add replication details
	if account.Properties.SecondaryLocation != nil {
		properties["secondary_location"] = *account.Properties.SecondaryLocation
		properties["status_of_secondary"] = *account.Properties.StatusOfSecondary
	}
	
	// Add network rule set details
	if account.Properties.NetworkRuleSet != nil {
		networkRules := map[string]interface{}{
			"default_action": string(*account.Properties.NetworkRuleSet.DefaultAction),
			"bypass":         string(*account.Properties.NetworkRuleSet.Bypass),
		}
		
		// Add IP rules
		if account.Properties.NetworkRuleSet.IPRules != nil {
			ipRules := make([]string, 0, len(account.Properties.NetworkRuleSet.IPRules))
			for _, rule := range account.Properties.NetworkRuleSet.IPRules {
				ipRules = append(ipRules, *rule.IPAddressOrRange)
			}
			networkRules["ip_rules"] = ipRules
		}
		
		// Add virtual network rules
		if account.Properties.NetworkRuleSet.VirtualNetworkRules != nil {
			vnetRules := make([]string, 0, len(account.Properties.NetworkRuleSet.VirtualNetworkRules))
			for _, rule := range account.Properties.NetworkRuleSet.VirtualNetworkRules {
				vnetRules = append(vnetRules, *rule.VirtualNetworkResourceID)
			}
			networkRules["virtual_network_rules"] = vnetRules
		}
		
		properties["network_rules"] = networkRules
	}
	
	// Add encryption details
	if account.Properties.Encryption != nil {
		properties["encryption"] = map[string]interface{}{
			"services": getEncryptionServices(account.Properties.Encryption),
			"key_source": string(*account.Properties.Encryption.KeySource),
		}
	}
	
	// Add tags
	if account.Tags != nil {
		tags := make(map[string]string)
		for k, v := range account.Tags {
			if v != nil {
				tags[k] = *v
			}
		}
		properties["tags"] = tags
	}
	
	return properties, nil
}

// collectVNetState collects the state of an Azure virtual network
func (p *Provider) collectVNetState(ctx context.Context, resource *models.Resource) (models.Properties, error) {
	// Extract resource details
	subscriptionID := resource.Account
	resourceGroup := getResourceGroup(resource)
	vnetName := resource.Name
	
	// Create virtual networks client
	vnetClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create virtual network client: %w", err)
	}
	
	// Get virtual network details
	vnet, err := vnetClient.Get(ctx, resourceGroup, vnetName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get virtual network: %w", err)
	}
	
	// Build properties map
	properties := models.Properties{
		"id":                 *vnet.ID,
		"name":               *vnet.Name,
		"location":           *vnet.Location,
		"provisioning_state": *vnet.Properties.ProvisioningState,
	}
	
	// Add address space
	if vnet.Properties.AddressSpace != nil && vnet.Properties.AddressSpace.AddressPrefixes != nil {
		properties["address_space"] = vnet.Properties.AddressSpace.AddressPrefixes
	}
	
	// Add subnets
	if vnet.Properties.Subnets != nil {
		subnets := make([]map[string]interface{}, 0, len(vnet.Properties.Subnets))
		
		for _, subnet := range vnet.Properties.Subnets {
			subnetInfo := map[string]interface{}{
				"id":                 *subnet.ID,
				"name":               *subnet.Name,
				"address_prefix":     *subnet.Properties.AddressPrefix,
				"provisioning_state": *subnet.Properties.ProvisioningState,
			}
			
			// Add network security group if present
			if subnet.Properties.NetworkSecurityGroup != nil {
				subnetInfo["network_security_group"] = *subnet.Properties.NetworkSecurityGroup.ID
			}
			
			// Add route table if present
			if subnet.Properties.RouteTable != nil {
				subnetInfo["route_table"] = *subnet.Properties.RouteTable.ID
			}
			
			subnets = append(subnets, subnetInfo)
		}
		
		properties["subnets"] = subnets
	}
	
	// Add DNS servers
	if vnet.Properties.DhcpOptions != nil && vnet.Properties.DhcpOptions.DNSServers != nil {
		properties["dns_servers"] = vnet.Properties.DhcpOptions.DNSServers
	}
	
	// Add tags
	if vnet.Tags != nil {
		tags := make(map[string]string)
		for k, v := range vnet.Tags {
			if v != nil {
				tags[k] = *v
			}
		}
		properties["tags"] = tags
	}
	
	return properties, nil
}

// collectNSGState collects the state of an Azure network security group
func (p *Provider) collectNSGState(ctx context.Context, resource *models.Resource) (models.Properties, error) {
	// Extract resource details
	subscriptionID := resource.Account
	resourceGroup := getResourceGroup(resource)
	nsgName := resource.Name
	
	// Create network security groups client
	nsgClient, err := armnetwork.NewSecurityGroupsClient(subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NSG client: %w", err)
	}
	
	// Get NSG details
	nsg, err := nsgClient.Get(ctx, resourceGroup, nsgName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get NSG: %w", err)
	}
	
	// Build properties map
	properties := models.Properties{
		"id":                 *nsg.ID,
		"name":               *nsg.Name,
		"location":           *nsg.Location,
		"provisioning_state": *nsg.Properties.ProvisioningState,
	}
	
	// Add security rules
	if nsg.Properties.SecurityRules != nil {
		securityRules := make([]map[string]interface{}, 0, len(nsg.Properties.SecurityRules))
		
		for _, rule := range nsg.Properties.SecurityRules {
			ruleInfo := map[string]interface{}{
				"id":                   *rule.ID,
				"name":                *rule.Name,
				"protocol":            string(*rule.Properties.Protocol),
				"source_port_range":   *rule.Properties.SourcePortRange,
				"dest_port_range":     *rule.Properties.DestinationPortRange,
				"source_address_prefix": *rule.Properties.SourceAddressPrefix,
				"dest_address_prefix":  *rule.Properties.DestinationAddressPrefix,
				"access":              string(*rule.Properties.Access),
				"priority":           *rule.Properties.Priority,
				"direction":          string(*rule.Properties.Direction),
			}
			
			securityRules = append(securityRules, ruleInfo)
		}
		
		properties["security_rules"] = securityRules
	}
	
	// Add default security rules
	if nsg.Properties.DefaultSecurityRules != nil {
		defaultRules := make([]map[string]interface{}, 0, len(nsg.Properties.DefaultSecurityRules))
		
		for _, rule := range nsg.Properties.DefaultSecurityRules {
			ruleInfo := map[string]interface{}{
				"id":                   *rule.ID,
				"name":                *rule.Name,
				"protocol":            string(*rule.Properties.Protocol),
				"source_port_range":   *rule.Properties.SourcePortRange,
				"dest_port_range":     *rule.Properties.DestinationPortRange,
				"source_address_prefix": *rule.Properties.SourceAddressPrefix,
				"dest_address_prefix":  *rule.Properties.DestinationAddressPrefix,
				"access":              string(*rule.Properties.Access),
				"priority":           *rule.Properties.Priority,
				"direction":          string(*rule.Properties.Direction),
			}
			
			defaultRules = append(defaultRules, ruleInfo)
		}
		
		properties["default_security_rules"] = defaultRules
	}
	
	// Add tags
	if nsg.Tags != nil {
		tags := make(map[string]string)
		for k, v := range nsg.Tags {
			if v != nil {
				tags[k] = *v
			}
		}
		properties["tags"] = tags
	}
	
	return properties, nil
}

// discoverVMs discovers Azure virtual machines
func (p *Provider) discoverVMs(ctx context.Context, subscriptionID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create VM client
	vmClient, err := armcompute.NewVirtualMachinesClient(subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM client: %w", err)
	}
	
	var resources []*models.Resource
	
	// If resource group specified, list VMs in that group
	if rg := getGroupFromFilter(filter); rg != "" {
		pager := vmClient.NewListPager(rg, nil)
		
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list VMs: %w", err)
			}
			
			for _, vm := range page.Value {
				// Create resource from VM
				resource := &models.Resource{
					ID:       *vm.ID,
					Name:     *vm.Name,
					Type:     models.ResourceTypeAzureVM,
					Provider: models.ProviderAzure,
					IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
					Region:   *vm.Location,
					Account:  subscriptionID,
					Tags:     make(models.Tags),
				}
				
				// Add tags
				if vm.Tags != nil {
					for k, v := range vm.Tags {
						if v != nil {
							resource.Tags[k] = *v
						}
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
				if filter.Region != "" && filter.Region != resource.Region {
					continue
				}
				
				resources = append(resources, resource)
			}
		}
	} else {
		// List VMs across all resource groups
		pager := vmClient.NewListAllPager(nil)
		
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list VMs: %w", err)
			}
			
			for _, vm := range page.Value {
				// Create resource from VM
				resource := &models.Resource{
					ID:       *vm.ID,
					Name:     *vm.Name,
					Type:     models.ResourceTypeAzureVM,
					Provider: models.ProviderAzure,
					IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
					Region:   *vm.Location,
					Account:  subscriptionID,
					Tags:     make(models.Tags),
				}
				
				// Add tags
				if vm.Tags != nil {
					for k, v := range vm.Tags {
						if v != nil {
							resource.Tags[k] = *v
						}
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
				if filter.Region != "" && filter.Region != resource.Region {
					continue
				}
				
				resources = append(resources, resource)
			}
		}
	}
	
	return resources, nil
}

// discoverStorageAccounts discovers Azure storage accounts
func (p *Provider) discoverStorageAccounts(ctx context.Context, subscriptionID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create storage accounts client
	storageClient, err := armstorage.NewAccountsClient(subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}
	
	var resources []*models.Resource
	
	// If resource group specified, list storage accounts in that group
	if rg := getGroupFromFilter(filter); rg != "" {
		pager := storageClient.NewListByResourceGroupPager(rg, nil)
		
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list storage accounts: %w", err)
			}
			
			for _, account := range page.Value {
				// Create resource from storage account
				resource := &models.Resource{
					ID:       *account.ID,
					Name:     *account.Name,
					Type:     "azure_storage_account",
					Provider: models.ProviderAzure,
					IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
					Region:   *account.Location,
					Account:  subscriptionID,
					Tags:     make(models.Tags),
				}
				
				// Add tags
				if account.Tags != nil {
					for k, v := range account.Tags {
						if v != nil {
							resource.Tags[k] = *v
						}
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
				if filter.Region != "" && filter.Region != resource.Region {
					continue
				}
				
				resources = append(resources, resource)
			}
		}
	} else {
		// List storage accounts across all resource groups
		pager := storageClient.NewListPager(nil)
		
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list storage accounts: %w", err)
			}
			
			for _, account := range page.Value {
				// Create resource from storage account
				resource := &models.Resource{
					ID:       *account.ID,
					Name:     *account.Name,
					Type:     "azure_storage_account",
					Provider: models.ProviderAzure,
					IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
					Region:   *account.Location,
					Account:  subscriptionID,
					Tags:     make(models.Tags),
				}
				
				// Add tags
				if account.Tags != nil {
					for k, v := range account.Tags {
						if v != nil {
							resource.Tags[k] = *v
						}
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
				if filter.Region != "" && filter.Region != resource.Region {
					continue
				}
				
				resources = append(resources, resource)
			}
		}
	}
	
	return resources, nil
}

// discoverVirtualNetworks discovers Azure virtual networks
func (p *Provider) discoverVirtualNetworks(ctx context.Context, subscriptionID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create virtual networks client
	vnetClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create virtual network client: %w", err)
	}
	
	var resources []*models.Resource
	
	// If resource group specified, list virtual networks in that group
	if rg := getGroupFromFilter(filter); rg != "" {
		pager := vnetClient.NewListPager(rg, nil)
		
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list virtual networks: %w", err)
			}
			
			for _, vnet := range page.Value {
				// Create resource from virtual network
				resource := &models.Resource{
					ID:       *vnet.ID,
					Name:     *vnet.Name,
					Type:     "azure_virtual_network",
					Provider: models.ProviderAzure,
					IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
					Region:   *vnet.Location,
					Account:  subscriptionID,
					Tags:     make(models.Tags),
				}
				
				// Add tags
				if vnet.Tags != nil {
					for k, v := range vnet.Tags {
						if v != nil {
							resource.Tags[k] = *v
						}
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
				if filter.Region != "" && filter.Region != resource.Region {
					continue
				}
				
				resources = append(resources, resource)
			}
		}
	} else {
		// List virtual networks across all resource groups
		pager := vnetClient.NewListAllPager(nil)
		
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list virtual networks: %w", err)
			}
			
			for _, vnet := range page.Value {
				// Create resource from virtual network
				resource := &models.Resource{
					ID:       *vnet.ID,
					Name:     *vnet.Name,
					Type:     "azure_virtual_network",
					Provider: models.ProviderAzure,
					IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
					Region:   *vnet.Location,
					Account:  subscriptionID,
					Tags:     make(models.Tags),
				}
				
				// Add tags
				if vnet.Tags != nil {
					for k, v := range vnet.Tags {
						if v != nil {
							resource.Tags[k] = *v
						}
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
				if filter.Region != "" && filter.Region != resource.Region {
					continue
				}
				
				resources = append(resources, resource)
			}
		}
	}
	
	return resources, nil
}

// Helper functions

// getResourceGroup extracts the resource group from resource ID
func getResourceGroup(resource *models.Resource) string {
	// Parse the resource ID to extract resource group
	// Azure resource IDs have the format:
	// /subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/{provider}/{resource-type}/{resource-name}
	
	// We'll use a simple string split approach
	parts := strings.Split(resource.ID, "/")
	
	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	
	// If the resource ID doesn't follow the expected format, try to get it from metadata
	return ""
}

// getGroupFromFilter tries to extract resource group from filter
func getGroupFromFilter(filter models.ResourceFilter) string {
	// In a real implementation, you might have more context about how resource groups
	// are represented in your filter. This is a placeholder.
	
	// For now, we'll assume the project field might contain the resource group
	return filter.Project
}

// getOSType extracts the OS type from a VM
func getOSType(vm *armcompute.VirtualMachine) string {
	if vm.Properties.StorageProfile.OSDisk != nil && vm.Properties.StorageProfile.OSDisk.OSType != nil {
		return string(*vm.Properties.StorageProfile.OSDisk.OSType)
	}
	return ""
}

// getAdminUsername extracts the admin username from a VM
func getAdminUsername(vm *armcompute.VirtualMachine) string {
	if vm.Properties.OSProfile != nil && vm.Properties.OSProfile.AdminUsername != nil {
		return *vm.Properties.OSProfile.AdminUsername
	}
	return ""
}

// getNICs extracts network interface information from a VM
func getNICs(vm *armcompute.VirtualMachine) []string {
	if vm.Properties.NetworkProfile != nil && vm.Properties.NetworkProfile.NetworkInterfaces != nil {
		nics := make([]string, 0, len(vm.Properties.NetworkProfile.NetworkInterfaces))
		
		for _, nic := range vm.Properties.NetworkProfile.NetworkInterfaces {
			if nic.ID != nil {
				nics = append(nics, *nic.ID)
			}
		}
		
		return nics
	}
	
	return []string{}
}

// isBootDiagnosticsEnabled checks if boot diagnostics is enabled
func isBootDiagnosticsEnabled(vm *armcompute.VirtualMachine) bool {
	if vm.Properties.DiagnosticsProfile != nil && 
	   vm.Properties.DiagnosticsProfile.BootDiagnostics != nil {
		return *vm.Properties.DiagnosticsProfile.BootDiagnostics.Enabled
	}
	return false
}

// getEncryptionServices extracts encryption services configuration
func getEncryptionServices(encryption *armstorage.Encryption) map[string]interface{} {
	services := make(map[string]interface{})
	
	if encryption.Services != nil {
		if encryption.Services.Blob != nil {
			services["blob"] = map[string]interface{}{
				"enabled": *encryption.Services.Blob.Enabled,
			}
		}
		
		if encryption.Services.File != nil {
			services["file"] = map[string]interface{}{
				"enabled": *encryption.Services.File.Enabled,
			}
		}
		
		if encryption.Services.Table != nil {
			services["table"] = map[string]interface{}{
				"enabled": *encryption.Services.Table.Enabled,
			}
		}
		
		if encryption.Services.Queue != nil {
			services["queue"] = map[string]interface{}{
				"enabled": *encryption.Services.Queue.Enabled,
			}
		}
	}
	
	return services
}

// discoverNetworkSecurityGroups discovers Azure network security groups
func (p *Provider) discoverNetworkSecurityGroups(ctx context.Context, subscriptionID string, filter models.ResourceFilter) ([]*models.Resource, error) {
	// Create NSG client
	nsgClient, err := armnetwork.NewSecurityGroupsClient(subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NSG client: %w", err)
	}
	
	var resources []*models.Resource
	
	// If resource group specified, list NSGs in that group
	if rg := getGroupFromFilter(filter); rg != "" {
		pager := nsgClient.NewListPager(rg, nil)
		
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list NSGs: %w", err)
			}
			
			for _, nsg := range page.Value {
				// Create resource from NSG
				resource := &models.Resource{
					ID:       *nsg.ID,
					Name:     *nsg.Name,
					Type:     "azure_network_security_group",
					Provider: models.ProviderAzure,
					IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
					Region:   *nsg.Location,
					Account:  subscriptionID,
					Tags:     make(models.Tags),
				}
				
				// Add tags
				if nsg.Tags != nil {
					for k, v := range nsg.Tags {
						if v != nil {
							resource.Tags[k] = *v
						}
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
				if filter.Region != "" && filter.Region != resource.Region {
					continue
				}
				
				resources = append(resources, resource)
			}
		}
	} else {
		// List NSGs across all resource groups
		pager := nsgClient.NewListAllPager(nil)
		
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list NSGs: %w", err)
			}
			
			for _, nsg := range page.Value {
				// Create resource from NSG
				resource := &models.Resource{
					ID:       *nsg.ID,
					Name:     *nsg.Name,
					Type:     "azure_network_security_group",
					Provider: models.ProviderAzure,
					IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
					Region:   *nsg.Location,
					Account:  subscriptionID,
					Tags:     make(models.Tags),
				}
				
				// Add tags
				if nsg.Tags != nil {
					for k, v := range nsg.Tags {
						if v != nil {
							resource.Tags[k] = *v
						}
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
				if filter.Region != "" && filter.Region != resource.Region {
					continue
				}
				
				resources = append(resources, resource)
			}
		}
	}
	
	return resources, nil
}