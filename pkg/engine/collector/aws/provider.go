package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/models"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/storage/database"
)

// Provider implements the provider interface for AWS
type Provider struct {
	db *database.DB
}

// NewProvider creates a new AWS provider
func NewProvider(db *database.DB) *Provider {
	return &Provider{
		db: db,
	}
}

// CollectState collects the current state of an AWS resource
func (p *Provider) CollectState(ctx context.Context, resource *models.Resource) (*models.ResourceState, error) {
	// Create AWS config
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(resource.Region))
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS SDK config: %w", err)
	}

	// Collect state based on resource type
	var properties models.Properties
	var stateSource models.StateSource = models.StateSourceAWS

	switch resource.Type {
	case models.ResourceTypeEC2Instance:
		properties, err = p.collectEC2State(ctx, cfg, resource)
	case models.ResourceTypeS3Bucket:
		properties, err = p.collectS3State(ctx, cfg, resource)
	case models.ResourceTypeSecurityGroup:
		properties, err = p.collectSecurityGroupState(ctx, cfg, resource)
	default:
		return nil, fmt.Errorf("unsupported AWS resource type: %s", resource.Type)
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

// ListResources discovers AWS resources based on the filter
func (p *Provider) ListResources(ctx context.Context, filter models.ResourceFilter) ([]*models.Resource, error) {
	var resources []*models.Resource

	// Determine regions to scan
	regions := []string{"us-east-1"} // Default to us-east-1
	if filter.Region != "" {
		regions = []string{filter.Region}
	} else {
		// Get all regions
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
		if err != nil {
			return nil, fmt.Errorf("unable to load AWS SDK config: %w", err)
		}

		ec2Client := ec2.NewFromConfig(cfg)
		regionsOutput, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
		if err != nil {
			return nil, fmt.Errorf("unable to describe AWS regions: %w", err)
		}

		regions = make([]string, 0, len(regionsOutput.Regions))
		for _, region := range regionsOutput.Regions {
			regions = append(regions, *region.RegionName)
		}
	}

	// Scan each region
	for _, region := range regions {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("unable to load AWS SDK config for region %s: %w", region, err)
		}

		// Determine which resource types to scan
		resourceTypes := []models.ResourceType{
			models.ResourceTypeEC2Instance,
			models.ResourceTypeS3Bucket,
			models.ResourceTypeSecurityGroup,
		}

		if len(filter.Types) > 0 {
			resourceTypes = filter.Types
		}

		// Discover resources for each type
		for _, resourceType := range resourceTypes {
			var typeResources []*models.Resource

			switch resourceType {
			case models.ResourceTypeEC2Instance:
				typeResources, err = p.discoverEC2Instances(ctx, cfg, region, filter)
			case models.ResourceTypeS3Bucket:
				typeResources, err = p.discoverS3Buckets(ctx, cfg, region, filter)
			case models.ResourceTypeSecurityGroup:
				typeResources, err = p.discoverSecurityGroups(ctx, cfg, region, filter)
			default:
				continue // Skip unsupported types
			}

			if err != nil {
				return nil, fmt.Errorf("error discovering %s resources in %s: %w", resourceType, region, err)
			}

			resources = append(resources, typeResources...)
		}
	}

	return resources, nil
}

// collectEC2State collects the state of an EC2 instance
func (p *Provider) collectEC2State(ctx context.Context, cfg aws.Config, resource *models.Resource) (models.Properties, error) {
	client := ec2.NewFromConfig(cfg)

	// Extract instance ID from resource ID
	instanceID := resource.Name // Assuming the resource name is the instance ID

	// Describe the instance
	resp, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe EC2 instance %s: %w", instanceID, err)
	}

	// Check if instance exists
	if len(resp.Reservations) == 0 || len(resp.Reservations[0].Instances) == 0 {
		return nil, fmt.Errorf("EC2 instance %s not found", instanceID)
	}

	instance := resp.Reservations[0].Instances[0]

	// Build properties map
	properties := models.Properties{
		"id":               instanceID,
		"instance_type":    instance.InstanceType,
		"state":            instance.State.Name,
		"subnet_id":        instance.SubnetId,
		"vpc_id":           instance.VpcId,
		"private_ip":       instance.PrivateIpAddress,
		"public_ip":        instance.PublicIpAddress,
		"key_name":         instance.KeyName,
		"availability_zone": instance.Placement.AvailabilityZone,
	}

	// Add tags
	if len(instance.Tags) > 0 {
		tags := make(map[string]string)
		for _, tag := range instance.Tags {
			tags[*tag.Key] = *tag.Value
		}
		properties["tags"] = tags
	}

	// Add security groups
	if len(instance.SecurityGroups) > 0 {
		securityGroups := make([]map[string]string, 0, len(instance.SecurityGroups))
		for _, sg := range instance.SecurityGroups {
			securityGroups = append(securityGroups, map[string]string{
				"id":   *sg.GroupId,
				"name": *sg.GroupName,
			})
		}
		properties["security_groups"] = securityGroups
	}

	return properties, nil
}

// collectS3State collects the state of an S3 bucket
func (p *Provider) collectS3State(ctx context.Context, cfg aws.Config, resource *models.Resource) (models.Properties, error) {
	client := s3.NewFromConfig(cfg)

	// Extract bucket name from resource
	bucketName := resource.Name

	// Get bucket location
	locResp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 bucket location for %s: %w", bucketName, err)
	}

	// Build properties map
	properties := models.Properties{
		"name":     bucketName,
		"location": locResp.LocationConstraint,
	}

	// Get bucket ACL
	aclResp, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 bucket ACL for %s: %w", bucketName, err)
	}

	// Add ACL information
	properties["owner"] = map[string]string{
		"id":          *aclResp.Owner.ID,
		"displayName": *aclResp.Owner.DisplayName,
	}

	// Get public access block configuration
	pubAccessResp, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil && pubAccessResp.PublicAccessBlockConfiguration != nil {
		properties["public_access_block"] = map[string]bool{
			"block_public_acls":       *pubAccessResp.PublicAccessBlockConfiguration.BlockPublicAcls,
			"ignore_public_acls":      *pubAccessResp.PublicAccessBlockConfiguration.IgnorePublicAcls,
			"block_public_policy":     *pubAccessResp.PublicAccessBlockConfiguration.BlockPublicPolicy,
			"restrict_public_buckets": *pubAccessResp.PublicAccessBlockConfiguration.RestrictPublicBuckets,
		}
	}

	// Get encryption configuration
	encryptionResp, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil && encryptionResp.ServerSideEncryptionConfiguration != nil {
		encRules := make([]map[string]interface{}, 0)
		for _, rule := range encryptionResp.ServerSideEncryptionConfiguration.Rules {
			encRule := map[string]interface{}{}
			if rule.ApplyServerSideEncryptionByDefault != nil {
				encRule["sse_algorithm"] = rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm
				encRule["kms_master_key_id"] = rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
			}
			encRules = append(encRules, encRule)
		}
		properties["encryption"] = encRules
	}

	return properties, nil
}

// collectSecurityGroupState collects the state of a security group
func (p *Provider) collectSecurityGroupState(ctx context.Context, cfg aws.Config, resource *models.Resource) (models.Properties, error) {
	client := ec2.NewFromConfig(cfg)

	// Extract security group ID from resource
	sgID := resource.Name

	// Describe the security group
	resp, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security group %s: %w", sgID, err)
	}

	// Check if security group exists
	if len(resp.SecurityGroups) == 0 {
		return nil, fmt.Errorf("security group %s not found", sgID)
	}

	sg := resp.SecurityGroups[0]

	// Build properties map
	properties := models.Properties{
		"id":          *sg.GroupId,
		"name":        *sg.GroupName,
		"description": *sg.Description,
		"vpc_id":      *sg.VpcId,
	}

	// Add tags
	if len(sg.Tags) > 0 {
		tags := make(map[string]string)
		for _, tag := range sg.Tags {
			tags[*tag.Key] = *tag.Value
		}
		properties["tags"] = tags
	}

	// Add inbound rules
	inboundRules := make([]map[string]interface{}, 0, len(sg.IpPermissions))
	for _, perm := range sg.IpPermissions {
		rule := map[string]interface{}{
			"from_port":   perm.FromPort,
			"to_port":     perm.ToPort,
			"ip_protocol": perm.IpProtocol,
		}

		// Add IP ranges
		if len(perm.IpRanges) > 0 {
			ipRanges := make([]map[string]string, 0, len(perm.IpRanges))
			for _, ipRange := range perm.IpRanges {
				r := map[string]string{
					"cidr_ip": *ipRange.CidrIp,
				}
				if ipRange.Description != nil {
					r["description"] = *ipRange.Description
				}
				ipRanges = append(ipRanges, r)
			}
			rule["ip_ranges"] = ipRanges
		}

		// Add source security groups
		if len(perm.UserIdGroupPairs) > 0 {
			sgRefs := make([]map[string]string, 0, len(perm.UserIdGroupPairs))
			for _, sgRef := range perm.UserIdGroupPairs {
				ref := map[string]string{
					"group_id": *sgRef.GroupId,
				}
				if sgRef.Description != nil {
					ref["description"] = *sgRef.Description
				}
				sgRefs = append(sgRefs, ref)
			}
			rule["source_security_groups"] = sgRefs
		}

		inboundRules = append(inboundRules, rule)
	}
	properties["inbound_rules"] = inboundRules

	// Add outbound rules
	outboundRules := make([]map[string]interface{}, 0, len(sg.IpPermissionsEgress))
	for _, perm := range sg.IpPermissionsEgress {
		rule := map[string]interface{}{
			"from_port":   perm.FromPort,
			"to_port":     perm.ToPort,
			"ip_protocol": perm.IpProtocol,
		}

		// Add IP ranges
		if len(perm.IpRanges) > 0 {
			ipRanges := make([]map[string]string, 0, len(perm.IpRanges))
			for _, ipRange := range perm.IpRanges {
				r := map[string]string{
					"cidr_ip": *ipRange.CidrIp,
				}
				if ipRange.Description != nil {
					r["description"] = *ipRange.Description
				}
				ipRanges = append(ipRanges, r)
			}
			rule["ip_ranges"] = ipRanges
		}

		outboundRules = append(outboundRules, rule)
	}
	properties["outbound_rules"] = outboundRules

	return properties, nil
}

// discoverEC2Instances discovers EC2 instances
func (p *Provider) discoverEC2Instances(ctx context.Context, cfg aws.Config, region string, filter models.ResourceFilter) ([]*models.Resource, error) {
	client := ec2.NewFromConfig(cfg)
	var resources []*models.Resource

	// Prepare EC2 filter
	var ec2Filters []types.Filter
	if len(filter.Tags) > 0 {
		for key, value := range filter.Tags {
			ec2Filters = append(ec2Filters, types.Filter{
				Name:   aws.String(fmt.Sprintf("tag:%s", key)),
				Values: []string{value},
			})
		}
	}

	// Describe instances
	resp, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: ec2Filters,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe EC2 instances: %w", err)
	}

	// Process results
	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			// Skip terminated instances
			if instance.State.Name == "terminated" {
				continue
			}

			// Create resource
			resource := &models.Resource{
				ID:       *instance.InstanceId,
				Name:     *instance.InstanceId,
				Type:     models.ResourceTypeEC2Instance,
				Provider: models.ProviderAWS,
				IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
				Region:   region,
				Account:  "aws-account-id", // This should be determined dynamically
				Tags:     make(models.Tags),
			}

			// Add tags
			for _, tag := range instance.Tags {
				resource.Tags[*tag.Key] = *tag.Value
			}

			resources = append(resources, resource)
		}
	}

	return resources, nil
}

// discoverS3Buckets discovers S3 buckets
func (p *Provider) discoverS3Buckets(ctx context.Context, cfg aws.Config, region string, filter models.ResourceFilter) ([]*models.Resource, error) {
	client := s3.NewFromConfig(cfg)
	var resources []*models.Resource

	// List buckets
	resp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 buckets: %w", err)
	}

	// Process results
	for _, bucket := range resp.Buckets {
		// Check bucket region
		locResp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			// Skip buckets we can't access
			continue
		}

		bucketRegion := "us-east-1" // Default region for S3
		if locResp.LocationConstraint != "" {
			bucketRegion = string(locResp.LocationConstraint)
		}

		// Skip if it doesn't match our target region
		if region != "" && bucketRegion != region {
			continue
		}

		// Create resource
		resource := &models.Resource{
			ID:       *bucket.Name,
			Name:     *bucket.Name,
			Type:     models.ResourceTypeS3Bucket,
			Provider: models.ProviderAWS,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
			Region:   bucketRegion,
			Account:  "aws-account-id", // This should be determined dynamically
			Tags:     make(models.Tags),
		}

		// Get bucket tags if possible
		tagResp, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: bucket.Name,
		})
		if err == nil {
			for _, tag := range tagResp.TagSet {
				resource.Tags[*tag.Key] = *tag.Value
			}
		}

		// Apply tag filter if specified
		if len(filter.Tags) > 0 {
			match := true
			for key, value := range filter.Tags {
				if tagValue, exists := resource.Tags[key]; !exists || tagValue != value {
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

// discoverSecurityGroups discovers security groups
func (p *Provider) discoverSecurityGroups(ctx context.Context, cfg aws.Config, region string, filter models.ResourceFilter) ([]*models.Resource, error) {
	client := ec2.NewFromConfig(cfg)
	var resources []*models.Resource

	// Prepare EC2 filter
	var ec2Filters []types.Filter
	if len(filter.Tags) > 0 {
		for key, value := range filter.Tags {
			ec2Filters = append(ec2Filters, types.Filter{
				Name:   aws.String(fmt.Sprintf("tag:%s", key)),
				Values: []string{value},
			})
		}
	}

	// Describe security groups
	resp, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: ec2Filters,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	// Process results
	for _, sg := range resp.SecurityGroups {
		// Create resource
		resource := &models.Resource{
			ID:       *sg.GroupId,
			Name:     *sg.GroupId,
			Type:     models.ResourceTypeSecurityGroup,
			Provider: models.ProviderAWS,
			IaCType:  models.IaCTypeTerraform, // Assume Terraform for now
			Region:   region,
			Account:  "aws-account-id", // This should be determined dynamically
			Tags:     make(models.Tags),
		}

		// Add tags
		for _, tag := range sg.Tags {
			resource.Tags[*tag.Key] = *tag.Value
		}

		resources = append(resources, resource)
	}

	return resources, nil
}