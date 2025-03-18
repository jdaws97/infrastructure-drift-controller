package cloud

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	pkgconfig "github.com/jdaws97/infrastructure-drift-controller/pkg/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/logging"
)

// CloudResource represents a resource in the cloud
type CloudResource struct {
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	ResourceName string                 `json:"resource_name"`
	Attributes   map[string]interface{} `json:"attributes"`
	Tags         map[string]string      `json:"tags"`
	Region       string                 `json:"region"`
	AccountID    string                 `json:"account_id"`
}

// ResourceQuery represents a query for cloud resources
type ResourceQuery struct {
	ResourceType string            `json:"resource_type"`
	Filters      map[string]string `json:"filters"`
}

// AWSQuerier is responsible for querying AWS resources
type AWSQuerier struct {
	config   *pkgconfig.AWSConfig
	logger   *logging.Logger
	awsCfg   aws.Config
	ec2Svc   *ec2.Client
	s3Svc    *s3.Client
	rdsSvc   *rds.Client
}

// NewAWSQuerier creates a new AWS querier
func NewAWSQuerier(cfg *pkgconfig.AWSConfig) (*AWSQuerier, error) {
	logger := logging.GetGlobalLogger().WithField("component", "aws_querier")
	
	// Load AWS SDK configuration
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(cfg.Region),
	}
	
	// Use AWS profile if specified
	if cfg.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(cfg.Profile))
	}
	
	// Load AWS configuration
	awsCfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}
	
	// Create AWS service clients
	ec2Svc := ec2.NewFromConfig(awsCfg)
	s3Svc := s3.NewFromConfig(awsCfg)
	rdsSvc := rds.NewFromConfig(awsCfg)
	
	return &AWSQuerier{
		config:  cfg,
		logger:  logger,
		awsCfg:  awsCfg,
		ec2Svc:  ec2Svc,
		s3Svc:   s3Svc,
		rdsSvc:  rdsSvc,
	}, nil
}

// GetResources queries AWS resources based on resource types
func (q *AWSQuerier) GetResources(ctx context.Context, resourceTypes []string) (map[string]CloudResource, error) {
	resources := make(map[string]CloudResource)
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}
	
	// Create a semaphore channel for concurrency control
	semaphore := make(chan struct{}, q.config.MaxConcurrency)
	
	// Process each resource type concurrently
	for _, resourceType := range resourceTypes {
		wg.Add(1)
		go func(rt string) {
			defer wg.Done()
			
			// Acquire semaphore token
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Query resources by type
			results, err := q.queryResourcesByType(ctx, rt)
			if err != nil {
				q.logger.Error(err, "Failed to query AWS resources of type %s", rt)
				return
			}
			
			// Store results
			mu.Lock()
			for id, resource := range results {
				resources[id] = resource
			}
			mu.Unlock()
		}(resourceType)
	}
	
	// Wait for all queries to complete
	wg.Wait()
	
	q.logger.Info("Retrieved %d AWS resources", len(resources))
	return resources, nil
}

// queryResourcesByType queries AWS resources based on their type
func (q *AWSQuerier) queryResourcesByType(ctx context.Context, resourceType string) (map[string]CloudResource, error) {
	switch resourceType {
	case "aws_instance":
		return q.queryEC2Instances(ctx)
	case "aws_vpc":
		return q.queryVPCs(ctx)
	case "aws_subnet":
		return q.querySubnets(ctx)
	case "aws_security_group":
		return q.querySecurityGroups(ctx)
	case "aws_s3_bucket":
		return q.queryS3Buckets(ctx)
	case "aws_db_instance":
		return q.queryRDSInstances(ctx)
	default:
		q.logger.Warn("Unsupported AWS resource type: %s", resourceType)
		return nil, nil
	}
}

// queryEC2Instances queries EC2 instances
func (q *AWSQuerier) queryEC2Instances(ctx context.Context) (map[string]CloudResource, error) {
	resources := make(map[string]CloudResource)
	
	// Query EC2 instances
	result, err := q.ec2Svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe EC2 instances: %w", err)
	}
	
	// Process results
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			// Create resource ID
			resourceID := aws.ToString(instance.InstanceId)
			
			// Extract attributes
			attributes := map[string]interface{}{
				"id":                resourceID,
				"ami":               aws.ToString(instance.ImageId),
				"instance_type":     instance.InstanceType,
				"availability_zone": aws.ToString(instance.Placement.AvailabilityZone),
				"vpc_id":            aws.ToString(instance.VpcId),
				"subnet_id":         aws.ToString(instance.SubnetId),
				"state":             instance.State.Name,
			}
			
			// Extract tags
			tags := make(map[string]string)
			for _, tag := range instance.Tags {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			
			// Get name from tags
			name := resourceID
			if val, ok := tags["Name"]; ok {
				name = val
			}
			
			// Store resource
			resources[resourceID] = CloudResource{
				ResourceType: "aws_instance",
				ResourceID:   resourceID,
				ResourceName: name,
				Attributes:   attributes,
				Tags:         tags,
				Region:       q.config.Region,
			}
		}
	}
	
	return resources, nil
}

// queryVPCs queries VPCs
// queryVPCs queries VPCs
func (q *AWSQuerier) queryVPCs(ctx context.Context) (map[string]CloudResource, error) {
	resources := make(map[string]CloudResource)
	
	// Query VPCs
	result, err := q.ec2Svc.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPCs: %w", err)
	}
	
	// Process results
	for _, vpc := range result.Vpcs {
		// Create resource ID
		resourceID := aws.ToString(vpc.VpcId)
		
		// Extract attributes
		attributes := map[string]interface{}{
			"id":         resourceID,
			"cidr_block": aws.ToString(vpc.CidrBlock),
			"is_default": aws.ToBool(vpc.IsDefault),
			"state":      vpc.State,
		}
		
		// Get DNS attributes through additional API calls
		dnsSupport, err := q.ec2Svc.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
			VpcId:     vpc.VpcId,
			Attribute: "enableDnsSupport",
		})
		if err == nil && dnsSupport.EnableDnsSupport != nil {
			attributes["enable_dns_support"] = aws.ToBool(dnsSupport.EnableDnsSupport.Value)
		}
		
		dnsHostnames, err := q.ec2Svc.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
			VpcId:     vpc.VpcId,
			Attribute: "enableDnsHostnames",
		})
		if err == nil && dnsHostnames.EnableDnsHostnames != nil {
			attributes["enable_dns_hostnames"] = aws.ToBool(dnsHostnames.EnableDnsHostnames.Value)
		}
		
		// Extract tags
		tags := make(map[string]string)
		for _, tag := range vpc.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		
		// Get name from tags
		name := resourceID
		if val, ok := tags["Name"]; ok {
			name = val
		}
		
		// Store resource
		resources[resourceID] = CloudResource{
			ResourceType: "aws_vpc",
			ResourceID:   resourceID,
			ResourceName: name,
			Attributes:   attributes,
			Tags:         tags,
			Region:       q.config.Region,
		}
	}
	
	return resources, nil
}

// querySubnets queries Subnets
func (q *AWSQuerier) querySubnets(ctx context.Context) (map[string]CloudResource, error) {
	resources := make(map[string]CloudResource)
	
	// Query Subnets
	result, err := q.ec2Svc.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Subnets: %w", err)
	}
	
	// Process results
	for _, subnet := range result.Subnets {
		// Create resource ID
		resourceID := aws.ToString(subnet.SubnetId)
		
		// Extract attributes
		attributes := map[string]interface{}{
			"id":                      resourceID,
			"vpc_id":                  aws.ToString(subnet.VpcId),
			"cidr_block":              aws.ToString(subnet.CidrBlock),
			"availability_zone":       aws.ToString(subnet.AvailabilityZone),
			"map_public_ip_on_launch": aws.ToBool(subnet.MapPublicIpOnLaunch),
			"state":                   subnet.State,
		}
		
		// Extract tags
		tags := make(map[string]string)
		for _, tag := range subnet.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		
		// Get name from tags
		name := resourceID
		if val, ok := tags["Name"]; ok {
			name = val
		}
		
		// Store resource
		resources[resourceID] = CloudResource{
			ResourceType: "aws_subnet",
			ResourceID:   resourceID,
			ResourceName: name,
			Attributes:   attributes,
			Tags:         tags,
			Region:       q.config.Region,
		}
	}
	
	return resources, nil
}

// querySecurityGroups queries Security Groups
func (q *AWSQuerier) querySecurityGroups(ctx context.Context) (map[string]CloudResource, error) {
	resources := make(map[string]CloudResource)
	
	// Query Security Groups
	result, err := q.ec2Svc.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Security Groups: %w", err)
	}
	
	// Process results
	for _, sg := range result.SecurityGroups {
		// Create resource ID
		resourceID := aws.ToString(sg.GroupId)
		
		// Extract attributes
		attributes := map[string]interface{}{
			"id":          resourceID,
			"name":        aws.ToString(sg.GroupName),
			"description": aws.ToString(sg.Description),
			"vpc_id":      aws.ToString(sg.VpcId),
		}
		
		// Process ingress rules
		var ingressRules []map[string]interface{}
		for _, rule := range sg.IpPermissions {
			for _, ipRange := range rule.IpRanges {
				ingressRule := map[string]interface{}{
					"from_port":   rule.FromPort,
					"to_port":     rule.ToPort,
					"protocol":    aws.ToString(rule.IpProtocol),
					"cidr_blocks": aws.ToString(ipRange.CidrIp),
					"description": aws.ToString(ipRange.Description),
				}
				ingressRules = append(ingressRules, ingressRule)
			}
		}
		attributes["ingress"] = ingressRules
		
		// Process egress rules
		var egressRules []map[string]interface{}
		for _, rule := range sg.IpPermissionsEgress {
			for _, ipRange := range rule.IpRanges {
				egressRule := map[string]interface{}{
					"from_port":   rule.FromPort,
					"to_port":     rule.ToPort,
					"protocol":    aws.ToString(rule.IpProtocol),
					"cidr_blocks": aws.ToString(ipRange.CidrIp),
					"description": aws.ToString(ipRange.Description),
				}
				egressRules = append(egressRules, egressRule)
			}
		}
		attributes["egress"] = egressRules
		
		// Extract tags
		tags := make(map[string]string)
		for _, tag := range sg.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		
		// Store resource
		resources[resourceID] = CloudResource{
			ResourceType: "aws_security_group",
			ResourceID:   resourceID,
			ResourceName: aws.ToString(sg.GroupName),
			Attributes:   attributes,
			Tags:         tags,
			Region:       q.config.Region,
		}
	}
	
	return resources, nil
}

// queryS3Buckets queries S3 buckets
func (q *AWSQuerier) queryS3Buckets(ctx context.Context) (map[string]CloudResource, error) {
	resources := make(map[string]CloudResource)
	
	// Query S3 buckets
	result, err := q.s3Svc.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 buckets: %w", err)
	}
	
	// Process results
	for _, bucket := range result.Buckets {
		// Create resource ID
		bucketName := aws.ToString(bucket.Name)
		
		// Extract attributes
		attributes := map[string]interface{}{
			"id":           bucketName,
			"bucket":       bucketName,
			"creation_date": bucket.CreationDate.String(),
		}
		
		// Get bucket region
		regionOutput, err := q.s3Svc.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: aws.String(bucketName),
		})
		
		bucketRegion := q.config.Region
		if err == nil && regionOutput.LocationConstraint != "" {
			bucketRegion = string(regionOutput.LocationConstraint)
		}
		
		// Get bucket tags
		tags := make(map[string]string)
		tagsOutput, err := q.s3Svc.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: aws.String(bucketName),
		})
		
		if err == nil {
			for _, tag := range tagsOutput.TagSet {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
		}
		
		// Store resource
		resources[bucketName] = CloudResource{
			ResourceType: "aws_s3_bucket",
			ResourceID:   bucketName,
			ResourceName: bucketName,
			Attributes:   attributes,
			Tags:         tags,
			Region:       bucketRegion,
		}
	}
	
	return resources, nil
}

// queryRDSInstances queries RDS instances
func (q *AWSQuerier) queryRDSInstances(ctx context.Context) (map[string]CloudResource, error) {
	resources := make(map[string]CloudResource)
	
	// Query RDS instances
	result, err := q.rdsSvc.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe RDS instances: %w", err)
	}
	
	// Process results
	for _, dbInstance := range result.DBInstances {
		// Create resource ID
		resourceID := aws.ToString(dbInstance.DBInstanceIdentifier)
		
		// Extract attributes
		attributes := map[string]interface{}{
			"id":                    resourceID,
			"db_instance_identifier": resourceID,
			"engine":                aws.ToString(dbInstance.Engine),
			"engine_version":        aws.ToString(dbInstance.EngineVersion),
			"instance_class":        aws.ToString(dbInstance.DBInstanceClass),
			"storage_type":          aws.ToString(dbInstance.StorageType),
			"allocated_storage":     dbInstance.AllocatedStorage,
			"endpoint":              aws.ToString(dbInstance.Endpoint.Address),
			"port":                  dbInstance.Endpoint.Port,
			"vpc_id":                aws.ToString(dbInstance.DBSubnetGroup.VpcId),
			"multi_az":              dbInstance.MultiAZ,
			"status":                aws.ToString(dbInstance.DBInstanceStatus),
		}
		
		// Extract tags
		tags := make(map[string]string)
		tagsOutput, err := q.rdsSvc.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{
			ResourceName: dbInstance.DBInstanceArn,
		})
		
		if err == nil {
			for _, tag := range tagsOutput.TagList {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
		}
		
		// Store resource
		resources[resourceID] = CloudResource{
			ResourceType: "aws_db_instance",
			ResourceID:   resourceID,
			ResourceName: resourceID,
			Attributes:   attributes,
			Tags:         tags,
			Region:       q.config.Region,
		}
	}
	
	return resources, nil
}

// GetResourcesByIDs retrieves specific AWS resources by their IDs and types
func (q *AWSQuerier) GetResourcesByIDs(ctx context.Context, resourceTypes map[string][]string) (map[string]CloudResource, error) {
	resources := make(map[string]CloudResource)
	errorsCh := make(chan error, len(resourceTypes))
	resourcesCh := make(chan CloudResource, 100)
	done := make(chan struct{})
	
	// Collect resources
	go func() {
		for resource := range resourcesCh {
			resources[resource.ResourceID] = resource
		}
		close(done)
	}()
	
	// Process each resource type concurrently
	var wg sync.WaitGroup
	for resourceType, ids := range resourceTypes {
		wg.Add(1)
		go func(rt string, resourceIDs []string) {
			defer wg.Done()
			
			err := q.queryResourcesByTypeAndIDs(ctx, rt, resourceIDs, resourcesCh)
			if err != nil {
				errorsCh <- fmt.Errorf("failed to query %s resources: %w", rt, err)
			}
		}(resourceType, ids)
	}
	
	// Wait for all queries to complete
	wg.Wait()
	close(resourcesCh)
	close(errorsCh)
	
	// Wait for resource collection
	<-done
	
	// Check for errors
	if len(errorsCh) > 0 {
		var errMsgs []string
		for err := range errorsCh {
			errMsgs = append(errMsgs, err.Error())
		}
		return resources, fmt.Errorf("encountered errors during AWS resource queries: %v", errMsgs)
	}
	
	return resources, nil
}

// queryResourcesByTypeAndIDs queries specific AWS resources by their IDs and type
func (q *AWSQuerier) queryResourcesByTypeAndIDs(ctx context.Context, resourceType string, resourceIDs []string, resultCh chan<- CloudResource) error {
	switch resourceType {
	case "aws_instance":
		return q.queryEC2InstancesByIDs(ctx, resourceIDs, resultCh)
	case "aws_vpc":
		return q.queryVPCsByIDs(ctx, resourceIDs, resultCh)
	case "aws_subnet":
		return q.querySubnetsByIDs(ctx, resourceIDs, resultCh)
	case "aws_security_group":
		return q.querySecurityGroupsByIDs(ctx, resourceIDs, resultCh)
	case "aws_s3_bucket":
		return q.queryS3BucketsByNames(ctx, resourceIDs, resultCh)
	case "aws_db_instance":
		return q.queryRDSInstancesByIDs(ctx, resourceIDs, resultCh)
	default:
		q.logger.Warn("Unsupported AWS resource type: %s", resourceType)
		return nil
	}
}

// queryEC2InstancesByIDs queries specific EC2 instances by their IDs
func (q *AWSQuerier) queryEC2InstancesByIDs(ctx context.Context, instanceIDs []string, resultCh chan<- CloudResource) error {
	if len(instanceIDs) == 0 {
		return nil
	}
	
	// Convert string IDs to AWS strings
	var ids []string
	for _, id := range instanceIDs {
		ids = append(ids, id)
	}
	
	// Query EC2 instances
	result, err := q.ec2Svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: ids,
	})
	if err != nil {
		return fmt.Errorf("failed to describe EC2 instances: %w", err)
	}
	
	// Process results
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			// Create resource ID
			resourceID := aws.ToString(instance.InstanceId)
			
			// Extract attributes
			attributes := map[string]interface{}{
				"id":                resourceID,
				"ami":               aws.ToString(instance.ImageId),
				"instance_type":     instance.InstanceType,
				"availability_zone": aws.ToString(instance.Placement.AvailabilityZone),
				"vpc_id":            aws.ToString(instance.VpcId),
				"subnet_id":         aws.ToString(instance.SubnetId),
				"state":             instance.State.Name,
			}
			
			// Extract tags
			tags := make(map[string]string)
			for _, tag := range instance.Tags {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			
			// Get name from tags
			name := resourceID
			if val, ok := tags["Name"]; ok {
				name = val
			}
			
			// Send resource
			resultCh <- CloudResource{
				ResourceType: "aws_instance",
				ResourceID:   resourceID,
				ResourceName: name,
				Attributes:   attributes,
				Tags:         tags,
				Region:       q.config.Region,
			}
		}
	}
	
	return nil
}

// queryVPCsByIDs queries specific VPCs by their IDs
func (q *AWSQuerier) queryVPCsByIDs(ctx context.Context, vpcIDs []string, resultCh chan<- CloudResource) error {
	if len(vpcIDs) == 0 {
		return nil
	}
	
	// Query VPCs
	result, err := q.ec2Svc.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		VpcIds: vpcIDs,
	})
	if err != nil {
		return fmt.Errorf("failed to describe VPCs: %w", err)
	}
	
	// Process results
	for _, vpc := range result.Vpcs {
		// Create resource ID
		resourceID := aws.ToString(vpc.VpcId)
		
		// Extract attributes
		attributes := map[string]interface{}{
			"id":         resourceID,
			"cidr_block": aws.ToString(vpc.CidrBlock),
			"is_default": aws.ToBool(vpc.IsDefault),
			"state":      vpc.State,
		}
		
		// Get DNS attributes through additional API calls
		dnsSupport, err := q.ec2Svc.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
			VpcId:     vpc.VpcId,
			Attribute: "enableDnsSupport",
		})
		if err == nil && dnsSupport.EnableDnsSupport != nil {
			attributes["enable_dns_support"] = aws.ToBool(dnsSupport.EnableDnsSupport.Value)
		}
		
		dnsHostnames, err := q.ec2Svc.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
			VpcId:     vpc.VpcId,
			Attribute: "enableDnsHostnames",
		})
		if err == nil && dnsHostnames.EnableDnsHostnames != nil {
			attributes["enable_dns_hostnames"] = aws.ToBool(dnsHostnames.EnableDnsHostnames.Value)
		}
		
		// Extract tags
		tags := make(map[string]string)
		for _, tag := range vpc.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		
		// Get name from tags
		name := resourceID
		if val, ok := tags["Name"]; ok {
			name = val
		}
		
		// Send resource
		resultCh <- CloudResource{
			ResourceType: "aws_vpc",
			ResourceID:   resourceID,
			ResourceName: name,
			Attributes:   attributes,
			Tags:         tags,
			Region:       q.config.Region,
		}
	}
	
	return nil
}

// querySubnetsByIDs queries specific Subnets by their IDs
func (q *AWSQuerier) querySubnetsByIDs(ctx context.Context, subnetIDs []string, resultCh chan<- CloudResource) error {
	if len(subnetIDs) == 0 {
		return nil
	}
	
	// Query Subnets
	result, err := q.ec2Svc.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		SubnetIds: subnetIDs,
	})
	if err != nil {
		return fmt.Errorf("failed to describe Subnets: %w", err)
	}
	
	// Process results
	for _, subnet := range result.Subnets {
		// Create resource ID
		resourceID := aws.ToString(subnet.SubnetId)
		
		// Extract attributes
		attributes := map[string]interface{}{
			"id":                      resourceID,
			"vpc_id":                  aws.ToString(subnet.VpcId),
			"cidr_block":              aws.ToString(subnet.CidrBlock),
			"availability_zone":       aws.ToString(subnet.AvailabilityZone),
			"map_public_ip_on_launch": aws.ToBool(subnet.MapPublicIpOnLaunch),
			"state":                   subnet.State,
		}
		
		// Extract tags
		tags := make(map[string]string)
		for _, tag := range subnet.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		
		// Get name from tags
		name := resourceID
		if val, ok := tags["Name"]; ok {
			name = val
		}
		
		// Send resource
		resultCh <- CloudResource{
			ResourceType: "aws_subnet",
			ResourceID:   resourceID,
			ResourceName: name,
			Attributes:   attributes,
			Tags:         tags,
			Region:       q.config.Region,
		}
	}
	
	return nil
}

// querySecurityGroupsByIDs queries specific Security Groups by their IDs
func (q *AWSQuerier) querySecurityGroupsByIDs(ctx context.Context, sgIDs []string, resultCh chan<- CloudResource) error {
	if len(sgIDs) == 0 {
		return nil
	}
	
	// Query Security Groups
	result, err := q.ec2Svc.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: sgIDs,
	})
	if err != nil {
		return fmt.Errorf("failed to describe Security Groups: %w", err)
	}
	
	// Process results
	for _, sg := range result.SecurityGroups {
		// Create resource ID
		resourceID := aws.ToString(sg.GroupId)
		
		// Extract attributes
		attributes := map[string]interface{}{
			"id":          resourceID,
			"name":        aws.ToString(sg.GroupName),
			"description": aws.ToString(sg.Description),
			"vpc_id":      aws.ToString(sg.VpcId),
		}
		
		// Process ingress rules
		var ingressRules []map[string]interface{}
		for _, rule := range sg.IpPermissions {
			for _, ipRange := range rule.IpRanges {
				ingressRule := map[string]interface{}{
					"from_port":   rule.FromPort,
					"to_port":     rule.ToPort,
					"protocol":    aws.ToString(rule.IpProtocol),
					"cidr_blocks": aws.ToString(ipRange.CidrIp),
					"description": aws.ToString(ipRange.Description),
				}
				ingressRules = append(ingressRules, ingressRule)
			}
		}
		attributes["ingress"] = ingressRules
		
		// Process egress rules
		var egressRules []map[string]interface{}
		for _, rule := range sg.IpPermissionsEgress {
			for _, ipRange := range rule.IpRanges {
				egressRule := map[string]interface{}{
					"from_port":   rule.FromPort,
					"to_port":     rule.ToPort,
					"protocol":    aws.ToString(rule.IpProtocol),
					"cidr_blocks": aws.ToString(ipRange.CidrIp),
					"description": aws.ToString(ipRange.Description),
				}
				egressRules = append(egressRules, egressRule)
			}
		}
		attributes["egress"] = egressRules
		
		// Extract tags
		tags := make(map[string]string)
		for _, tag := range sg.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		
		// Send resource
		resultCh <- CloudResource{
			ResourceType: "aws_security_group",
			ResourceID:   resourceID,
			ResourceName: aws.ToString(sg.GroupName),
			Attributes:   attributes,
			Tags:         tags,
			Region:       q.config.Region,
		}
	}
	
	return nil
}

// queryS3BucketsByNames queries specific S3 buckets by their names
func (q *AWSQuerier) queryS3BucketsByNames(ctx context.Context, bucketNames []string, resultCh chan<- CloudResource) error {
	if len(bucketNames) == 0 {
		return nil
	}
	
	// Process each bucket individually
	for _, bucketName := range bucketNames {
		// Verify the bucket exists
		_, err := q.s3Svc.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			q.logger.Warn("Bucket %s not found or access denied: %v", bucketName, err)
			continue
		}
		
		// Extract attributes
		attributes := map[string]interface{}{
			"id":     bucketName,
			"bucket": bucketName,
		}
		
		// Get bucket region
		regionOutput, err := q.s3Svc.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: aws.String(bucketName),
		})
		
		bucketRegion := q.config.Region
		if err == nil && regionOutput.LocationConstraint != "" {
			bucketRegion = string(regionOutput.LocationConstraint)
		}
		
		// Get bucket tags
		tags := make(map[string]string)
		tagsOutput, err := q.s3Svc.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: aws.String(bucketName),
		})
		
		if err == nil {
			for _, tag := range tagsOutput.TagSet {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
		}
		
		// Send resource
		resultCh <- CloudResource{
			ResourceType: "aws_s3_bucket",
			ResourceID:   bucketName,
			ResourceName: bucketName,
			Attributes:   attributes,
			Tags:         tags,
			Region:       bucketRegion,
		}
	}
	
	return nil
}

// queryRDSInstancesByIDs queries specific RDS instances by their IDs
func (q *AWSQuerier) queryRDSInstancesByIDs(ctx context.Context, instanceIDs []string, resultCh chan<- CloudResource) error {
	if len(instanceIDs) == 0 {
		return nil
	}
	
	// Process each instance individually since RDS doesn't support batch filtering by multiple IDs
	for _, instanceID := range instanceIDs {
		// Query RDS instance
		result, err := q.rdsSvc.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
			DBInstanceIdentifier: aws.String(instanceID),
		})
		if err != nil {
			q.logger.Warn("RDS instance %s not found or access denied: %v", instanceID, err)
			continue
		}
		
		// Process results (should only be one)
		for _, dbInstance := range result.DBInstances {
			// Create resource ID
			resourceID := aws.ToString(dbInstance.DBInstanceIdentifier)
			
			// Extract attributes
			attributes := map[string]interface{}{
				"id":                     resourceID,
				"db_instance_identifier": resourceID,
				"engine":                 aws.ToString(dbInstance.Engine),
				"engine_version":         aws.ToString(dbInstance.EngineVersion),
				"instance_class":         aws.ToString(dbInstance.DBInstanceClass),
				"storage_type":           aws.ToString(dbInstance.StorageType),
				"allocated_storage":      dbInstance.AllocatedStorage,
				"endpoint":               aws.ToString(dbInstance.Endpoint.Address),
				"port":                   dbInstance.Endpoint.Port,
				"vpc_id":                 aws.ToString(dbInstance.DBSubnetGroup.VpcId),
				"multi_az":               dbInstance.MultiAZ,
				"status":                 aws.ToString(dbInstance.DBInstanceStatus),
			}
			
			// Extract tags
			tags := make(map[string]string)
			tagsOutput, err := q.rdsSvc.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{
				ResourceName: dbInstance.DBInstanceArn,
			})
			
			if err == nil {
				for _, tag := range tagsOutput.TagList {
					tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
				}
			}
			
			// Send resource
			resultCh <- CloudResource{
				ResourceType: "aws_db_instance",
				ResourceID:   resourceID,
				ResourceName: resourceID,
				Attributes:   attributes,
				Tags:         tags,
				Region:       q.config.Region,
			}
		}
	}
	
	return nil
}

// Additional query methods for other resource types would be implemented similarly
// For brevity, I'm only showing the EC2 instance query as an example
// In a complete implementation, you would add similar methods for other resource types

// GenerateResourceID generates a unique ID for resources that don't have one
func GenerateResourceID() string {
	return uuid.New().String()
}