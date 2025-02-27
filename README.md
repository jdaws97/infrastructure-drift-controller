# Infrastructure Drift Controller (IDC)

## Quick Start Guide

### 1. Configuration

Create a configuration file `config.yaml`:

```yaml
providers:
  aws:
    regions:
      - us-east-1
      - us-west-2
  azure:
    subscriptions:
      - subscription-id-1
  gcp:
    projects:
      - project-id-1

detection:
  interval: 5m
  workers: 10

workflows:
  default:
    - type: notify
      channels:
        - slack-infrastructure

  critical:
    - type: approval
      min_approvals: 2
      approvers:
        - security-team
        - cloud-architects
    - type: remediate
      strategy: terraform-plan
```

### 2. Authentication

Supports multiple authentication methods:

- AWS: IAM Roles, Access Keys
- Azure: Service Principal, Managed Identity
- GCP: Service Account JSON
- Kubernetes: Kubeconfig

### 3. Running IDC

```bash
# Install
go install github.com/yourusername/infrastructure-drift-controller

# Run
idc start --config config.yaml
```

### 4. Creating Custom Workflows

Extend workflow templates in your configuration or via API:

```yaml
workflows:
  high-risk-databases:
    resource_types:
      - rds_instance
      - azure_sql_database
    actions:
      - type: notify
        message: "High-risk database drift detected"
      - type: approval
        approvers:
          - database-admin
```

## Features

- 🌐 Multi-Cloud Support
- 🛡️ Customizable Drift Detection
- 🔔 Flexible Notifications
- 🤖 Automatic Remediation
- 📊 Comprehensive Reporting

