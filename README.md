# Infrastructure Drift Detector

An intelligent infrastructure drift detection tool that uses the ReAct (Reasoning & Acting) methodology with AI LLMs to identify and remediate drift in AWS resources managed by Terraform.

## Features

- **Terraform State Parsing**: Directly parse Terraform state files to understand the desired infrastructure state
- **AWS Cloud Querying**: Query AWS resources to compare against the Terraform state
- **Drift Detection**: Identify and categorize different types of infrastructure drift
- **LLM Integration**: Leverage AI to analyze drift and generate intelligent remediation plans
- **Remediation Workflows**: Automated or manual approval-based remediation processes
- **Scheduling**: Flexible scheduling for periodic drift detection
- **Extensibility**: Modular design for adding support for additional cloud providers and IaC tools

## Architecture

```
drift-detector/
├── cmd/
│   └── drift-detector/
│       └── main.go                 # Entry point
├── pkg/
│   ├── config/                     # Configuration management
│   │   └── config.go
│   ├── iac/                        # IaC state parsing
│   │   └── state_parser.go
│   ├── cloud/                      # Cloud querying
│   │   └── aws_querier.go
│   ├── drift/                      # Drift detection
│   │   └── detector.go
│   ├── llm/                        # LLM integration
│   │   ├── client.go
│   │   └── integrator.go
│   ├── remediation/                # Remediation triggering
│   │   └── trigger.go
│   ├── scheduler/                  # Scheduling logic
│   │   └── scheduler.go
│   └── logging/                    # Logging utilities
│       └── logger.go
├── internal/
│   └── app/                        # Application logic
│       └── app.go
├── Dockerfile                      # Container build
├── go.mod                          # Go dependencies
└── README.md                       # Documentation
```

## Installation

### Prerequisites

- Go 1.19 or later
- AWS credentials configured
- Terraform state file(s)
- API key for OpenAI or Anthropic (for LLM integration)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/drift-detector.git
cd drift-detector

# Build the binary
go build -o drift-detector ./cmd/drift-detector
```

### Using Docker

```bash
# Build the Docker image
docker build -t drift-detector .

# Run the container
docker run -v /path/to/config:/app/config -v /path/to/terraform/state:/app/tf drift-detector
```

## Configuration

Create a `config.yaml` file:

```yaml
app:
  name: "drift-detector"
  version: "0.1.0"

aws:
  region: "us-west-2"
  profile: "default"
  max_concurrency: 5

terraform:
  state_path: "/path/to/terraform.tfstate"
  resource_types:
    - "aws_instance"
    - "aws_s3_bucket"
    - "aws_vpc"
    - "aws_subnet"
    - "aws_security_group"
  ignore_resources:
    - "aws_instance.temporary"

llm:
  provider: "openai"
  model: "gpt-4"
  api_key: "${OPENAI_API_KEY}"
  max_tokens: 2048
  temperature: 0.2
  timeout: "30s"
  retry_attempts: 3
  retry_delay: "1s"

logging:
  level: "info"
  json_format: false
  file_path: "/path/to/logs/drift-detector.log"

scheduler:
  enabled: true
  cron_spec: "0 */6 * * *"
  time_zone: "UTC"

remediation:
  enabled: true
  approval_mode: "manual"
  notify_emails:
    - "admin@example.com"
    - "infra-team@example.com"
  max_attempts: 3
  approval_timeout: "24h"
```

## Usage

### Running the Drift Detector

```bash
# Basic usage
./drift-detector --config /path/to/config.yaml

# Verbose logging
./drift-detector --config /path/to/config.yaml --verbose

# Run once and exit
./drift-detector --config /path/to/config.yaml --one-shot

# Show version
./drift-detector --version
```

### Understanding Drift Reports

Drift reports are generated in JSON format and include:

- **Resource information**: Type, ID, and name of the resource
- **Drift type**: Missing, extra, attribute drift, or tag drift
- **Severity**: Low, medium, high, or critical
- **Differences**: Detailed list of attribute differences
- **Metadata**: Additional context about the resource

### Remediation Process

1. Drift detection identifies infrastructure drift
2. LLM analyzes the drift and generates a remediation plan
3. Remediation is created and enters the approval workflow
4. Depending on configuration, remediation is approved automatically or requires manual approval
5. Once approved, the remediation is executed
6. Results are reported back to the system

## Development

### Adding Support for New Resource Types

Extend the `aws_querier.go` file to add support for additional AWS resource types:

1. Add the resource type to the `queryResourcesByType` method
2. Implement a new method for querying that resource type
3. Add attribute mapping in the `getAttributeKeysToCompare` function in `detector.go`

### Adding Support for Other Cloud Providers

Create a new cloud querier that implements the same interface:

1. Create a new file (e.g., `azure_querier.go`) in the `cloud` package
2. Implement the required methods for querying cloud resources
3. Update the application to use the appropriate querier based on configuration

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- [Terraform](https://www.terraform.io/) for infrastructure as code
- [OpenAI](https://openai.com/) and [Anthropic](https://www.anthropic.com/) for LLM technologies
- [ReAct Paper](https://arxiv.org/abs/2210.03629) for the Reasoning & Acting methodology
