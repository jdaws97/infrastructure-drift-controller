infrastructure-drift-controller/
│
├── cmd/ # Command line entry points
│ ├── server/ # API server
│ └── cli/ # CLI tool
│
├── pkg/ # Core packages
│ ├── api/ # API definitions
│ │ ├── rest/ # REST API handlers
│ │ └── grpc/ # gRPC service definitions (optional)
│ │
│ ├── models/ # Domain models
│ │ ├── resource.go # Resource representation
│ │ ├── state.go # State tracking
│ │ └── drift.go # Drift detection models
│ │
│ ├── engine/ # Core business logic
│ │ ├── parser/ # Universal IaC parser
│ │ │ ├── terraform/ # Terraform adapter
│ │ │ ├── cloudformation/ # CloudFormation adapter
│ │ │ ├── pulumi/ # Pulumi adapter
│ │ │ └── ansible/ # Ansible adapter
│ │ │
│ │ ├── collector/ # State collection
│ │ │ ├── aws/ # AWS adapter
│ │ │ ├── azure/ # Azure adapter
│ │ │ ├── gcp/ # GCP adapter
│ │ │ └── kubernetes/ # Kubernetes adapter
│ │ │
│ │ ├── detector/ # Drift detection logic
│ │ └── reconciler/ # Reconciliation logic
│ │
│ ├── workflow/ # Workflow engine
│ │ ├── actions/ # Action definitions
│ │ ├── approval/ # Approval chains
│ │ └── templates/ # Predefined workflow templates
│ │
│ ├── notification/ # Notification systems
│ │ ├── slack/ # Slack integration
│ │ ├── email/ # Email notifications
│ │ ├── teams/ # MS Teams integration
│ │ └── webhook/ # Generic webhook support
│ │
│ └── storage/ # Storage backends
│ ├── database/ # Database interactions
│ └── cache/ # Caching layer
│
├── internal/ # Internal packages
│ ├── config/ # Configuration
│ ├── auth/ # Authentication
│ └── metrics/ # Metrics and monitoring
│
├── web/ # Web UI
│ ├── src/ # Frontend source code
│ ├── public/ # Static assets
│ └── build/ # Build artifacts
│
├── test/ # Test files
│ ├── unit/ # Unit tests
│ ├── integration/ # Integration tests
│ └── fixtures/ # Test fixtures
│
├── deployments/ # Deployment configurations
│ ├── docker/ # Docker files
│ ├── kubernetes/ # Kubernetes manifests
│ └── terraform/ # Terraform for deploying the tool itself
│
├── docs/ # Documentation
│ ├── api/ # API documentation
│ ├── architecture/ # Architecture details
│ └── user/ # User guides
│
├── examples/ # Example configurations and usage
│ ├── workflows/ # Example workflows
│ └── providers/ # Provider-specific examples
│
├── scripts/ # Utility scripts
│
├── go.mod # Go module definition
├── go.sum # Go module checksums
├── Makefile # Build automation
└── README.md # Project overview
