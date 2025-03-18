drift-detector/
├── cmd/
│ └── drift-detector/
│ └── main.go # Entry point
├── pkg/
│ ├── config/ # Configuration management
│ │ └── config.go
│ ├── iac/ # IaC state parsing
│ │ └── state_parser.go
│ ├── cloud/ # Cloud querying
│ │ └── aws_querier.go
│ ├── drift/ # Drift detection
│ │ └── detector.go
│ ├── llm/ # LLM integration
│ │ ├── client.go
│ │ └── integrator.go
│ ├── remediation/ # Remediation triggering
│ │ └── trigger.go
│ ├── scheduler/ # Scheduling logic
│ │ └── scheduler.go
│ └── logging/ # Logging utilities
│ └── logger.go
├── internal/
│ └── app/ # Application logic
│ └── app.go
├── Dockerfile # Container build (no Terraform)
├── go.mod # Go dependencies
└── README.md # Documentation
