graph TB
subgraph "User Interfaces"
UI[Web UI]
CLI[CLI Tool]
API[REST API]
end

    subgraph "Core Components"
        Collector[State Collector]
        Parser[Universal Parser]
        DriftEngine[Drift Detection Engine]
        Workflows[Workflow Engine]
        StateMgr[State Manager]
    end

    subgraph "Integration Layer"
        ProviderAdapters[Provider Adapters]
        IaCAdapters[IaC Adapters]
        NotificationSvc[Notification Service]
        ReconSvc[Reconciliation Service]
    end

    subgraph "Providers"
        AWS[AWS API]
        Azure[Azure API]
        GCP[GCP API]
        Others[Other Providers]
    end

    subgraph "IaC Tools"
        Terraform[Terraform]
        Pulumi[Pulumi]
        CFN[CloudFormation]
        Ansible[Ansible]
        ARM[ARM Templates]
    end

    subgraph "Notification Channels"
        Slack[Slack]
        Email[Email]
        Teams[Teams]
        Custom[Custom Webhooks]
    end

    subgraph "Data Store"
        DB[(Database)]
    end

    UI --> API
    CLI --> API
    API --> Parser
    API --> DriftEngine
    API --> Workflows

    IaCAdapters --> Parser
    Parser --> StateMgr

    ProviderAdapters --> Collector
    Collector --> StateMgr

    StateMgr --> DB

    StateMgr --> DriftEngine
    DriftEngine --> Workflows
    Workflows --> NotificationSvc
    Workflows --> ReconSvc

    NotificationSvc --> Slack
    NotificationSvc --> Email
    NotificationSvc --> Teams
    NotificationSvc --> Custom

    ReconSvc --> ProviderAdapters

    IaCAdapters --> Terraform
    IaCAdapters --> Pulumi
    IaCAdapters --> CFN
    IaCAdapters --> Ansible
    IaCAdapters --> ARM

    ProviderAdapters --> AWS
    ProviderAdapters --> Azure
    ProviderAdapters --> GCP
    ProviderAdapters --> Others
