package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/logging"
	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	App        AppConfig        `mapstructure:"app" validate:"required"`
	AWS        AWSConfig        `mapstructure:"aws" validate:"required"`
	Terraform  TerraformConfig  `mapstructure:"terraform" validate:"required"`
	LLM        LLMConfig        `mapstructure:"llm" validate:"required"`
	Logging    LoggingConfig    `mapstructure:"logging" validate:"required"`
	Scheduler  SchedulerConfig  `mapstructure:"scheduler" validate:"required"`
	Remediation RemediationConfig `mapstructure:"remediation" validate:"required"`
}

// AppConfig holds application-specific configuration
type AppConfig struct {
	Name    string `mapstructure:"name" validate:"required"`
	Version string `mapstructure:"version" validate:"required"`
}

// AWSConfig holds AWS-specific configuration
type AWSConfig struct {
	Region          string `mapstructure:"region" validate:"required"`
	Profile         string `mapstructure:"profile"`
	MaxConcurrency  int    `mapstructure:"max_concurrency" validate:"required,min=1"`
	AssumeRoleARN   string `mapstructure:"assume_role_arn"`
	RoleSessionName string `mapstructure:"role_session_name"`
}

// TerraformConfig holds Terraform-specific configuration
type TerraformConfig struct {
	StatePath      string   `mapstructure:"state_path" validate:"required"`
	ResourceTypes  []string `mapstructure:"resource_types" validate:"required,min=1"`
	IgnoreResources []string `mapstructure:"ignore_resources"`
}

// LLMConfig holds LLM-specific configuration
type LLMConfig struct {
	Provider     string        `mapstructure:"provider" validate:"required,oneof=openai anthropic"`
	Model        string        `mapstructure:"model" validate:"required"`
	APIKey       string        `mapstructure:"api_key" validate:"required"`
	MaxTokens    int           `mapstructure:"max_tokens" validate:"required,min=1"`
	Temperature  float64       `mapstructure:"temperature" validate:"required,min=0,max=1"`
	Timeout      time.Duration `mapstructure:"timeout" validate:"required"`
	RetryAttempts int          `mapstructure:"retry_attempts" validate:"required,min=0"`
	RetryDelay    time.Duration `mapstructure:"retry_delay" validate:"required"`
}

// LoggingConfig holds logging-specific configuration
type LoggingConfig struct {
	Level      string `mapstructure:"level" validate:"required,oneof=debug info warn error fatal"`
	JSONFormat bool   `mapstructure:"json_format"`
	FilePath   string `mapstructure:"file_path"`
}

// SchedulerConfig holds scheduler-specific configuration
type SchedulerConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	CronSpec  string `mapstructure:"cron_spec" validate:"required_if=Enabled true"`
	TimeZone  string `mapstructure:"time_zone"`
}

// RemediationConfig holds remediation-specific configuration
type RemediationConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	ApprovalMode  string   `mapstructure:"approval_mode" validate:"required,oneof=auto manual"`
	NotifyEmails  []string `mapstructure:"notify_emails" validate:"required_if=ApprovalMode manual,dive,email"`
	MaxAttempts   int      `mapstructure:"max_attempts" validate:"required,min=1"`
	ApprovalTimeout time.Duration `mapstructure:"approval_timeout" validate:"required_if=ApprovalMode manual"`
}

// LoadConfig loads the application configuration from a file
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()
	
	// Set default configuration values
	setDefaults(v)
	
	// Read configuration file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("/etc/drift-detector")
	}
	
	// Enable environment variable overrides
	v.SetEnvPrefix("DRIFT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	
	// Read configuration
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		logging.Warn("Config file not found, using defaults and environment variables")
	}
	
	// Parse configuration
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Validate configuration
	validate := validator.New()
	if err := validate.Struct(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Special case: LLM API key from environment variable
	if config.LLM.APIKey == "" {
		apiKey := os.Getenv("DRIFT_LLM_API_KEY")
		if apiKey == "" {
			return nil, fmt.Errorf("LLM API key is required, set it in config or DRIFT_LLM_API_KEY env var")
		}
		config.LLM.APIKey = apiKey
	}
	
	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// App defaults
	v.SetDefault("app.name", "drift-detector")
	v.SetDefault("app.version", "0.1.0")
	
	// AWS defaults
	v.SetDefault("aws.region", "us-west-2")
	v.SetDefault("aws.max_concurrency", 5)
	
	// Terraform defaults
	v.SetDefault("terraform.resource_types", []string{
		"aws_instance", 
		"aws_s3_bucket", 
		"aws_vpc", 
		"aws_subnet",
		"aws_security_group",
	})
	
	// LLM defaults
	v.SetDefault("llm.provider", "openai")
	v.SetDefault("llm.model", "gpt-4")
	v.SetDefault("llm.max_tokens", 2048)
	v.SetDefault("llm.temperature", 0.2)
	v.SetDefault("llm.timeout", 30*time.Second)
	v.SetDefault("llm.retry_attempts", 3)
	v.SetDefault("llm.retry_delay", 1*time.Second)
	
	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.json_format", false)
	
	// Scheduler defaults
	v.SetDefault("scheduler.enabled", true)
	v.SetDefault("scheduler.cron_spec", "0 */6 * * *") // Every 6 hours
	v.SetDefault("scheduler.time_zone", "UTC")
	
	// Remediation defaults
	v.SetDefault("remediation.enabled", false)
	v.SetDefault("remediation.approval_mode", "manual")
	v.SetDefault("remediation.max_attempts", 3)
	v.SetDefault("remediation.approval_timeout", 24*time.Hour)
}