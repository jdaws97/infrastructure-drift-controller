package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	API          APIConfig
	Database     DatabaseConfig
	Detection    DetectionConfig
	Providers    ProvidersConfig
	Workflow     WorkflowConfig
	Notification NotificationConfig
}

// APIConfig holds API server configuration
type APIConfig struct {
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Driver   string
	Host     string
	Port     int
	User     string
	Password string
	Name     string
	SSLMode  string
}

// DetectionConfig holds drift detection configuration
type DetectionConfig struct {
	Interval time.Duration
	Workers  int
}

// ProvidersConfig holds provider-specific configuration
type ProvidersConfig struct {
	AWS   AWSConfig
	Azure AzureConfig
	GCP   GCPConfig
}

// AWSConfig holds AWS-specific configuration
type AWSConfig struct {
	Regions []string
}

// AzureConfig holds Azure-specific configuration
type AzureConfig struct {
	SubscriptionIDs []string
}

// GCPConfig holds GCP-specific configuration
type GCPConfig struct {
	Projects []string
}

// WorkflowConfig holds workflow engine configuration
type WorkflowConfig struct {
	DefaultApprovalTimeout time.Duration
}

// NotificationConfig holds notification configuration
type NotificationConfig struct {
	DefaultChannels []string               `mapstructure:"default_channels"`
	Slack           map[string]interface{} `mapstructure:"slack"`
	Email           map[string]interface{} `mapstructure:"email"`
	MatterMost      map[string]interface{} `mapstructure:"mattermost"`
	Teams           map[string]interface{} `mapstructure:"teams"`
	Webhook         map[string]interface{} `mapstructure:"webhook"`
}

// Load loads the application configuration from file and environment variables
func Load() (*Config, error) {
	// Set default config file path
	configPath := "config"
	if os.Getenv("CONFIG_PATH") != "" {
		configPath = os.Getenv("CONFIG_PATH")
	}

	// Initialize viper
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(configPath)
	v.AddConfigPath(".")

	// Set environment variable prefix
	v.SetEnvPrefix("IDC")
	v.AutomaticEnv()

	// Read the config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found, will rely on defaults and env vars
	}

	// Set defaults
	setDefaults(v)

	// Parse config into struct
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode config: %w", err)
	}

	return &config, nil
}

func setDefaults(v *viper.Viper) {
	// API defaults
	v.SetDefault("api.port", 8080)
	v.SetDefault("api.readTimeout", "5s")
	v.SetDefault("api.writeTimeout", "10s")

	// Database defaults
	v.SetDefault("database.driver", "postgres")
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.name", "idc")
	v.SetDefault("database.sslmode", "disable")

	// Detection defaults
	v.SetDefault("detection.interval", "5m")
	v.SetDefault("detection.workers", 10)

	// Workflow defaults
	v.SetDefault("workflow.defaultApprovalTimeout", "24h")

	// Notification defaults
	v.SetDefault("notification.slack", map[string]interface{}{})
	v.SetDefault("notification.email", map[string]interface{}{})
	v.SetDefault("notification.mattermost", map[string]interface{}{})
	v.SetDefault("notification.teams", map[string]interface{}{})
	v.SetDefault("notification.webhook", map[string]interface{}{})
	v.SetDefault("notification.default_channels", []string{})
}
