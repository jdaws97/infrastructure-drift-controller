package logging

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Logger represents the application logger
type Logger struct {
	logger zerolog.Logger
}

// LogLevel represents the logging level
type LogLevel string

// Log levels
const (
	DebugLevel LogLevel = "debug"
	InfoLevel  LogLevel = "info"
	WarnLevel  LogLevel = "warn"
	ErrorLevel LogLevel = "error"
	FatalLevel LogLevel = "fatal"
)

// Config holds logger configuration
type Config struct {
	Level      LogLevel
	JSONFormat bool
	Output     io.Writer
}

// DefaultConfig returns the default logger configuration
func DefaultConfig() Config {
	return Config{
		Level:      InfoLevel,
		JSONFormat: false,
		Output:     os.Stdout,
	}
}

// New creates a new logger instance
func New(config Config) *Logger {
	// Set global log level
	level, err := zerolog.ParseLevel(string(config.Level))
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Configure output format
	var output io.Writer = config.Output
	if !config.JSONFormat {
		output = zerolog.ConsoleWriter{
			Out:        config.Output,
			TimeFormat: time.RFC3339,
		}
	}

	// Create logger
	logger := zerolog.New(output).With().Timestamp().Caller().Logger()
	
	return &Logger{
		logger: logger,
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.logger.Debug().Msgf(msg, args...)
	} else {
		l.logger.Debug().Msg(msg)
	}
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.logger.Info().Msgf(msg, args...)
	} else {
		l.logger.Info().Msg(msg)
	}
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.logger.Warn().Msgf(msg, args...)
	} else {
		l.logger.Warn().Msg(msg)
	}
}

// Error logs an error message
func (l *Logger) Error(err error, msg string, args ...interface{}) {
	event := l.logger.Error().Err(err)
	if len(args) > 0 {
		event.Msgf(msg, args...)
	} else {
		event.Msg(msg)
	}
}

// Fatal logs a fatal message and exits the application
func (l *Logger) Fatal(err error, msg string, args ...interface{}) {
	event := l.logger.Fatal().Err(err)
	if len(args) > 0 {
		event.Msgf(msg, args...)
	} else {
		event.Msg(msg)
	}
}

// WithField adds a field to the logger
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return &Logger{
		logger: l.logger.With().Interface(key, value).Logger(),
	}
}

// WithFields adds multiple fields to the logger
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	ctx := l.logger.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return &Logger{
		logger: ctx.Logger(),
	}
}

// Global logger instance
var globalLogger = New(DefaultConfig())

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(logger *Logger) {
	globalLogger = logger
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() *Logger {
	return globalLogger
}

// Global convenience functions

// Debug logs a debug message using the global logger
func Debug(msg string, args ...interface{}) {
	globalLogger.Debug(msg, args...)
}

// Info logs an info message using the global logger
func Info(msg string, args ...interface{}) {
	globalLogger.Info(msg, args...)
}

// Warn logs a warning message using the global logger
func Warn(msg string, args ...interface{}) {
	globalLogger.Warn(msg, args...)
}

// Error logs an error message using the global logger
func Error(err error, msg string, args ...interface{}) {
	globalLogger.Error(err, msg, args...)
}

// Fatal logs a fatal message using the global logger and exits the application
func Fatal(err error, msg string, args ...interface{}) {
	globalLogger.Fatal(err, msg, args...)
}

// WithField adds a field to the global logger
func WithField(key string, value interface{}) *Logger {
	return globalLogger.WithField(key, value)
}

// WithFields adds multiple fields to the global logger
func WithFields(fields map[string]interface{}) *Logger {
	return globalLogger.WithFields(fields)
}