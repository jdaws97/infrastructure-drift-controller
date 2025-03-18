package llm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jdaws97/infrastructure-drift-controller/pkg/config"
	"github.com/jdaws97/infrastructure-drift-controller/pkg/logging"
	"github.com/sashabaranov/go-openai"
)

// CompletionRequest represents a request for a completion from the LLM
type CompletionRequest struct {
	Prompt       string   `json:"prompt"`
	MaxTokens    int      `json:"max_tokens"`
	Temperature  float64  `json:"temperature"`
	StopSequences []string `json:"stop_sequences,omitempty"`
}

// CompletionResponse represents a response from the LLM
type CompletionResponse struct {
	Text      string `json:"text"`
	TokensUsed int    `json:"tokens_used"`
}

// LLMProvider represents the type of LLM provider
type LLMProvider string

// LLM providers
const (
	OpenAIProvider    LLMProvider = "openai"
	AnthropicProvider LLMProvider = "anthropic"
)

// Client is a client for interacting with LLM APIs
type Client struct {
	config        *config.LLMConfig
	provider      LLMProvider
	openaiClient  *openai.Client
	logger        *logging.Logger
}

// NewClient creates a new LLM client
func NewClient(cfg *config.LLMConfig) (*Client, error) {
	logger := logging.GetGlobalLogger().WithField("component", "llm_client")
	
	// Determine LLM provider
	var provider LLMProvider
	switch cfg.Provider {
	case "openai":
		provider = OpenAIProvider
	case "anthropic":
		provider = AnthropicProvider
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", cfg.Provider)
	}
	
	// Create provider-specific clients
	var openaiClient *openai.Client
	
	if provider == OpenAIProvider {
		openaiClient = openai.NewClient(cfg.APIKey)
	}
	
	// Note: For Anthropic, we would create an Anthropic client here
	// But for now, we'll just focus on OpenAI since that's more common
	
	return &Client{
		config:       cfg,
		provider:     provider,
		openaiClient: openaiClient,
		logger:       logger,
	}, nil
}

// Complete generates a completion using the LLM
func (c *Client) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	// Use client timeout if configured
	if c.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.Timeout)
		defer cancel()
	}
	
	// Apply default values if not specified
	if req.MaxTokens <= 0 {
		req.MaxTokens = c.config.MaxTokens
	}
	
	if req.Temperature < 0 {
		req.Temperature = c.config.Temperature
	}
	
	// Call the appropriate provider
	switch c.provider {
	case OpenAIProvider:
		return c.completeWithOpenAI(ctx, req)
	case AnthropicProvider:
		return c.completeWithAnthropic(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", c.provider)
	}
}

// completeWithOpenAI generates a completion using OpenAI
func (c *Client) completeWithOpenAI(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	c.logger.Info("Sending request to OpenAI, prompt length: %d chars", len(req.Prompt))
	
	// Convert stop sequences
	var stop []string
	if len(req.StopSequences) > 0 {
		stop = req.StopSequences
	}
	
	// Create chat request
	chatReq := openai.ChatCompletionRequest{
		Model: c.config.Model,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleUser,
				Content: req.Prompt,
			},
		},
		MaxTokens:   req.MaxTokens,
		Temperature: float32(req.Temperature),
		Stop:        stop,
	}
	
	// Send the request with retry logic
	var chatResp openai.ChatCompletionResponse
	var err error
	
	for attempt := 0; attempt <= c.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			c.logger.Info("Retrying OpenAI request (attempt %d/%d)...", attempt, c.config.RetryAttempts)
			time.Sleep(c.config.RetryDelay)
		}
		
		chatResp, err = c.openaiClient.CreateChatCompletion(ctx, chatReq)
		if err == nil {
			break
		}
		
		c.logger.Error(err, "OpenAI request failed")
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to get completion from OpenAI after %d attempts: %w", 
			c.config.RetryAttempts+1, err)
	}
	
	// Extract response text
	if len(chatResp.Choices) == 0 {
		return nil, errors.New("OpenAI returned empty response")
	}
	
	text := chatResp.Choices[0].Message.Content
	c.logger.Info("Received response from OpenAI, length: %d chars, tokens used: %d", 
		len(text), chatResp.Usage.TotalTokens)
	
	return &CompletionResponse{
		Text:      text,
		TokensUsed: chatResp.Usage.TotalTokens,
	}, nil
}

// completeWithAnthropic generates a completion using Anthropic
func (c *Client) completeWithAnthropic(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	// Note: This would implement the Anthropic API
	// For simplicity, we'll just return a placeholder error
	return nil, errors.New("Anthropic integration not implemented yet")
}