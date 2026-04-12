package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LLMConfig holds configuration for the LLM evaluator.
type LLMConfig struct {
	Provider string        `json:"provider"` // "ollama", "bedrock", "anthropic", "openai"
	Model    string        `json:"model"`
	Prompt   string        `json:"prompt"`   // template with {{request_json}} placeholder
	Timeout  time.Duration `json:"timeout"`  // default 10s
	Fallback string        `json:"fallback"` // "allow" or "deny", default "deny"
}

// LLMEvaluator calls an LLM API to make policy decisions.
type LLMEvaluator struct {
	config    LLMConfig
	providers map[string]LLMProviderConfig
}

// NewLLMEvaluator creates an LLMEvaluator from a generic config map.
func NewLLMEvaluator(config map[string]any, providers map[string]LLMProviderConfig) (*LLMEvaluator, error) {
	var lc LLMConfig

	if v, ok := config["provider"]; ok {
		if s, ok := v.(string); ok {
			lc.Provider = s
		}
	}
	if v, ok := config["model"]; ok {
		if s, ok := v.(string); ok {
			lc.Model = s
		}
	}
	if v, ok := config["prompt"]; ok {
		if s, ok := v.(string); ok {
			lc.Prompt = s
		}
	}
	if v, ok := config["fallback"]; ok {
		if s, ok := v.(string); ok {
			lc.Fallback = s
		}
	}

	lc.Timeout = parseTimeout(config["timeout"], 10*time.Second)

	if lc.Provider == "" {
		return nil, fmt.Errorf("llm evaluator: provider is required")
	}
	if lc.Prompt == "" {
		return nil, fmt.Errorf("llm evaluator: prompt template is required")
	}
	if lc.Fallback == "" || lc.Fallback == "allow" {
		// Security: fallback="allow" would auto-allow on any LLM error.
		// Always override to "deny" for fail-closed behavior.
		lc.Fallback = "deny"
	}

	return &LLMEvaluator{
		config:    lc,
		providers: providers,
	}, nil
}

// Type returns the evaluator type identifier.
func (l *LLMEvaluator) Type() string {
	return "llm"
}

// Evaluate calls the LLM provider and parses the response for a policy decision.
func (l *LLMEvaluator) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error) {
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return l.fallbackDecision("failed to marshal request: " + err.Error()), nil
	}

	prompt := strings.ReplaceAll(l.config.Prompt, "{{request_json}}", string(reqJSON))

	switch l.config.Provider {
	case "ollama":
		return l.evaluateOllama(ctx, prompt)
	case "bedrock", "anthropic", "openai":
		return nil, fmt.Errorf("llm evaluator: provider %q is not yet implemented", l.config.Provider)
	default:
		return nil, fmt.Errorf("llm evaluator: unknown provider %q", l.config.Provider)
	}
}

// evaluateOllama calls the Ollama /api/generate endpoint.
func (l *LLMEvaluator) evaluateOllama(ctx context.Context, prompt string) (*PolicyDecision, error) {
	timeout := l.config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := "http://localhost:11434"
	if pc, ok := l.providers[l.config.Provider]; ok && pc.Endpoint != "" {
		endpoint = pc.Endpoint
	}

	model := l.config.Model
	if model == "" {
		if pc, ok := l.providers[l.config.Provider]; ok && pc.Model != "" {
			model = pc.Model
		}
	}

	body := map[string]any{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return l.fallbackDecision("failed to marshal ollama request: " + err.Error()), nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/generate", bytes.NewReader(bodyBytes))
	if err != nil {
		return l.fallbackDecision("failed to create HTTP request: " + err.Error()), nil
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return l.fallbackDecision("ollama request failed: " + err.Error()), nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return l.fallbackDecision("failed to read ollama response: " + err.Error()), nil
	}

	if resp.StatusCode != http.StatusOK {
		return l.fallbackDecision(fmt.Sprintf("ollama returned status %d: %s", resp.StatusCode, string(respBody))), nil
	}

	// Parse the Ollama response to extract the generated text.
	var ollamaResp struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return l.fallbackDecision("failed to parse ollama response: " + err.Error()), nil
	}

	// Try to extract a JSON decision from the generated text.
	decision, err := extractDecisionFromText(ollamaResp.Response)
	if err != nil {
		return l.fallbackDecision("failed to extract decision from LLM response: " + err.Error()), nil
	}

	return decision, nil
}

// extractDecisionFromText looks for a JSON object with "action" and "reason" in the text.
func extractDecisionFromText(text string) (*PolicyDecision, error) {
	// Try to find a JSON object in the text.
	start := strings.Index(text, "{")
	if start == -1 {
		return nil, fmt.Errorf("no JSON object found in response")
	}

	// Find the matching closing brace.
	depth := 0
	end := -1
	for i := start; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i + 1
				break
			}
		}
		if end != -1 {
			break
		}
	}

	if end == -1 {
		return nil, fmt.Errorf("no complete JSON object found in response")
	}

	var decision PolicyDecision
	if err := json.Unmarshal([]byte(text[start:end]), &decision); err != nil {
		return nil, fmt.Errorf("failed to parse decision JSON: %w", err)
	}

	if decision.Action == "" {
		return nil, fmt.Errorf("decision missing 'action' field")
	}

	return &decision, nil
}

// fallbackDecision returns a PolicyDecision using the configured fallback action.
func (l *LLMEvaluator) fallbackDecision(reason string) *PolicyDecision {
	return &PolicyDecision{
		Action: l.config.Fallback,
		Reason: "llm fallback: " + reason,
	}
}
