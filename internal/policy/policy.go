// Package policy defines the evaluator interface and types for the Sieve policy
// engine. The policy engine sits between an AI agent's request and the actual
// connector execution, deciding whether to allow, deny, require approval, or
// filter the operation.
//
// Multiple evaluator backends are supported (rules, script, LLM, chain,
// builtin). CreateEvaluator is the factory that dispatches by type string.
// The most common type is "rules" (see rules.go).
package policy

import (
	"context"
	"fmt"
)

// PolicyRequest describes the action an AI agent wants to perform.
//
// Security note on Phase: Phase is set explicitly by the calling code (MCP
// server or API router), NOT derived from request metadata. This prevents an
// agent from injecting phase="post" in its request parameters to bypass
// pre-execution policy checks. The caller sets Phase="pre" before execution
// and Phase="post" after, ensuring the policy engine always sees the correct
// phase regardless of what the agent sends.
type PolicyRequest struct {
	Operation  string         `json:"operation"`
	Connection string         `json:"connection"`
	Connector  string         `json:"connector"`
	Params     map[string]any `json:"params"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Phase      string         `json:"phase,omitempty"` // "pre" or "post", set by caller — not from metadata
}

// Redaction describes a region of a field that should be masked.
type Redaction struct {
	Field string `json:"field"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// PolicyDecision is the result of evaluating a policy. The Action field drives
// the control flow in the MCP server and API router. Rewrite is used by
// post-phase filter rules to return a modified version of the connector's
// response (e.g., with filtered-out list items removed).
type PolicyDecision struct {
	Action     string      `json:"action"` // "allow", "deny", "approval_required"
	Reason     string      `json:"reason,omitempty"`
	Redactions []Redaction `json:"redactions,omitempty"`
	Rewrite    string      `json:"rewrite,omitempty"` // if set, replace the response with this content
}

// Evaluator is the interface all policy evaluators implement.
type Evaluator interface {
	Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error)
	Type() string
}

// LLMProviderConfig holds configuration for an LLM provider endpoint.
type LLMProviderConfig struct {
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	APIKeyEnv string `json:"api_key_env"`
	Model     string `json:"model"`
}

// CreateEvaluator builds an Evaluator based on the given type string and config.
func CreateEvaluator(policyType string, config map[string]any, providers map[string]LLMProviderConfig) (Evaluator, error) {
	switch policyType {
	case "builtin":
		return NewBuiltinEvaluator(config)
	case "script":
		return NewScriptEvaluator(config)
	case "llm":
		return NewLLMEvaluator(config, providers)
	case "chain":
		return NewChainEvaluator(config, providers)
	case "rules":
		return NewRulesEvaluator(config, providers)
	default:
		return nil, fmt.Errorf("unknown policy evaluator type: %s", policyType)
	}
}
