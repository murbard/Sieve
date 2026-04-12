package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ChainConfig holds configuration for a chain of evaluators.
type ChainConfig struct {
	Evaluators []ChainEntry `json:"evaluators"`
}

// ChainEntry describes one evaluator in a chain.
type ChainEntry struct {
	Type   string         `json:"type"`
	Config map[string]any `json:"config"`
}

// ChainEvaluator runs multiple evaluators in sequence.
type ChainEvaluator struct {
	evaluators []Evaluator
}

// NewChainEvaluator creates a ChainEvaluator from a generic config map.
func NewChainEvaluator(config map[string]any, providers map[string]LLMProviderConfig) (*ChainEvaluator, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("chain evaluator: failed to marshal config: %w", err)
	}

	var cc ChainConfig
	if err := json.Unmarshal(data, &cc); err != nil {
		return nil, fmt.Errorf("chain evaluator: failed to parse config: %w", err)
	}

	if len(cc.Evaluators) == 0 {
		return nil, fmt.Errorf("chain evaluator: at least one evaluator is required")
	}

	evaluators := make([]Evaluator, 0, len(cc.Evaluators))
	for i, entry := range cc.Evaluators {
		eval, err := CreateEvaluator(entry.Type, entry.Config, providers)
		if err != nil {
			return nil, fmt.Errorf("chain evaluator: entry %d: %w", i, err)
		}
		evaluators = append(evaluators, eval)
	}

	return &ChainEvaluator{evaluators: evaluators}, nil
}

// Type returns the evaluator type identifier.
func (c *ChainEvaluator) Type() string {
	return "chain"
}

// Evaluate runs each sub-evaluator in sequence. A deny from any evaluator
// short-circuits the chain. Redactions are collected from all evaluators.
func (c *ChainEvaluator) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error) {
	var (
		allRedactions    []Redaction
		allFilters       []ResponseFilter
		approvalRequired bool
		reasons          []string
		rewrite          string
	)

	for _, eval := range c.evaluators {
		decision, err := eval.Evaluate(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("chain evaluator (%s): %w", eval.Type(), err)
		}

		if len(decision.Redactions) > 0 {
			allRedactions = append(allRedactions, decision.Redactions...)
		}
		if len(decision.Filters) > 0 {
			allFilters = append(allFilters, decision.Filters...)
		}
		if decision.Rewrite != "" {
			rewrite = decision.Rewrite
		}

		switch decision.Action {
		case "deny":
			decision.Redactions = allRedactions
			return decision, nil
		case "approval_required":
			approvalRequired = true
			if decision.Reason != "" {
				reasons = append(reasons, decision.Reason)
			}
		default:
			if decision.Reason != "" {
				reasons = append(reasons, decision.Reason)
			}
		}
	}

	action := "allow"
	if approvalRequired {
		action = "approval_required"
	}

	return &PolicyDecision{
		Action:     action,
		Reason:     strings.Join(reasons, "; "),
		Redactions: allRedactions,
		Filters:    allFilters,
		Rewrite:    rewrite,
	}, nil
}
