// Package policy implements the Sieve policy engine that governs what AI agents
// can and cannot do.
//
// rules.go contains the rules-based policy evaluator, the most common evaluator
// type. It implements a first-match-wins model inspired by firewall rule chains:
// rules are evaluated top-to-bottom and the first rule whose conditions match
// determines the outcome. If no rule matches, the configured default action
// (typically "deny") applies.
//
// Rules are evaluated in a single pre-execution phase. Post-execution content
// filtering is handled via ResponseFilter objects that are collected during
// evaluation and applied by the caller after the operation executes.
//
// Match conditions within a single rule use AND logic: all specified conditions
// must be true for the rule to fire. An empty match block matches everything,
// which is useful for catch-all rules at the bottom of the list.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Rule is a single entry in an ordered rule list.
type Rule struct {
	// Match conditions — all must be true for the rule to fire (AND logic).
	// Empty/nil match = matches everything.
	Match *RuleMatch `json:"match,omitempty"`

	// Action to take when matched.
	Action string `json:"action"` // "allow", "deny", "approval_required", "script"

	// Reason shown to the agent when this rule fires.
	Reason string `json:"reason,omitempty"`

	// Script config — only for action="script".
	Script *ScriptAction `json:"script,omitempty"`

	// FilterExclude — KEPT for backward compatibility. Translates to a
	// ResponseFilter with ExcludeContaining at evaluation time.
	FilterExclude string `json:"filter_exclude,omitempty"`

	// RedactPatterns — KEPT for backward compatibility. Translates to a
	// ResponseFilter with RedactPatterns at evaluation time.
	RedactPatterns []string `json:"redact_patterns,omitempty"`

	// ResponseFilter — per-rule post-processing applied after execution
	// when this rule matches with "allow".
	ResponseFilter *ResponseFilter `json:"response_filter,omitempty"`
}

// RuleMatch defines conditions for a rule to fire.
type RuleMatch struct {
	// Operations to match (exact names). Empty = match all.
	Operations []string `json:"operations,omitempty"`

	// The rules evaluator no longer checks this field; all rules evaluate
	// in pre-execution mode. Post-execution filtering uses ResponseFilter.
	// Phase field removed — single-phase model. Field kept in JSON for backward compat only.

	// ContentContains — match if the response in metadata contains
	// this string (case-insensitive).
	ContentContains string `json:"content_contains,omitempty"`

	// From — match if the email's from address matches any of these
	// (supports * prefix glob like "*@company.com").
	From []string `json:"from,omitempty"`

	// SubjectContains — match if subject contains any of these strings
	// (case-insensitive).
	SubjectContains []string `json:"subject_contains,omitempty"`

	// Labels — match if the email has at least one of these labels.
	Labels []string `json:"labels,omitempty"`
}

// ScriptAction defines a script to run for action="script".
type ScriptAction struct {
	Command string `json:"command"` // e.g. "python3"
	Path    string `json:"path"`    // script file path
	Timeout string `json:"timeout"` // e.g. "5s"
}

// RulesConfig is the config for the rules evaluator.
type RulesConfig struct {
	Rules           []Rule           `json:"rules"`
	DefaultAction   string           `json:"default_action"` // "allow" or "deny", default "deny"
	Scope           string           `json:"scope,omitempty"`
	ResponseFilters []ResponseFilter `json:"response_filters,omitempty"` // global post-processing filters
}

// RulesEvaluator evaluates an ordered list of rules using first-match-wins
// semantics. Redact patterns are precompiled at construction time to avoid
// repeated regex compilation on every request.
type RulesEvaluator struct {
	config         RulesConfig
	redactCompiled map[int][]*regexp.Regexp // precompiled per rule index
}

// NewRulesEvaluator creates a RulesEvaluator from a generic config map.
func NewRulesEvaluator(config map[string]any, providers map[string]LLMProviderConfig) (*RulesEvaluator, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("rules evaluator: marshal config: %w", err)
	}

	var rc RulesConfig
	if err := json.Unmarshal(data, &rc); err != nil {
		return nil, fmt.Errorf("rules evaluator: parse config: %w", err)
	}

	// Default to deny-by-default: if no rule matches, the safest posture
	// is to block the action rather than allow it.
	if rc.DefaultAction == "" {
		rc.DefaultAction = "deny"
	}

	// Precompile redact patterns.
	compiled := make(map[int][]*regexp.Regexp)
	for i, rule := range rc.Rules {
		if len(rule.RedactPatterns) > 0 {
			var patterns []*regexp.Regexp
			for _, p := range rule.RedactPatterns {
				re, err := regexp.Compile(p)
				if err != nil {
					return nil, fmt.Errorf("rules evaluator: rule %d: invalid redact pattern %q: %w", i, p, err)
				}
				patterns = append(patterns, re)
			}
			compiled[i] = patterns
		}
	}

	return &RulesEvaluator{config: rc, redactCompiled: compiled}, nil
}

func (r *RulesEvaluator) Type() string { return "rules" }

// Evaluate iterates rules top to bottom. First matching rule wins.
// Rules always evaluate in pre-execution mode. Post-execution content
// filtering is handled via ResponseFilter objects attached to the decision.
func (r *RulesEvaluator) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error) {
	// First-match-wins: iterate rules in order. The first rule whose conditions
	// all match determines the decision. This makes rule ordering critical —
	// more specific rules must come before broader catch-all rules.
	for i, rule := range r.config.Rules {
		if !r.matches(&rule, req) {
			continue
		}

		// This rule matched — its action is authoritative.
		switch rule.Action {
		case "allow":
			decision := &PolicyDecision{
				Action: "allow",
				Reason: rule.Reason,
			}
			r.applyRedactions(decision, i, req)
			r.collectFilters(decision, &rule)
			return decision, nil

		case "deny":
			reason := rule.Reason
			if reason == "" {
				reason = fmt.Sprintf("denied by rule %d", i+1)
			}
			return &PolicyDecision{Action: "deny", Reason: reason}, nil

		case "approval_required":
			reason := rule.Reason
			if reason == "" {
				reason = fmt.Sprintf("approval required by rule %d", i+1)
			}
			return &PolicyDecision{Action: "approval_required", Reason: reason}, nil

		case "script":
			// Script actions delegate the decision to an external process,
			// enabling custom logic that's too complex for declarative rules.
			// Missing script config is treated as deny (fail-closed).
			if rule.Script == nil {
				return &PolicyDecision{Action: "deny", Reason: "rule has action=script but no script config"}, nil
			}
			scriptConfig := map[string]any{
				"command": rule.Script.Command,
				"script":  rule.Script.Path,
				"timeout": rule.Script.Timeout,
			}
			eval, err := NewScriptEvaluator(scriptConfig)
			if err != nil {
				return &PolicyDecision{Action: "deny", Reason: "script evaluator error: " + err.Error()}, nil
			}
			return eval.Evaluate(ctx, req)

		default:
			// Unknown action, skip to next rule.
			continue
		}
	}

	// No rule matched — use the configured default (typically "deny" for
	// fail-closed security).
	return &PolicyDecision{
		Action: r.config.DefaultAction,
		Reason: "default policy",
	}, nil
}

// collectFilters gathers ResponseFilter objects from a matched rule and from
// the global config, attaching them to the decision for post-execution use.
func (r *RulesEvaluator) collectFilters(decision *PolicyDecision, rule *Rule) {
	// Per-rule ResponseFilter (new style).
	if rule.ResponseFilter != nil {
		decision.Filters = append(decision.Filters, *rule.ResponseFilter)
	}

	// Legacy backward-compat: translate FilterExclude into a ResponseFilter.
	if rule.FilterExclude != "" {
		decision.Filters = append(decision.Filters, ResponseFilter{
			ExcludeContaining: rule.FilterExclude,
		})
	}

	// Legacy backward-compat: translate RedactPatterns into a ResponseFilter.
	if len(rule.RedactPatterns) > 0 {
		decision.Filters = append(decision.Filters, ResponseFilter{
			RedactPatterns: rule.RedactPatterns,
		})
	}

	// Global response filters from the config.
	decision.Filters = append(decision.Filters, r.config.ResponseFilters...)
}

// matches checks if a rule's conditions all match the request. All specified
// conditions must be true (AND logic). This means adding more conditions to a
// rule makes it narrower, not broader. A nil match block matches everything,
// useful for default/catch-all rules.
func (r *RulesEvaluator) matches(rule *Rule, req *PolicyRequest) bool {
	m := rule.Match
	if m == nil {
		return true // no conditions = match everything
	}

	// Operation check.
	if len(m.Operations) > 0 {
		matched := false
		for _, op := range m.Operations {
			if op == "*" || op == req.Operation {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Content contains check (typically used with response data in metadata).
	if m.ContentContains != "" {
		response, _ := req.Metadata["response"].(string)
		if !strings.Contains(strings.ToLower(response), strings.ToLower(m.ContentContains)) {
			return false
		}
	}

	// From address check. The "from" field may appear in metadata (extracted
	// from the response) or in params (provided by the agent). We check both
	// locations to support matching regardless of where the data originates.
	if len(m.From) > 0 {
		from, _ := req.Metadata["from"].(string)
		if from == "" {
			from, _ = req.Params["from"].(string)
		}
		fromLower := strings.ToLower(from)
		matched := false
		for _, pattern := range m.From {
			pattern = strings.ToLower(pattern)
			if pattern == fromLower {
				matched = true
			} else if strings.HasPrefix(pattern, "*") && strings.HasSuffix(fromLower, pattern[1:]) {
				matched = true
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Subject contains check.
	if len(m.SubjectContains) > 0 {
		subject, _ := req.Metadata["subject"].(string)
		subjectLower := strings.ToLower(subject)
		matched := false
		for _, kw := range m.SubjectContains {
			if strings.Contains(subjectLower, strings.ToLower(kw)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Label check. Labels are tricky because they may arrive as structured
	// metadata (parsed []any) or be embedded in a raw JSON response string.
	// The fallback to raw string matching handles the case where the response
	// contains label data that hasn't been explicitly extracted into metadata.
	// Label check. Three paths:
	// 1. Structured labels in metadata (parsed []any) → match against those
	// 2. Labels in raw response string → raw substring match
	// 3. No label data at all → fail-closed (don't match)
	if len(m.Labels) > 0 {
		labelsVerified := false

		// Path 1: structured labels from metadata
		if labels, ok := req.Metadata["labels"].([]any); ok && len(labels) > 0 {
			var emailLabels []string
			for _, l := range labels {
				if s, ok := l.(string); ok {
					emailLabels = append(emailLabels, strings.ToLower(s))
				}
			}
			matched := false
			for _, want := range m.Labels {
				for _, have := range emailLabels {
					if strings.EqualFold(want, have) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				return false
			}
			labelsVerified = true
		}

		// Path 2: raw response string fallback
		if !labelsVerified {
			if response, ok := req.Metadata["response"].(string); ok {
				responseLower := strings.ToLower(response)
				if strings.Contains(responseLower, `"labels"`) {
					matched := false
					for _, want := range m.Labels {
						if strings.Contains(responseLower, strings.ToLower(want)) {
							matched = true
							break
						}
					}
					if !matched {
						return false
					}
					labelsVerified = true
				}
			}
		}

		// Path 3: no label data found — fail-closed
		if !labelsVerified {
			return false
		}
	}

	return true
}

// applyRedactions computes redaction positions from precompiled patterns.
func (r *RulesEvaluator) applyRedactions(decision *PolicyDecision, ruleIdx int, req *PolicyRequest) {
	patterns, ok := r.redactCompiled[ruleIdx]
	if !ok {
		return
	}

	// Look for body in metadata or response.
	body, _ := req.Metadata["body"].(string)
	if body == "" {
		body, _ = req.Metadata["response"].(string)
	}
	if body == "" {
		return
	}

	for _, re := range patterns {
		for _, loc := range re.FindAllStringIndex(body, -1) {
			decision.Redactions = append(decision.Redactions, Redaction{
				Field: "body",
				Start: loc[0],
				End:   loc[1],
			})
		}
	}
}

