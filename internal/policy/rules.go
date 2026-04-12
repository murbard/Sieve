// Package policy implements the Sieve policy engine that governs what AI agents
// can and cannot do.
//
// rules.go contains the rules-based policy evaluator, the most common evaluator
// type. It implements a first-match-wins model inspired by firewall rule chains:
// rules are evaluated top-to-bottom and the first rule whose conditions match
// determines the outcome. If no rule matches, the configured default action
// (typically "deny") applies.
//
// Rules operate in two phases:
//   - "pre" phase: evaluated BEFORE the connector executes the operation.
//     Used for access control (allow/deny/approval_required).
//   - "post" phase: evaluated AFTER execution, with the response available
//     in metadata. Used for content filtering, redaction, and output-based
//     deny decisions.
//
// This two-phase design means a policy can allow an agent to read emails but
// redact sensitive content from the response, or deny forwarding responses
// that contain certain keywords — decisions that require seeing the actual data.
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
	Action string `json:"action"` // "allow", "deny", "approval_required", "skip", "script", "filter"

	// Reason shown to the agent when this rule fires.
	Reason string `json:"reason,omitempty"`

	// Script config — only for action="script".
	Script *ScriptAction `json:"script,omitempty"`

	// RedactPatterns — regex patterns to redact from response content.
	// Applied when action is "allow" or "filter".
	RedactPatterns []string `json:"redact_patterns,omitempty"`

	// FilterExclude — for action="filter" on post-phase: remove items
	// from list responses where any field contains this string.
	FilterExclude string `json:"filter_exclude,omitempty"`
}

// RuleMatch defines conditions for a rule to fire.
type RuleMatch struct {
	// Operations to match (exact names). Empty = match all.
	Operations []string `json:"operations,omitempty"`

	// Phase: "pre" (before execution) or "post" (after execution).
	// Empty = "pre".
	Phase string `json:"phase,omitempty"`

	// ContentContains — for post-phase: match if the response contains
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
	Rules         []Rule `json:"rules"`
	DefaultAction string `json:"default_action"` // "allow" or "deny", default "deny"
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
func (r *RulesEvaluator) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error) {
	phase := req.Phase
	if phase == "" {
		phase = "pre"
	}

	// First-match-wins: iterate rules in order. The first rule whose conditions
	// all match determines the decision. This makes rule ordering critical —
	// more specific rules must come before broader catch-all rules.
	for i, rule := range r.config.Rules {
		if !r.matches(&rule, req, phase) {
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

		case "filter":
			// Filter actions only make sense in the post phase because they
			// operate on the actual response content. If encountered in pre
			// phase, skip to the next rule rather than erroring — this allows
			// a single rule list to contain both pre and post rules naturally.
			if phase != "post" {
				continue
			}
			response, _ := req.Metadata["response"].(string)
			if response == "" {
				return &PolicyDecision{Action: "allow"}, nil
			}
			rewritten, reason := r.filterResponse(response, rule.FilterExclude)
			decision := &PolicyDecision{
				Action:  "allow",
				Reason:  reason,
				Rewrite: rewritten,
			}
			r.applyRedactions(decision, i, req)
			return decision, nil

		default:
			// Unknown action, skip to next rule.
			continue
		}
	}

	// No rule matched — use default.
	return &PolicyDecision{
		Action: r.config.DefaultAction,
		Reason: "default policy",
	}, nil
}

// matches checks if a rule's conditions all match the request. All specified
// conditions must be true (AND logic). This means adding more conditions to a
// rule makes it narrower, not broader. A nil match block matches everything,
// useful for default/catch-all rules.
func (r *RulesEvaluator) matches(rule *Rule, req *PolicyRequest, phase string) bool {
	m := rule.Match
	if m == nil {
		return true // no conditions = match everything
	}

	// Phase check.
	rulePhase := m.Phase
	if rulePhase == "" {
		rulePhase = "pre"
	}
	if rulePhase != phase {
		return false
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

	// Content contains (post-phase).
	if m.ContentContains != "" {
		response, _ := req.Metadata["response"].(string)
		if !strings.Contains(strings.ToLower(response), strings.ToLower(m.ContentContains)) {
			return false
		}
	}

	// From address check. The "from" field may appear in metadata (post-phase,
	// extracted from the response) or in params (pre-phase, provided by the
	// agent). We check both locations to support matching in either phase.
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

		// Path 2: raw response string fallback (post-phase)
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

// filterResponse removes items from a JSON list response where any field
// contains the exclude string. This enables policies like "don't show the agent
// any emails from legal@" — the items are silently removed from the list and
// the total count is adjusted so the agent sees a consistent response.
func (r *RulesEvaluator) filterResponse(response string, exclude string) (string, string) {
	if exclude == "" {
		return response, ""
	}

	excludeLower := strings.ToLower(exclude)

	var data map[string]any
	if err := json.Unmarshal([]byte(response), &data); err != nil {
		// Not JSON, check the whole response.
		if strings.Contains(strings.ToLower(response), excludeLower) {
			return "", fmt.Sprintf("response filtered: contains %q", exclude)
		}
		return response, ""
	}

	// Handle list formats: {"emails": [...]}, {"messages": [...]}, {"items": [...]}
	for _, key := range []string{"emails", "messages", "items", "threads", "results"} {
		items, ok := data[key].([]any)
		if !ok {
			continue
		}

		var filtered []any
		removed := 0
		for _, item := range items {
			itemJSON, _ := json.Marshal(item)
			if strings.Contains(strings.ToLower(string(itemJSON)), excludeLower) {
				removed++
			} else {
				filtered = append(filtered, item)
			}
		}

		if removed > 0 {
			data[key] = filtered
			if total, ok := data["total"].(float64); ok {
				data["total"] = total - float64(removed)
			}
			// Clear pagination token to prevent side-channel leakage.
			// Without this, an agent could infer how many items were filtered
			// by comparing the visible count with the pagination behavior.
			for _, ptKey := range []string{"next_page_token", "nextPageToken"} {
				delete(data, ptKey)
			}
			rewritten, _ := json.Marshal(data)
			return string(rewritten), fmt.Sprintf("filtered %d item(s) containing %q", removed, exclude)
		}
	}

	return response, ""
}
