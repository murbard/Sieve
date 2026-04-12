package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// BuiltinConfig holds declarative rules for the builtin evaluator.
// Designed to be composable: start with a preset, layer on filters.
type BuiltinConfig struct {
	// Operation-level permissions: op name -> "allow"|"deny"|"approval_required"
	// Use "*" as a wildcard default.
	Operations map[string]string `json:"operations"`

	// Filters restrict which items are visible. All filters must pass (AND logic).
	// These are intentionally simple — for complex logic, use a script evaluator.
	Filters *Filters `json:"filters,omitempty"`

	// RedactPatterns are regexes applied to response content.
	// Matches are replaced with [REDACTED].
	RedactPatterns []string `json:"redact_patterns,omitempty"`

	// RateLimits define optional rate-limiting thresholds.
	RateLimits *RateLimits `json:"rate_limits,omitempty"`
}

// Filters restrict which items the agent can see. Empty/nil means no restriction.
type Filters struct {
	// SubjectKeywords: at least one must appear in the subject (case-insensitive).
	// Empty means no restriction.
	SubjectKeywords []string `json:"subject_keywords,omitempty"`

	// SubjectExclude: if any of these appear in the subject, deny access.
	SubjectExclude []string `json:"subject_exclude,omitempty"`

	// FromAddresses: email must be from one of these (supports * glob).
	FromAddresses []string `json:"from_addresses,omitempty"`

	// ToAddresses: email must be addressed to one of these.
	ToAddresses []string `json:"to_addresses,omitempty"`

	// Labels: email must have at least one of these labels.
	Labels []string `json:"labels,omitempty"`

	// AfterDate: only emails after this date (YYYY-MM-DD).
	AfterDate string `json:"after_date,omitempty"`
}

// RateLimits defines optional rate-limiting thresholds.
type RateLimits struct {
	MaxReadsPerHour  int `json:"max_reads_per_hour,omitempty"`
	MaxDraftsPerHour int `json:"max_drafts_per_hour,omitempty"`
	MaxSendsPerDay   int `json:"max_sends_per_day,omitempty"`
}

// BuiltinEvaluator applies declarative operation rules and content filters.
type BuiltinEvaluator struct {
	config         BuiltinConfig
	redactPatterns []*regexp.Regexp
}

// NewBuiltinEvaluator creates a BuiltinEvaluator from a generic config map.
func NewBuiltinEvaluator(config map[string]any) (*BuiltinEvaluator, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("builtin evaluator: failed to marshal config: %w", err)
	}

	var bc BuiltinConfig
	if err := json.Unmarshal(data, &bc); err != nil {
		return nil, fmt.Errorf("builtin evaluator: failed to parse config: %w", err)
	}

	if bc.Operations == nil {
		bc.Operations = make(map[string]string)
	}

	// Pre-compile redaction patterns.
	var patterns []*regexp.Regexp
	for _, p := range bc.RedactPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("builtin evaluator: invalid redact pattern %q: %w", p, err)
		}
		patterns = append(patterns, re)
	}

	return &BuiltinEvaluator{config: bc, redactPatterns: patterns}, nil
}

// Type returns the evaluator type identifier.
func (b *BuiltinEvaluator) Type() string {
	return "builtin"
}

// Evaluate checks the operation against configured rules, applies filters,
// and computes redactions.
func (b *BuiltinEvaluator) Evaluate(_ context.Context, req *PolicyRequest) (*PolicyDecision, error) {
	// 1. Check operation permission.
	action, ok := b.config.Operations[req.Operation]
	if !ok {
		action, ok = b.config.Operations["*"]
		if !ok {
			action = "deny"
		}
	}

	switch action {
	case "allow", "approval_required":
		// Continue to filter checks.
	case "deny":
		return &PolicyDecision{
			Action: "deny",
			Reason: fmt.Sprintf("operation %q denied by policy", req.Operation),
		}, nil
	default:
		return &PolicyDecision{
			Action: "deny",
			Reason: fmt.Sprintf("invalid action %q for operation %q", action, req.Operation),
		}, nil
	}

	// 2. Apply content filters (only for operations that access content).
	if b.config.Filters != nil && req.Metadata != nil {
		if reason, ok := b.checkFilters(req); !ok {
			return &PolicyDecision{
				Action: "deny",
				Reason: reason,
			}, nil
		}
	}

	// 3. Compute redactions.
	var redactions []Redaction
	if len(b.redactPatterns) > 0 {
		if body, ok := req.Metadata["body"].(string); ok {
			for _, re := range b.redactPatterns {
				for _, loc := range re.FindAllStringIndex(body, -1) {
					redactions = append(redactions, Redaction{
						Field: "body",
						Start: loc[0],
						End:   loc[1],
					})
				}
			}
		}
	}

	return &PolicyDecision{
		Action:     action,
		Reason:     fmt.Sprintf("builtin rule for %q", req.Operation),
		Redactions: redactions,
	}, nil
}

// checkFilters applies all configured filters. Returns ("", true) if all pass,
// or (reason, false) if any filter rejects.
func (b *BuiltinEvaluator) checkFilters(req *PolicyRequest) (string, bool) {
	f := b.config.Filters
	meta := req.Metadata

	// Subject keyword filter.
	if len(f.SubjectKeywords) > 0 {
		subject, _ := meta["subject"].(string)
		subjectLower := strings.ToLower(subject)
		matched := false
		for _, kw := range f.SubjectKeywords {
			if strings.Contains(subjectLower, strings.ToLower(kw)) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Sprintf("subject does not contain any of: %s", strings.Join(f.SubjectKeywords, ", ")), false
		}
	}

	// Subject exclude filter.
	if len(f.SubjectExclude) > 0 {
		subject, _ := meta["subject"].(string)
		subjectLower := strings.ToLower(subject)
		for _, kw := range f.SubjectExclude {
			if strings.Contains(subjectLower, strings.ToLower(kw)) {
				return fmt.Sprintf("subject contains excluded keyword: %q", kw), false
			}
		}
	}

	// From address filter.
	if len(f.FromAddresses) > 0 {
		from, _ := meta["from"].(string)
		fromLower := strings.ToLower(from)
		matched := false
		for _, pattern := range f.FromAddresses {
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
			return fmt.Sprintf("sender not in allowed list"), false
		}
	}

	// Label filter.
	if len(f.Labels) > 0 {
		labels, _ := meta["labels"].([]any)
		matched := false
		for _, want := range f.Labels {
			for _, have := range labels {
				if haveStr, ok := have.(string); ok && strings.EqualFold(haveStr, want) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return "email does not have any of the required labels", false
		}
	}

	return "", true
}
