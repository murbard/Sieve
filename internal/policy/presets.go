package policy

import "fmt"

// --- Rule-based presets ---

func RulesPresetReadOnly() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails", "read_email", "read_thread", "list_labels", "get_attachment"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
		"scope":          "gmail",
	}
}

func RulesPresetDrafter() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email", "send_draft", "reply"}},
				"action": "approval_required",
				"reason": "Sending requires approval",
			},
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails", "read_email", "read_thread", "list_labels", "get_attachment", "create_draft", "update_draft"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
		"scope":          "gmail",
	}
}

func RulesPresetFullAssist() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"send_email", "send_draft", "reply"}},
				"action": "approval_required",
				"reason": "Sending requires approval",
			},
		},
		"default_action": "allow",
		"scope":          "gmail",
	}
}

func RulesPresetTriage() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"match":  map[string]any{"operations": []any{"list_emails", "read_email", "read_thread", "list_labels", "get_attachment", "add_label", "remove_label", "archive"}},
				"action": "allow",
			},
		},
		"default_action": "deny",
		"scope":          "gmail",
	}
}

var rulesPresets = map[string]func() map[string]any{
	"read-only":   RulesPresetReadOnly,
	"drafter":     RulesPresetDrafter,
	"full-assist": RulesPresetFullAssist,
	"triage":      RulesPresetTriage,
}

// GetRulesPreset returns a rules-type preset by name.
func GetRulesPreset(name string) (map[string]any, error) {
	fn, ok := rulesPresets[name]
	if !ok {
		return nil, fmt.Errorf("unknown rules preset: %q", name)
	}
	return fn(), nil
}

// RulesPresetNames returns available rules preset names.
func RulesPresetNames() []string {
	names := make([]string, 0, len(rulesPresets))
	for name := range rulesPresets {
		names = append(names, name)
	}
	return names
}
