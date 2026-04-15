// Package mockconnector provides a configurable mock implementation of
// connector.Connector for use in tests. It returns canned responses and
// records calls for assertion.
package mockconnector

import (
	"context"
	"fmt"
	"sync"

	"github.com/murbard/Sieve/internal/connector"
)

// Call records a single operation invocation.
type Call struct {
	Operation string
	Params    map[string]any
}

// Mock implements connector.Connector with configurable behavior.
type Mock struct {
	ConnType   string
	Ops        []connector.OperationDef
	Responses  map[string]any   // operation -> response
	Errors     map[string]error // operation -> error
	Calls      []Call
	mu         sync.Mutex
}

// New creates a Mock with the given type and default Gmail-like operations.
func New(connType string) *Mock {
	return &Mock{
		ConnType:  connType,
		Responses: make(map[string]any),
		Errors:    make(map[string]error),
		Ops: []connector.OperationDef{
			{Name: "list_emails", Description: "List emails", ReadOnly: true, Params: map[string]connector.ParamDef{
				"query":       {Type: "string", Required: false},
				"max_results": {Type: "int", Required: false},
			}},
			{Name: "read_email", Description: "Read an email", ReadOnly: true, Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Required: true},
			}},
			{Name: "send_email", Description: "Send an email", ReadOnly: false, Params: map[string]connector.ParamDef{
				"to":      {Type: "[]string", Required: true},
				"subject": {Type: "string", Required: true},
				"body":    {Type: "string", Required: true},
			}},
			{Name: "list_labels", Description: "List labels", ReadOnly: true},
		},
	}
}

// NewMinimal creates a Mock with no operations.
func NewMinimal(connType string) *Mock {
	return &Mock{
		ConnType:  connType,
		Responses: make(map[string]any),
		Errors:    make(map[string]error),
	}
}

// SetResponse configures the response for an operation.
func (m *Mock) SetResponse(op string, resp any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Responses[op] = resp
}

// SetError configures an error for an operation.
func (m *Mock) SetError(op string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Errors[op] = err
}

// GetCalls returns all recorded calls.
func (m *Mock) GetCalls() []Call {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Call{}, m.Calls...)
}

// Reset clears recorded calls.
func (m *Mock) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = nil
}

// --- connector.Connector interface ---

func (m *Mock) Type() string { return m.ConnType }

func (m *Mock) Operations() []connector.OperationDef { return m.Ops }

func (m *Mock) Execute(_ context.Context, op string, params map[string]any) (any, error) {
	m.mu.Lock()
	m.Calls = append(m.Calls, Call{Operation: op, Params: params})
	resp := m.Responses[op]
	err := m.Errors[op]
	m.mu.Unlock()

	if err != nil {
		return nil, err
	}
	if resp != nil {
		return resp, nil
	}

	// Default responses for common operations.
	switch op {
	case "list_emails":
		return map[string]any{
			"emails": []any{
				map[string]any{
					"id": "msg1", "thread_id": "t1", "from": "sender@test.com",
					"to": []string{"me@test.com"}, "subject": "Test Email",
					"body": "Hello world", "labels": []string{"INBOX"},
					"snippet": "Hello world", "has_attachment": false,
				},
			},
			"total":           1,
			"next_page_token": "",
		}, nil
	case "read_email":
		return map[string]any{
			"id": params["message_id"], "thread_id": "t1", "from": "sender@test.com",
			"to": []string{"me@test.com"}, "subject": "Test Email",
			"body": "Hello world", "labels": []string{"INBOX"},
		}, nil
	case "send_email":
		return map[string]any{"id": "sent1", "thread_id": "t2"}, nil
	case "list_labels":
		return []any{
			map[string]any{"id": "INBOX", "name": "INBOX"},
			map[string]any{"id": "SENT", "name": "SENT"},
		}, nil
	case "get_attachment":
		return map[string]any{
			"id":        params["attachment_id"],
			"filename":  "report.pdf",
			"mime_type": "application/pdf",
			"size":      int64(1024),
		}, nil
	default:
		return nil, fmt.Errorf("mock: operation %q not configured", op)
	}
}

func (m *Mock) Validate(_ context.Context) error { return nil }

// Factory returns a connector.Factory that always returns this mock.
func (m *Mock) Factory() connector.Factory {
	return func(config map[string]any) (connector.Connector, error) {
		return m, nil
	}
}

// Meta returns connector metadata for registration.
func (m *Mock) Meta() connector.ConnectorMeta {
	return connector.ConnectorMeta{
		Type:        m.ConnType,
		Name:        "Mock " + m.ConnType,
		Description: "Mock connector for testing",
		Category:    "Test",
	}
}
