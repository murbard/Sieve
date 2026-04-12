// Package mcp implements the Model Context Protocol (MCP) server for Sieve.
//
// MCP is the protocol AI agents (e.g., Claude) use to discover and invoke tools.
// This server exposes connector operations as MCP tools, with every tool call
// passing through a two-phase policy pipeline:
//
//  1. Pre-execution check: Before the connector runs, the policy evaluator
//     decides whether the operation is allowed, denied, or requires human
//     approval. This is the primary access-control gate.
//
//  2. Post-execution check: After the connector returns data, the policy
//     evaluator gets a second pass with the actual response content. This
//     enables content filtering, redaction, and output-based deny decisions
//     that can only be made once the data is visible.
//
// The approval flow is non-blocking for MCP clients: when approval is required,
// the server returns immediately with an approval ID and URL. The agent can
// poll for resolution. This differs from the REST API which blocks with
// WaitForResolution (suitable for synchronous HTTP clients).
//
// Tool naming handles multi-connection scenarios by prefixing tool names with
// the connector type (e.g., "google_list_emails") when a token has access to
// multiple connections. Single-connection tokens get unprefixed names.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/plandex-ai/sieve/internal/approval"
	"github.com/plandex-ai/sieve/internal/audit"
	"github.com/plandex-ai/sieve/internal/connections"
	"github.com/plandex-ai/sieve/internal/connector"
	"github.com/plandex-ai/sieve/internal/policies"
	"github.com/plandex-ai/sieve/internal/policy"
	"github.com/plandex-ai/sieve/internal/tokens"
)

// JSON-RPC 2.0 types

// JSONRPCRequest represents an incoming JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents an outgoing JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP tool types

// ToolDef describes a tool exposed via MCP.
type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ToolCallParams holds the parameters for a tools/call request.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// ToolCallResult is the result returned from a tools/call invocation.
type ToolCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ContentBlock is a single content item in a tool call result.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Server implements the MCP protocol over Streamable HTTP. Policy evaluators
// are cached per token ID to avoid reconstructing them on every request.
type Server struct {
	tokens      *tokens.Service
	connections *connections.Service
	policies    *policies.Service
	approval *approval.Queue
	audit    *audit.Logger
}

// NewServer creates a new MCP Server.
func NewServer(
	tokensSvc *tokens.Service,
	connsSvc *connections.Service,
	policiesSvc *policies.Service,
	approvalQ *approval.Queue,
	auditLog *audit.Logger,
) *Server {
	return &Server{
		tokens:      tokensSvc,
		connections: connsSvc,
		policies:    policiesSvc,
		approval: approvalQ,
		audit:    auditLog,
	}
}

// Handler returns an http.Handler that serves the MCP endpoint.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			s.writeError(w, nil, -32600, "only POST is supported")
			return
		}

		// Extract and validate bearer token.
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			s.writeError(w, nil, -32000, "missing or invalid Authorization header")
			return
		}
		bearerToken := strings.TrimPrefix(authHeader, "Bearer ")

		tok, err := s.tokens.Validate(bearerToken)
		if err != nil {
			s.writeError(w, nil, -32000, "invalid token: "+err.Error())
			return
		}

		// Parse JSON-RPC request.
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, nil, -32700, "parse error: "+err.Error())
			return
		}

		if req.JSONRPC != "2.0" {
			s.writeError(w, req.ID, -32600, "invalid jsonrpc version")
			return
		}

		// Dispatch by method.
		var resp *JSONRPCResponse
		switch req.Method {
		case "initialize":
			resp = s.handleInitialize(req.ID)
		case "tools/list":
			resp = s.handleToolsList(req.ID, tok)
		case "tools/call":
			resp = s.handleToolsCall(r.Context(), req.ID, tok, req.Params)
		default:
			resp = &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32601, Message: "method not found: " + req.Method},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
}

// handleInitialize returns server info and capabilities.
func (s *Server) handleInitialize(id any) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]any{
				"name":    "sieve",
				"version": "0.1.0",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
		},
	}
}

// handleToolsList builds and returns tool definitions based on the token's connections.
func (s *Server) handleToolsList(id any, tok *tokens.Token) *JSONRPCResponse {
	var tools []ToolDef

	// Determine if there are multiple connections (affects tool naming).
	multiConn := len(tok.Connections) > 1

	for _, connID := range tok.Connections {
		conn, err := s.connections.Get(connID)
		if err != nil {
			continue // skip connections we can't load
		}

		c, err := s.connections.GetConnector(connID)
		if err != nil {
			continue
		}

		for _, op := range c.Operations() {
			// Normalize dots to underscores in tool names. Operations like
			// "drive.list_files" become "drive_list_files" since dots in
			// tool names can confuse LLM tool callers.
			toolName := strings.ReplaceAll(op.Name, ".", "_")
			if multiConn {
				toolName = conn.ConnectorType + "_" + toolName
			}

			schema := buildInputSchema(op, multiConn)

			tools = append(tools, ToolDef{
				Name:        toolName,
				Description: op.Description,
				InputSchema: schema,
			})
		}
	}

	// Built-in tools
	tools = append(tools, ToolDef{
		Name:        "list_connections",
		Description: "List the available service connections and their IDs.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	})

	tools = append(tools, ToolDef{
		Name:        "list_policies",
		Description: "List all available policies with their names and rule summaries.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	})

	tools = append(tools, ToolDef{
		Name:        "get_my_policy",
		Description: "Get the full policy (rules) that applies to this token.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	})

	tools = append(tools, ToolDef{
		Name:        "propose_policy",
		Description: "Propose a new policy or changes to an existing policy. The proposal goes to the human admin for approval — you cannot enact policy changes directly. Describe what the policy should do and provide the rules.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Name for the proposed policy",
				},
				"description": map[string]any{
					"type":        "string",
					"description": "Human-readable description of what this policy does and why you're proposing it",
				},
				"rules": map[string]any{
					"type":        "array",
					"description": "Array of policy rules. Each rule has: match (operations, from, subject_contains, labels, content_contains), action (allow/deny/approval_required/script/filter), and optional reason, filter_exclude, redact_patterns, script config.",
					"items": map[string]any{
						"type": "object",
					},
				},
			},
			"required": []string{"name", "description", "rules"},
		},
	})

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]any{
			"tools": tools,
		},
	}
}

// handleToolsCall executes a tool through the policy pipeline.
func (s *Server) handleToolsCall(ctx context.Context, id any, tok *tokens.Token, params json.RawMessage) *JSONRPCResponse {
	var call ToolCallParams
	if err := json.Unmarshal(params, &call); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32602, Message: "invalid params: " + err.Error()},
		}
	}

	start := time.Now()

	// Handle built-in tools.
	switch call.Name {
	case "list_connections":
		return s.handleListConnections(id, tok, start)
	case "list_policies":
		return s.handleListPolicies(id, tok, start)
	case "get_my_policy":
		return s.handleGetMyPolicy(id, tok, start)
	case "propose_policy":
		return s.handleProposePolicy(id, tok, start, call.Arguments)
	}

	// Resolve connection and operation from the tool name.
	connID, opName, err := s.resolveToolCall(tok, call)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32602, Message: err.Error()},
		}
	}

	// Security: verify the resolved connection is in the token's allow-list.
	// This prevents an agent from accessing connections it wasn't granted,
	// even if it crafts a tool name or "connection" argument manually.
	if !s.tokenHasConnection(tok, connID) {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "connection not allowed for this token"},
		}
	}

	conn, err := s.connections.Get(connID)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "connection not found: " + err.Error()},
		}
	}

	// Build policy request.
	policyReq := &policy.PolicyRequest{
		Operation:  opName,
		Connection: connID,
		Connector:  conn.ConnectorType,
		Params:     call.Arguments,
		Metadata:   call.Arguments,
		Phase:      "pre",
	}

	// Get or create the policy evaluator for this token.
	evaluator, err := s.getEvaluator(tok)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "policy evaluator error: " + err.Error()},
		}
	}

	// Phase 1: Pre-execution policy check. The Phase field is not set here,
	// so it defaults to "pre" in the evaluator. This is the primary access
	// control gate — deny/approval_required decisions stop execution entirely.
	decision, err := evaluator.Evaluate(ctx, policyReq)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "policy evaluation error: " + err.Error()},
		}
	}

	switch decision.Action {
	case "deny":
		durationMs := time.Since(start).Milliseconds()
		s.logAudit(tok, connID, opName, call.Arguments, "deny", decision.Reason, durationMs)
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: ToolCallResult{
				Content: []ContentBlock{{Type: "text", Text: "Policy denied: " + decision.Reason}},
				IsError: true,
			},
		}

	case "approval_required":
		item, err := s.approval.Submit(&approval.SubmitRequest{
			TokenID:      tok.ID,
			ConnectionID: connID,
			Operation:    opName,
			RequestData:  call.Arguments,
		})
		if err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      id,
				Error:   &JSONRPCError{Code: -32000, Message: "failed to submit for approval: " + err.Error()},
			}
		}

		durationMs := time.Since(start).Milliseconds()
		s.logAudit(tok, connID, opName, call.Arguments, "approval_required", "", durationMs)

		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: ToolCallResult{
				Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf(
					"This action requires human approval.\n\nApproval ID: %s\nApprove at: the Sieve admin UI (/approvals)\nPoll status: /api/v1/approvals/%s/status\n\nThe request has been submitted and is waiting for review.",
					item.ID, item.ID,
				)}},
			},
		}

	case "allow":
		// Proceed to execute.

	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "unexpected policy action: " + decision.Action},
		}
	}

	// Execute via connector.
	c, err := s.connections.GetConnector(connID)
	if err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: -32000, Message: "connector error: " + err.Error()},
		}
	}

	result, err := c.Execute(ctx, opName, call.Arguments)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		s.logAudit(tok, connID, opName, call.Arguments, "error", err.Error(), durationMs)
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: ToolCallResult{
				Content: []ContentBlock{{Type: "text", Text: "Execution error: " + err.Error()}},
				IsError: true,
			},
		}
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		resultJSON = []byte(fmt.Sprintf("%v", result))
	}

	// Phase 2: Post-execution policy check. Now that we have the actual
	// response content, give the policy a second pass to filter, redact, or
	// deny based on what the connector returned. Phase is set explicitly to
	// "post" on the struct (not in metadata) to prevent agents from spoofing it.
	postReq := &policy.PolicyRequest{
		Operation:  opName,
		Connection: connID,
		Connector:  conn.ConnectorType,
		Params:     call.Arguments,
		Phase:      "post",
		Metadata: map[string]any{
			"phase":    "post",
			"response": string(resultJSON),
		},
	}
	postDecision, err := evaluator.Evaluate(ctx, postReq)
	if err != nil {
		// Fail-closed: any error in post-execution policy evaluation is treated
		// as a deny. This prevents data leakage if the policy engine is misconfigured.
		durationMs = time.Since(start).Milliseconds()
		s.logAudit(tok, connID, opName, call.Arguments, "deny_post", fmt.Sprintf("post-execution policy error: %v", err), durationMs)
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: ToolCallResult{
				Content: []ContentBlock{{Type: "text", Text: "Blocked by policy"}},
				IsError: true,
			},
		}
	}
	if postDecision.Action == "deny" {
		durationMs = time.Since(start).Milliseconds()
		s.logAudit(tok, connID, opName, call.Arguments, "deny_post", postDecision.Reason, durationMs)
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: ToolCallResult{
				Content: []ContentBlock{{Type: "text", Text: "Filtered by policy: " + postDecision.Reason}},
				IsError: true,
			},
		}
	}

	// If the policy rewrote the response, use the rewritten version.
	if postDecision.Rewrite != "" {
		resultJSON = []byte(postDecision.Rewrite)
	}

	reason := postDecision.Reason
	s.logAudit(tok, connID, opName, call.Arguments, "allow", reason, durationMs)

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: ToolCallResult{
			Content: []ContentBlock{{Type: "text", Text: string(resultJSON)}},
		},
	}
}

// handleListConnections returns the token's available connections.
func (s *Server) handleListConnections(id any, tok *tokens.Token, start time.Time) *JSONRPCResponse {
	var conns []map[string]string
	for _, connID := range tok.Connections {
		conn, err := s.connections.Get(connID)
		if err != nil {
			continue
		}
		conns = append(conns, map[string]string{
			"id":        conn.ID,
			"connector": conn.ConnectorType,
			"name":      conn.DisplayName,
		})
	}

	resultJSON, _ := json.Marshal(conns)
	durationMs := time.Since(start).Milliseconds()
	s.logAudit(tok, "", "list_connections", nil, "allow", "", durationMs)

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: ToolCallResult{
			Content: []ContentBlock{{Type: "text", Text: string(resultJSON)}},
		},
	}
}

func (s *Server) handleListPolicies(id any, tok *tokens.Token, start time.Time) *JSONRPCResponse {
	pols, err := s.policies.List()
	if err != nil {
		return &JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: -32000, Message: err.Error()}}
	}

	var summaries []map[string]any
	for _, p := range pols {
		summary := map[string]any{
			"id":   p.ID,
			"name": p.Name,
			"type": p.PolicyType,
		}
		if rules, ok := p.PolicyConfig["rules"].([]any); ok {
			summary["rule_count"] = len(rules)
		}
		summaries = append(summaries, summary)
	}

	resultJSON, _ := json.Marshal(summaries)
	s.logAudit(tok, "", "list_policies", nil, "allow", "", time.Since(start).Milliseconds())

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  ToolCallResult{Content: []ContentBlock{{Type: "text", Text: string(resultJSON)}}},
	}
}

func (s *Server) handleGetMyPolicy(id any, tok *tokens.Token, start time.Time) *JSONRPCResponse {
	var results []map[string]any
	for _, pid := range tok.PolicyIDs {
		p, err := s.policies.Get(pid)
		if err != nil {
			return &JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: -32000, Message: err.Error()}}
		}
		results = append(results, map[string]any{
			"id":     p.ID,
			"name":   p.Name,
			"type":   p.PolicyType,
			"config": p.PolicyConfig,
		})
	}

	resultJSON, _ := json.Marshal(results)
	s.logAudit(tok, "", "get_my_policy", nil, "allow", "", time.Since(start).Milliseconds())

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  ToolCallResult{Content: []ContentBlock{{Type: "text", Text: string(resultJSON)}}},
	}
}

func (s *Server) handleProposePolicy(id any, tok *tokens.Token, start time.Time, args map[string]any) *JSONRPCResponse {
	name, _ := args["name"].(string)
	description, _ := args["description"].(string)
	rules, _ := args["rules"].([]any)

	if name == "" || description == "" {
		return &JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: -32602, Message: "name and description are required"}}
	}

	// Submit to approval queue — the human decides
	item, err := s.approval.Submit(&approval.SubmitRequest{
		TokenID:      tok.ID,
		ConnectionID: "",
		Operation:    "propose_policy",
		RequestData: map[string]any{
			"name":           name,
			"description":    description,
			"rules":          rules,
			"default_action": "deny",
			"proposed_by":    tok.Name,
		},
	})
	if err != nil {
		return &JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: -32000, Message: err.Error()}}
	}

	s.logAudit(tok, "", "propose_policy", args, "approval_required", description, time.Since(start).Milliseconds())

	msg := fmt.Sprintf("Policy proposal submitted for review.\n\nProposal: %s\nDescription: %s\nRules: %d rule(s)\nApproval ID: %s\nReview at: the Sieve admin UI (/approvals)",
		name, description, len(rules), item.ID)

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  ToolCallResult{Content: []ContentBlock{{Type: "text", Text: msg}}},
	}
}

// resolveToolCall determines the connection ID and operation name from a tool call.
// When there are multiple connections, the tool name may be prefixed with the
// connector type, and a "connection" argument may be provided. For single
// connections the tool name maps directly to the operation.
func (s *Server) resolveToolCall(tok *tokens.Token, call ToolCallParams) (connID string, opName string, err error) {
	// If a "connection" argument is explicitly provided, use it.
	if connArg, ok := call.Arguments["connection"]; ok {
		connIDStr, ok := connArg.(string)
		if !ok {
			return "", "", fmt.Errorf("connection argument must be a string")
		}
		connID = connIDStr

		// The tool name may be prefixed with connector type; strip it.
		conn, err := s.connections.Get(connID)
		if err != nil {
			return "", "", fmt.Errorf("connection %q not found", connID)
		}
		prefix := conn.ConnectorType + "_"
		opName = call.Name
		if strings.HasPrefix(opName, prefix) {
			opName = strings.TrimPrefix(opName, prefix)
		}
		opName = denormalizeDots(opName)

		return connID, opName, nil
	}

	// Single connection: use the only available connection.
	// Reverse the dot-to-underscore normalization applied when building tool names.
	if len(tok.Connections) == 1 {
		return tok.Connections[0], denormalizeDots(call.Name), nil
	}

	// Multiple connections: tool name should be prefixed. Find the matching connector.
	for _, cID := range tok.Connections {
		conn, err := s.connections.Get(cID)
		if err != nil {
			continue
		}
		prefix := conn.ConnectorType + "_"
		if strings.HasPrefix(call.Name, prefix) {
			return cID, denormalizeDots(strings.TrimPrefix(call.Name, prefix)), nil
		}
	}

	return "", "", fmt.Errorf("cannot resolve connection for tool %q; provide a 'connection' argument", call.Name)
}

// tokenHasConnection checks whether the given connection ID is in the token's allowed list.
func (s *Server) tokenHasConnection(tok *tokens.Token, connID string) bool {
	for _, c := range tok.Connections {
		if c == connID {
			return true
		}
	}
	return false
}

// getEvaluator creates a composite evaluator from all policies attached to the
// token. Multiple policies are chained: all must allow, first deny wins,
// redactions and rewrites are merged. This enables composable policy blocks
// like "drafter" + "redact-pii" + "rate-limit-reads".
func (s *Server) getEvaluator(tok *tokens.Token) (policy.Evaluator, error) {
	return s.policies.BuildEvaluator(tok.PolicyIDs)
}

// denormalizeDots reverses the dot-to-underscore normalization applied to tool
// names. Operations with namespace prefixes like "drive_list_files" are converted
// back to "drive.list_files" to match the connector's Execute method.
// Only the FIRST underscore after a known namespace prefix is converted.
func denormalizeDots(name string) string {
	prefixes := []string{"drive", "calendar", "people", "sheets", "docs",
		"s3", "ec2", "lambda", "ses", "dynamodb", "hyperstack"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p+"_") {
			return p + "." + name[len(p)+1:]
		}
	}
	return name
}

// buildInputSchema generates a JSON Schema object for a connector operation,
// optionally adding a "connection" parameter when multi-connection mode is active.
func buildInputSchema(op connector.OperationDef, multiConn bool) map[string]any {
	properties := make(map[string]any)
	var required []string

	for name, param := range op.Params {
		prop := map[string]any{
			"description": param.Description,
		}

		switch param.Type {
		case "string":
			prop["type"] = "string"
		case "int":
			prop["type"] = "integer"
		case "bool":
			prop["type"] = "boolean"
		case "[]string":
			prop["type"] = "array"
			prop["items"] = map[string]any{"type": "string"}
		default:
			prop["type"] = "string"
		}

		properties[name] = prop

		if param.Required {
			required = append(required, name)
		}
	}

	if multiConn {
		properties["connection"] = map[string]any{
			"type":        "string",
			"description": "The connection ID to use for this operation.",
		}
	}

	schema := map[string]any{
		"type":       "object",
		"properties": properties,
	}

	if len(required) > 0 {
		schema["required"] = required
	}

	return schema
}

// logAudit writes an entry to the audit log, ignoring errors.
func (s *Server) logAudit(tok *tokens.Token, connID, operation string, params map[string]any, policyResult, responseSummary string, durationMs int64) {
	_ = s.audit.Log(&audit.LogRequest{
		TokenID:         tok.ID,
		TokenName:       tok.Name,
		ConnectionID:    connID,
		Operation:       operation,
		Params:          params,
		PolicyResult:    policyResult,
		ResponseSummary: responseSummary,
		DurationMs:      durationMs,
	})
}

// writeError writes a JSON-RPC error response directly to the http.ResponseWriter.
func (s *Server) writeError(w http.ResponseWriter, id any, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &JSONRPCError{Code: code, Message: message},
	})
}
