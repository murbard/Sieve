# MCP Integration Guide

This document describes how AI agents interact with Sieve over the Model Context Protocol (MCP). MCP is the protocol used by Claude Code, Claude Desktop, and other AI agent frameworks to discover and invoke tools.

## Protocol overview

Sieve implements MCP over **Streamable HTTP** (JSON-RPC 2.0 over HTTP POST). The MCP endpoint is:

```
POST http://localhost:19817/mcp
```

Every request must include a Bearer token in the `Authorization` header. The token determines which connections and tools the agent can access.

### Request format

All MCP requests are JSON-RPC 2.0:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

### Response format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": { ... }
}
```

Errors use the standard JSON-RPC error object:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "invalid token: token expired"
  }
}
```

## Authentication

Every request requires a valid Sieve token:

```
Authorization: Bearer sieve_tok_xxxxx
```

The token is validated on every request. Invalid, expired, or revoked tokens receive a `-32000` error. The token's role determines which connections and tools appear in `tools/list`.

## MCP methods

Sieve supports three standard MCP methods:

| Method | Description |
|--------|-------------|
| `initialize` | Handshake. Returns server info and capabilities. |
| `tools/list` | List all tools available to this token. |
| `tools/call` | Invoke a tool. Goes through the full policy pipeline. |

## Built-in tools

Every MCP session includes five built-in tools, regardless of what connections the token has access to.

### list_connections

Discover what service connections are available to this token.

**Parameters:** none

**Returns:** JSON array of connection objects:

```json
[
  { "id": "work", "connector": "google", "name": "Work Gmail" },
  { "id": "anthropic", "connector": "httpproxy", "name": "Anthropic API" }
]
```

### list_policies

List all policies with their names, types, and rule counts.

**Parameters:** none

**Returns:** JSON array of policy summaries:

```json
[
  { "id": "pol_abc", "name": "read-only", "type": "rules", "rule_count": 3 },
  { "id": "pol_def", "name": "drafter", "type": "rules", "rule_count": 5 }
]
```

### get_my_policy

Get the full policy rules that apply to this token, organized by connection.

**Parameters:** none

**Returns:** JSON array of connection-policy bindings:

```json
[
  {
    "connection_id": "work",
    "policies": [
      {
        "id": "pol_abc",
        "name": "drafter",
        "type": "rules",
        "config": {
          "rules": [ ... ],
          "default_action": "deny"
        }
      }
    ]
  }
]
```

This is useful for agents to understand their own permissions before attempting operations.

### get_policy_schema

Get the complete JSON schema for policy rules. Agents should call this before using `propose_policy` to understand all available match fields, actions, and filter options.

**Parameters:** none

**Returns:** The full schema definition.

### propose_policy

Propose a new policy or changes to an existing one. The proposal goes to the human admin's approval queue -- agents cannot enact policy changes directly.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Name for the proposed policy |
| `description` | string | Yes | Human-readable description of what this policy does and why |
| `default_action` | string | No | `"allow"` or `"deny"` (recommended: `"deny"`) |
| `rules` | array | Yes | Ordered array of policy rules (first-match-wins) |

**Returns:** Confirmation that the proposal was submitted, with an approval ID.

**Example call:**

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "propose_policy",
    "arguments": {
      "name": "restrict-to-project-x",
      "description": "Only allow reading emails labeled project-x, deny everything else",
      "default_action": "deny",
      "rules": [
        {
          "match": {
            "operations": ["list_emails", "read_email", "read_thread"],
            "labels": ["project-x"]
          },
          "action": "allow"
        }
      ]
    }
  }
}
```

## Connector tools

In addition to the five built-in tools, the agent sees tools for each operation supported by its connections. These are the actual service operations (reading emails, creating drafts, listing Drive files, etc.).

### Tool naming

Tool names are derived from the connector's operation names with dots replaced by underscores:

- `list_emails` (Gmail)
- `drive_list_files` (Drive)
- `calendar_create_event` (Calendar)
- `sheets_read_range` (Sheets)

### Multi-connection prefixing

When a token's role grants access to **multiple connections**, tool names are prefixed with the connection ID to disambiguate:

```
work_list_emails        # list emails from the "work" Gmail connection
personal_list_emails    # list emails from the "personal" Gmail connection
work_drive_list_files   # list Drive files from the "work" connection
```

When a token has access to only **one connection**, tool names are unprefixed:

```
list_emails
drive_list_files
calendar_list_events
```

### Tool schemas

Each connector tool includes a JSON Schema for its input parameters. The schema is generated from the connector's operation definitions and includes parameter types, descriptions, and required flags.

For multi-connection tokens, each tool also includes a `connection` parameter that defaults to the connection ID embedded in the tool name.

## Policy pipeline

Every `tools/call` request passes through the policy pipeline:

```
Agent calls tools/call
    |
    v
1. Validate token
    |
    v
2. Resolve connection + operation from tool name
    |
    v
3. Verify connection is in token's role
    |
    v
4. Build policy evaluator from role's policy bindings
    |
    v
5. Pre-execution policy check
    |
    +-- deny --> return error with reason
    |
    +-- approval_required --> submit to approval queue, return approval ID
    |
    +-- allow --> continue
        |
        v
6. Execute operation via connector (with real credentials)
        |
        v
7. Apply response filters (redaction, exclusion)
        |
        v
8. Return result to agent
        |
        v
9. Log to audit trail
```

## Approval flow

When a policy rule returns `approval_required`, the MCP server does **not** block. Instead it:

1. Submits the request to the approval queue
2. Returns immediately with a text response containing:
   - The approval ID
   - A URL to the admin UI where the human can review
   - Instructions to poll for status

The agent receives a response like:

```
This action requires human approval.

Approval ID: apr_abc123
Approve at: the Sieve admin UI (/approvals)
Poll status: /api/v1/approvals/apr_abc123/status

The request has been submitted and is waiting for review.
```

The agent can poll the approval status via the REST API:

```
GET /api/v1/approvals/apr_abc123/status
Authorization: Bearer sieve_tok_xxxxx
```

Once approved, the operation is executed by Sieve (the agent does not need to resubmit).

## Example: full MCP session

This shows a complete MCP interaction from initialization through tool discovery and execution.

### Step 1: Initialize

```json
// Request
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {}
}

// Response
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "serverInfo": {
      "name": "sieve",
      "version": "0.1.0"
    },
    "capabilities": {
      "tools": {}
    }
  }
}
```

### Step 2: List available tools

```json
// Request
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}

// Response (abridged -- shows a few tools from a single-connection token)
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "list_emails",
        "description": "Search and list emails using Gmail query syntax",
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": { "type": "string", "description": "Gmail search query string" },
            "max_results": { "type": "integer", "description": "Maximum number of results to return" },
            "page_token": { "type": "string", "description": "Page token for pagination" }
          }
        }
      },
      {
        "name": "read_email",
        "description": "Read a single email by message ID",
        "inputSchema": {
          "type": "object",
          "properties": {
            "message_id": { "type": "string", "description": "The ID of the message to read" }
          },
          "required": ["message_id"]
        }
      },
      {
        "name": "create_draft",
        "description": "Create a new email draft",
        "inputSchema": {
          "type": "object",
          "properties": {
            "to": { "type": "array", "items": { "type": "string" }, "description": "Recipient email addresses" },
            "subject": { "type": "string", "description": "Email subject" },
            "body": { "type": "string", "description": "Email body text" }
          }
        }
      },
      {
        "name": "list_connections",
        "description": "List the available service connections and their IDs.",
        "inputSchema": { "type": "object", "properties": {} }
      },
      {
        "name": "get_my_policy",
        "description": "Get the full policy (rules) that applies to this token.",
        "inputSchema": { "type": "object", "properties": {} }
      }
    ]
  }
}
```

### Step 3: Call a tool (allowed)

```json
// Request
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "list_emails",
    "arguments": {
      "query": "from:boss@company.com",
      "max_results": 5
    }
  }
}

// Response
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"emails\":[{\"id\":\"18f3a...\",\"from\":\"boss@company.com\",\"subject\":\"Q4 Planning\",\"snippet\":\"Let's discuss...\"}],\"total\":1}"
      }
    ]
  }
}
```

### Step 4: Call a tool (denied by policy)

```json
// Request
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "send_email",
    "arguments": {
      "to": ["external@other.com"],
      "subject": "Hello",
      "body": "Test message"
    }
  }
}

// Response
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Policy denied: sends to external recipients are not allowed"
      }
    ],
    "isError": true
  }
}
```

### Step 5: Call a tool (requires approval)

```json
// Request
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "send_email",
    "arguments": {
      "to": ["colleague@company.com"],
      "subject": "Meeting notes",
      "body": "Here are the notes from today..."
    }
  }
}

// Response
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "This action requires human approval.\n\nApproval ID: apr_abc123\nApprove at: the Sieve admin UI (/approvals)\nPoll status: /api/v1/approvals/apr_abc123/status\n\nThe request has been submitted and is waiting for review."
      }
    ]
  }
}
```

## Claude Code configuration

To connect Claude Code to Sieve, add a `.mcp.json` file to your project root (or `~/.claude/mcp.json` for global configuration):

```json
{
  "mcpServers": {
    "sieve": {
      "type": "sse",
      "url": "http://localhost:19817/mcp",
      "headers": {
        "Authorization": "Bearer sieve_tok_xxxxx"
      }
    }
  }
}
```

The `sieve token create` command prints this configuration snippet automatically.

Once configured, Claude Code will discover Sieve's tools via `tools/list` and use them when relevant to the conversation. All tool calls pass through Sieve's policy pipeline transparently.

## Error codes

| Code | Meaning |
|------|---------|
| `-32700` | Parse error (malformed JSON) |
| `-32600` | Invalid request (wrong HTTP method or JSON-RPC version) |
| `-32601` | Method not found |
| `-32602` | Invalid params (bad tool name or arguments) |
| `-32000` | Server error (invalid token, connection not found, policy error) |
