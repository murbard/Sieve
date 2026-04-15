// Package gmail implements the Google connector for Sieve. It wraps Google
// service APIs (Gmail, Drive, Calendar, Contacts, Sheets, and Docs) behind
// the connector.Connector interface so that the MCP server and REST API can
// invoke Google operations uniformly through the policy pipeline.
//
// The connector uses a Factory pattern: Factory(config) returns a ready-to-use
// GoogleConnector. The factory handles two OAuth token scenarios:
//
//  1. If client_id and client_secret are present in the config, it builds a
//     refreshing TokenSource via oauth2.Config.TokenSource. This means expired
//     access tokens are automatically refreshed using the refresh_token, which
//     is the normal production path after the web UI OAuth flow.
//
//  2. If client credentials are missing (e.g., CLI setup before OAuth), it
//     falls back to a StaticTokenSource that uses the access token as-is.
//     This won't refresh, so it will stop working once the token expires —
//     but it allows basic validation and testing.
//
// Token expiry handling: if the stored expiry is zero/missing, it is set to
// time.Now() so the oauth2 library treats the token as expired and immediately
// attempts a refresh. This ensures stale tokens from a database restore or
// manual config don't silently fail.
package gmail

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/murbard/Sieve/internal/connector"
	gmailclient "github.com/murbard/Sieve/internal/gmail"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

// Meta describes the Google Account connector for the UI catalog.
var Meta = connector.ConnectorMeta{
	Type:        "google",
	Name:        "Google Account",
	Description: "Gmail, Drive, Calendar, Contacts, and Sheets via Google APIs",
	Category:    "Google",
	SetupFields: []connector.Field{
		{Name: "email", Label: "Google Account Email", Type: "text", Required: true, Placeholder: "you@gmail.com"},
		{Name: "oauth_token", Label: "OAuth Token", Type: "oauth", Required: true, HelpText: "Authenticate via Google OAuth"},
	},
}

// GoogleConnector implements the connector.Connector interface for Google services.
type GoogleConnector struct {
	client *gmailclient.Client
	email  string
}

// persistingTokenSource wraps an oauth2.TokenSource and calls a callback
// whenever a new token is obtained (i.e., after a refresh). This allows
// the refreshed credentials to be persisted back to the database so they
// survive server restarts without triggering another refresh cycle.
type persistingTokenSource struct {
	base     oauth2.TokenSource
	lastHash string // hash of last seen access_token to detect changes
	onRefresh func(token *oauth2.Token)
}

func (p *persistingTokenSource) Token() (*oauth2.Token, error) {
	tok, err := p.base.Token()
	if err != nil {
		return nil, err
	}
	// Detect if the token changed (refresh happened).
	if tok.AccessToken != p.lastHash {
		if p.lastHash != "" && p.onRefresh != nil {
			// Not the first call — a real refresh happened.
			p.onRefresh(tok)
		}
		p.lastHash = tok.AccessToken
	}
	return tok, nil
}

// Factory creates a new GoogleConnector from the provided config.
// Expected config keys:
//   - "email": string - the user's email address
//   - "oauth_token": map[string]any - OAuth2 token with keys: access_token, token_type, refresh_token, expiry
//   - "client_id", "client_secret": for token refresh
//   - "_on_token_refresh": func(*oauth2.Token) - optional callback for persisting refreshed tokens
func Factory(config map[string]any) (connector.Connector, error) {
	email, ok := config["email"].(string)
	if !ok || email == "" {
		return nil, fmt.Errorf("gmail connector: missing or invalid 'email' in config")
	}

	tokenMap, ok := config["oauth_token"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("gmail connector: missing or invalid 'oauth_token' in config")
	}

	token, err := tokenFromMap(tokenMap)
	if err != nil {
		return nil, fmt.Errorf("gmail connector: parsing oauth_token: %w", err)
	}

	// Build a refreshing token source using client credentials if available,
	// otherwise fall back to a static (non-refreshing) token source.
	var tokenSource oauth2.TokenSource
	clientID, _ := config["client_id"].(string)
	clientSecret, _ := config["client_secret"].(string)
	if clientID != "" && clientSecret != "" {
		oauthConf := &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
		}
		base := oauthConf.TokenSource(context.Background(), token)

		// Wrap with persistence callback if provided. This allows the
		// connections service to persist refreshed tokens back to the DB.
		onRefresh, _ := config["_on_token_refresh"].(func(*oauth2.Token))
		tokenSource = &persistingTokenSource{
			base:      base,
			lastHash:  token.AccessToken,
			onRefresh: onRefresh,
		}
	} else {
		tokenSource = oauth2.StaticTokenSource(token)
	}

	svc, err := googleapi.NewService(context.Background(), option.WithTokenSource(tokenSource))
	if err != nil {
		return nil, fmt.Errorf("gmail connector: creating gmail service: %w", err)
	}

	client := gmailclient.NewClient(svc, email)

	return &GoogleConnector{
		client: client,
		email:  email,
	}, nil
}

// tokenFromMap reconstructs an *oauth2.Token from a map[string]any.
func tokenFromMap(m map[string]any) (*oauth2.Token, error) {
	accessToken, _ := m["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("missing access_token")
	}

	token := &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    getStringFromMap(m, "token_type"),
		RefreshToken: getStringFromMap(m, "refresh_token"),
	}

	if expiryStr, ok := m["expiry"].(string); ok && expiryStr != "" {
		t, err := time.Parse(time.RFC3339, expiryStr)
		if err != nil {
			return nil, fmt.Errorf("parsing expiry: %w", err)
		}
		token.Expiry = t
	}

	// If expiry is zero (missing or unparseable), set it to now. The oauth2
	// library checks token.Valid() which returns false when Expiry <= now,
	// triggering an automatic refresh via the refresh_token. Without this,
	// a missing expiry would make the token appear perpetually valid even
	// after the access token actually expires on Google's side.
	if token.Expiry.IsZero() {
		token.Expiry = time.Now().UTC()
	}

	return token, nil
}

func getStringFromMap(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// Type returns "google".
func (g *GoogleConnector) Type() string {
	return "google"
}

// Operations returns the list of supported Gmail operations.
func (g *GoogleConnector) Operations() []connector.OperationDef {
	return []connector.OperationDef{
		{
			Name:        "list_emails",
			Description: "Search and list emails using Gmail query syntax",
			Params: map[string]connector.ParamDef{
				"query":       {Type: "string", Description: "Gmail search query string", Required: false},
				"max_results": {Type: "int", Description: "Maximum number of results to return", Required: false},
				"page_token":  {Type: "string", Description: "Page token for pagination", Required: false},
			},
			ReadOnly: true,
		},
		{
			Name:        "read_email",
			Description: "Read a single email by message ID",
			Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Description: "The ID of the message to read", Required: true},
			},
			ReadOnly: true,
		},
		{
			Name:        "read_thread",
			Description: "Read all messages in a thread",
			Params: map[string]connector.ParamDef{
				"thread_id": {Type: "string", Description: "The ID of the thread to read", Required: true},
			},
			ReadOnly: true,
		},
		{
			Name:        "create_draft",
			Description: "Create a new email draft",
			Params: map[string]connector.ParamDef{
				"to":       {Type: "[]string", Description: "Recipient email addresses", Required: false},
				"cc":       {Type: "[]string", Description: "CC email addresses", Required: false},
				"subject":  {Type: "string", Description: "Email subject", Required: false},
				"body":     {Type: "string", Description: "Email body text", Required: false},
				"reply_to": {Type: "string", Description: "Message ID to reply to", Required: false},
			},
			ReadOnly: false,
		},
		{
			Name:        "update_draft",
			Description: "Update an existing email draft",
			Params: map[string]connector.ParamDef{
				"draft_id": {Type: "string", Description: "The ID of the draft to update", Required: true},
				"to":       {Type: "[]string", Description: "Recipient email addresses", Required: false},
				"cc":       {Type: "[]string", Description: "CC email addresses", Required: false},
				"subject":  {Type: "string", Description: "Email subject", Required: false},
				"body":     {Type: "string", Description: "Email body text", Required: false},
			},
			ReadOnly: false,
		},
		{
			Name:        "send_email",
			Description: "Send an email directly",
			Params: map[string]connector.ParamDef{
				"to":       {Type: "[]string", Description: "Recipient email addresses", Required: false},
				"cc":       {Type: "[]string", Description: "CC email addresses", Required: false},
				"subject":  {Type: "string", Description: "Email subject", Required: false},
				"body":     {Type: "string", Description: "Email body text", Required: false},
				"reply_to": {Type: "string", Description: "Message ID to reply to", Required: false},
			},
			ReadOnly: false,
		},
		{
			Name:        "send_draft",
			Description: "Send an existing draft",
			Params: map[string]connector.ParamDef{
				"draft_id": {Type: "string", Description: "The ID of the draft to send", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "reply",
			Description: "Reply to an existing email",
			Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Description: "The ID of the message to reply to", Required: true},
				"to":         {Type: "[]string", Description: "Recipient email addresses (defaults to original sender)", Required: false},
				"cc":         {Type: "[]string", Description: "CC email addresses", Required: false},
				"subject":    {Type: "string", Description: "Email subject (defaults to Re: original subject)", Required: false},
				"body":       {Type: "string", Description: "Reply body text", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "add_label",
			Description: "Add a label to a message",
			Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Description: "The ID of the message", Required: true},
				"label_id":   {Type: "string", Description: "The ID of the label to add", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "remove_label",
			Description: "Remove a label from a message",
			Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Description: "The ID of the message", Required: true},
				"label_id":   {Type: "string", Description: "The ID of the label to remove", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "archive",
			Description: "Archive a message by removing the INBOX label",
			Params: map[string]connector.ParamDef{
				"message_id": {Type: "string", Description: "The ID of the message to archive", Required: true},
			},
			ReadOnly: false,
		},
		{
			Name:        "list_labels",
			Description: "List all labels for the account",
			Params:      map[string]connector.ParamDef{},
			ReadOnly:    true,
		},
		{
			Name:        "get_attachment",
			Description: "Download an email attachment",
			Params: map[string]connector.ParamDef{
				"message_id":    {Type: "string", Description: "The ID of the message containing the attachment", Required: true},
				"attachment_id": {Type: "string", Description: "The ID of the attachment", Required: true},
			},
			ReadOnly: true,
		},

		// NOTE: Drive, Calendar, People, Sheets, and Docs operations are not yet
		// implemented. They will be added here when the corresponding client
		// methods are built. Do not declare operations without implementation —
		// agents see them in tools/list and expect them to work.
	}
}

// Execute routes an operation to the appropriate gmail.Client method.
func (g *GoogleConnector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	switch op {
	case "list_emails":
		query := gmailclient.SearchQuery{
			Query:      getStringParam(params, "query"),
			MaxResults: int64(getIntParam(params, "max_results")),
			PageToken:  getStringParam(params, "page_token"),
		}
		return g.client.ListEmails(ctx, query)

	case "read_email":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		return g.client.GetEmail(ctx, messageID)

	case "read_thread":
		threadID, err := requireStringParam(params, "thread_id")
		if err != nil {
			return nil, err
		}
		return g.client.GetThread(ctx, threadID)

	case "create_draft":
		req := gmailclient.DraftRequest{
			To:      getStringSliceParam(params, "to"),
			Cc:      getStringSliceParam(params, "cc"),
			Subject: getStringParam(params, "subject"),
			Body:    getStringParam(params, "body"),
			ReplyTo: getStringParam(params, "reply_to"),
		}
		return g.client.CreateDraft(ctx, req)

	case "update_draft":
		draftID, err := requireStringParam(params, "draft_id")
		if err != nil {
			return nil, err
		}
		req := gmailclient.DraftRequest{
			To:      getStringSliceParam(params, "to"),
			Cc:      getStringSliceParam(params, "cc"),
			Subject: getStringParam(params, "subject"),
			Body:    getStringParam(params, "body"),
		}
		return g.client.UpdateDraft(ctx, draftID, req)

	case "send_email":
		req := gmailclient.DraftRequest{
			To:      getStringSliceParam(params, "to"),
			Cc:      getStringSliceParam(params, "cc"),
			Subject: getStringParam(params, "subject"),
			Body:    getStringParam(params, "body"),
			ReplyTo: getStringParam(params, "reply_to"),
		}
		return g.client.SendEmail(ctx, req)

	case "send_draft":
		draftID, err := requireStringParam(params, "draft_id")
		if err != nil {
			return nil, err
		}
		return g.client.SendDraft(ctx, draftID)

	case "add_label":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		labelID, err := requireStringParam(params, "label_id")
		if err != nil {
			return nil, err
		}
		return nil, g.client.AddLabel(ctx, messageID, labelID)

	case "remove_label":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		labelID, err := requireStringParam(params, "label_id")
		if err != nil {
			return nil, err
		}
		return nil, g.client.RemoveLabel(ctx, messageID, labelID)

	case "archive":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		return nil, g.client.Archive(ctx, messageID)

	case "list_labels":
		return g.client.ListLabels(ctx)

	case "reply":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		req := gmailclient.DraftRequest{
			To:      getStringSliceParam(params, "to"),
			Cc:      getStringSliceParam(params, "cc"),
			Subject: getStringParam(params, "subject"),
			Body:    getStringParam(params, "body"),
			ReplyTo: messageID,
		}
		return g.client.SendEmail(ctx, req)

	case "get_attachment":
		messageID, err := requireStringParam(params, "message_id")
		if err != nil {
			return nil, err
		}
		attachmentID, err := requireStringParam(params, "attachment_id")
		if err != nil {
			return nil, err
		}
		return g.client.GetAttachment(ctx, messageID, attachmentID)

	case "drive.list_files", "drive.get_file", "drive.download_file", "drive.upload_file", "drive.share_file",
		"calendar.list_events", "calendar.get_event", "calendar.create_event", "calendar.update_event", "calendar.delete_event",
		"people.list_contacts", "people.get_contact", "people.create_contact", "people.update_contact", "people.delete_contact",
		"sheets.get_spreadsheet", "sheets.read_range", "sheets.write_range", "sheets.create_spreadsheet",
		"docs.get_document", "docs.list_documents", "docs.create_document", "docs.update_document":
		return nil, fmt.Errorf("google: %s not yet implemented", op)

	default:
		return nil, fmt.Errorf("google connector: unknown operation %q", op)
	}
}

// Validate checks that the credentials are valid by listing 1 email.
func (g *GoogleConnector) Validate(ctx context.Context) error {
	_, err := g.client.ListEmails(ctx, gmailclient.SearchQuery{MaxResults: 1})
	if err != nil {
		return fmt.Errorf("gmail connector: validation failed: %w", err)
	}
	return nil
}

// --- param helper functions ---

func getStringParam(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	v, _ := params[key].(string)
	return v
}

func requireStringParam(params map[string]any, key string) (string, error) {
	v := getStringParam(params, key)
	if v == "" {
		return "", fmt.Errorf("gmail connector: missing required parameter %q", key)
	}
	return v, nil
}

func getIntParam(params map[string]any, key string) int {
	if params == nil {
		return 0
	}
	switch v := params[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

func getStringSliceParam(params map[string]any, key string) []string {
	if params == nil {
		return nil
	}
	// Direct []string assertion
	if v, ok := params[key].([]string); ok {
		return v
	}
	// Handle []any (common when decoded from JSON)
	if v, ok := params[key].([]any); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}
