// Package tokens manages API tokens that authenticate AI agents to Sieve.
//
// Each token is a capability handle: it grants access to specific connections
// and is bound to one or more policies (composed at evaluation time). The token
// itself is a random 32-byte secret with a "sieve_tok_" prefix.
//
// Security design:
//   - Only the SHA-256 hash is stored. Plaintext returned once at creation.
//   - All failure modes return generic "invalid token" to prevent enumeration.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/murbard/Sieve/internal/database"
)

// Token represents a stored API token.
type Token struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Connections []string   `json:"connections"`
	PolicyIDs   []string   `json:"policy_ids"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Revoked     bool       `json:"revoked"`
}

// CreateRequest is used when creating a new token.
type CreateRequest struct {
	Name        string
	Connections []string
	PolicyIDs   []string
	ExpiresIn   time.Duration // 0 means no expiry
}

// CreateResult is returned after creating a token.
type CreateResult struct {
	Token          *Token
	PlaintextToken string // "sieve_tok_..." - only returned at creation time
}

type Service struct {
	db *database.DB
}

func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

// Create generates a new API token.
func (s *Service) Create(req *CreateRequest) (*CreateResult, error) {
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generate token id: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	plaintext := "sieve_tok_" + hex.EncodeToString(tokenBytes)

	hash := sha256.Sum256([]byte(plaintext))
	tokenHash := hex.EncodeToString(hash[:])

	connectionsJSON, err := json.Marshal(req.Connections)
	if err != nil {
		return nil, fmt.Errorf("marshal connections: %w", err)
	}

	policyIDsJSON, err := json.Marshal(req.PolicyIDs)
	if err != nil {
		return nil, fmt.Errorf("marshal policy_ids: %w", err)
	}

	now := time.Now().UTC()
	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := now.Add(req.ExpiresIn)
		expiresAt = &t
	}

	_, err = s.db.Exec(
		`INSERT INTO tokens (id, name, token_hash, connections, policy_ids, created_at, expires_at, revoked)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		id, req.Name, tokenHash, string(connectionsJSON), string(policyIDsJSON), now, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert token: %w", err)
	}

	token := &Token{
		ID:          id,
		Name:        req.Name,
		Connections: req.Connections,
		PolicyIDs:   req.PolicyIDs,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
	}

	return &CreateResult{Token: token, PlaintextToken: plaintext}, nil
}

func (s *Service) Validate(plaintextToken string) (*Token, error) {
	hash := sha256.Sum256([]byte(plaintextToken))
	tokenHash := hex.EncodeToString(hash[:])

	row := s.db.QueryRow(
		`SELECT id, name, connections, policy_ids, created_at, expires_at, revoked
		 FROM tokens WHERE token_hash = ?`, tokenHash,
	)

	token, err := scanToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("invalid token")
		}
		return nil, fmt.Errorf("query token: %w", err)
	}

	if token.Revoked {
		return nil, fmt.Errorf("invalid token")
	}
	if token.ExpiresAt != nil && time.Now().UTC().After(*token.ExpiresAt) {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func (s *Service) Get(id string) (*Token, error) {
	row := s.db.QueryRow(
		`SELECT id, name, connections, policy_ids, created_at, expires_at, revoked
		 FROM tokens WHERE id = ?`, id,
	)
	token, err := scanToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("token not found")
		}
		return nil, err
	}
	return token, nil
}

func (s *Service) List() ([]Token, error) {
	rows, err := s.db.Query(
		`SELECT id, name, connections, policy_ids, created_at, expires_at, revoked FROM tokens`,
	)
	if err != nil {
		return nil, fmt.Errorf("query tokens: %w", err)
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		token, err := scanTokenRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		tokens = append(tokens, *token)
	}
	return tokens, rows.Err()
}

func (s *Service) Revoke(id string) error {
	result, err := s.db.Exec(`UPDATE tokens SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

func (s *Service) Delete(id string) error {
	result, err := s.db.Exec(`DELETE FROM tokens WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanFromScanner(s scanner) (*Token, error) {
	var (
		token           Token
		connectionsJSON string
		policyIDsJSON   string
		expiresAt       sql.NullTime
		revoked         int
	)

	err := s.Scan(
		&token.ID, &token.Name, &connectionsJSON, &policyIDsJSON,
		&token.CreatedAt, &expiresAt, &revoked,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(connectionsJSON), &token.Connections); err != nil {
		return nil, fmt.Errorf("unmarshal connections: %w", err)
	}
	if err := json.Unmarshal([]byte(policyIDsJSON), &token.PolicyIDs); err != nil {
		return nil, fmt.Errorf("unmarshal policy_ids: %w", err)
	}
	if expiresAt.Valid {
		token.ExpiresAt = &expiresAt.Time
	}
	token.Revoked = revoked != 0

	return &token, nil
}

func scanToken(row *sql.Row) (*Token, error)      { return scanFromScanner(row) }
func scanTokenRow(rows *sql.Rows) (*Token, error) { return scanFromScanner(rows) }
