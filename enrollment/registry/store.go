// Package registry persists individual-agent enrollment and broker authorization.
// It is shared by trusted server components, not shipped as endpoint configuration.
package registry

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
)

var (
	ErrNotFound    = errors.New("agent enrollment resource not found")
	ErrUnavailable = errors.New("agent enrollment is unavailable")
	ErrInvalid     = errors.New("invalid agent enrollment configuration")
	ErrDenied      = errors.New("agent identity is not authorized")
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	db      *sql.DB
	secrets cipher.AEAD
}

func NewStore(db *sql.DB, masterKey string) (*Store, error) {
	if db == nil || len(masterKey) < 32 {
		return nil, ErrInvalid
	}
	key := sha256.Sum256([]byte("openuem/agent-registry/secrets/v1\x00" + masterKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, secrets: aead}, nil
}

// Migrate requires the existing OpenUEM tenant/site tables. It adds only its own
// objects and serializes migration execution across trusted service replicas.
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627910)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS uem_agent_migrations(name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var applied bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_migrations WHERE name=$1)`, name).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("agent registry migration %s: %w", name, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_migrations(name) VALUES($1)`, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) seal(value []byte, purpose string) ([]byte, error) {
	nonce := make([]byte, s.secrets.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.secrets.Seal(nonce, nonce, value, []byte(purpose)), nil
}

func (s *Store) open(value []byte, purpose string) ([]byte, error) {
	if len(value) < s.secrets.NonceSize() {
		return nil, ErrUnavailable
	}
	data, err := s.secrets.Open(nil, value[:s.secrets.NonceSize()], value[s.secrets.NonceSize():], []byte(purpose))
	if err != nil {
		return nil, ErrUnavailable
	}
	return data, nil
}

func digest(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func newToken() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

type Scope struct {
	TenantID int `json:"tenant_id"`
	SiteID   int `json:"site_id"`
}

func (s Scope) valid() bool { return s.TenantID > 0 && s.SiteID >= 0 }

func audit(ctx context.Context, tx *sql.Tx, scope Scope, actor, action, id string) error {
	if !scope.valid() || actor == "" || len(actor) > 255 {
		return ErrInvalid
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO uem_agent_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,NULLIF($2,0),$3,$4,$5)`, scope.TenantID, scope.SiteID, actor, action, id)
	return err
}
