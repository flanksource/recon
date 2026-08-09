// Package db resolves a database and brings the schema up to date. It is the
// only place that decides between an embedded Postgres and an external one.
package db

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	commonsdb "github.com/flanksource/commons-db/db"
	"gorm.io/gorm"

	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

// EnvURL names an external database. Set it and the embedded server is never
// started.
const EnvURL = "RECON_DB_URL"

// Config selects and prepares the database.
type Config struct {
	// URL is an external DSN. Empty means start (or reuse) an embedded server
	// under DataDir.
	URL string

	// DataDir roots the embedded cluster. Required when URL is empty:
	// StartEmbedded deliberately picks no default, because a stray data
	// directory holding a security inventory is not something to create by
	// accident.
	DataDir string

	// Migrate applies the declarative schema after connecting. On by default;
	// turn it off only to inspect a database you must not modify.
	Migrate bool

	// Logger receives the embedded server's diagnostic output. Defaults to
	// stderr — never stdout, which carries structured command output.
	Logger io.Writer
}

// Handle is a live database plus whatever has to be released.
type Handle struct {
	DSN   string
	Gorm  *gorm.DB
	Store *store.Store

	stop func() error
}

// Close releases the pool and stops an embedded server if this process started
// one. It is safe to call on a nil handle.
func (h *Handle) Close() error {
	if h == nil || h.stop == nil {
		return nil
	}
	return h.stop()
}

// Open resolves the configuration into a ready database: an embedded server is
// started if needed, the schema is applied, and a store is returned.
func Open(ctx context.Context, config Config) (*Handle, error) {
	logger := config.Logger
	if logger == nil {
		logger = os.Stderr
	}

	dsn := config.URL
	if dsn == "" {
		dsn = os.Getenv(EnvURL)
	}

	handle := &Handle{}
	if dsn == "" {
		if config.DataDir == "" {
			return nil, fmt.Errorf("no database: set --db-url, %s, or a data directory", EnvURL)
		}
		if err := os.MkdirAll(config.DataDir, 0o700); err != nil {
			return nil, fmt.Errorf("create data directory %s: %w", config.DataDir, err)
		}

		started, stop, err := commonsdb.StartEmbedded(commonsdb.EmbeddedConfig{
			DataDir:  config.DataDir,
			Database: "recon",
			Logger:   logger,
		})
		if err != nil {
			return nil, fmt.Errorf("start embedded postgres in %s: %w", config.DataDir, err)
		}
		dsn = started
		handle.stop = stop
	}
	handle.DSN = dsn

	if config.Migrate {
		if err := schema.Apply(ctx, dsn); err != nil {
			_ = handle.Close()
			return nil, err
		}
	}

	gormDB, _, err := commonsdb.SetupDB(dsn, "recon")
	if err != nil {
		_ = handle.Close()
		return nil, fmt.Errorf("connect: %w", err)
	}

	handle.Gorm = gormDB
	handle.Store = store.New(gormDB)
	return handle, nil
}

// DefaultDataDir is where the embedded cluster lives when nothing else is
// configured. It sits under the user cache directory rather than the repo: the
// inventory describes live infrastructure and has no business inside a checkout
// that might be shared or archived.
func DefaultDataDir() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve cache directory: %w", err)
	}
	return filepath.Join(cache, "flanksource", "recon", "postgres"), nil
}
