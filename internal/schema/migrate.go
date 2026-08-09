package schema

import (
	"context"
	"embed"
	"fmt"

	"github.com/flanksource/commons-db/migrate"
)

//go:embed all:migrations
var migrations embed.FS

// Migrations exposes the embedded bundle so tests can build a provisioner.
func Migrations() embed.FS { return migrations }

const (
	// Dir is the root of the bundle inside the embedded filesystem.
	Dir = "migrations"

	// Name scopes the SQL hash log and the managed grant state in
	// schema_migration_scripts / schema_migration_security. It is permanent:
	// changing it makes every colocated script look unseen and re-run.
	Name = "recon"
)

// excluded keeps objects out of the Atlas diff. The migrator's own bookkeeping
// tables are not ours to reconcile, and anything another bundle owns in the
// same database must be left alone.
var excluded = []string{
	"schema_migration_scripts",
	"schema_migration_security",
}

// Options are the migrate options shared by Apply and the test provisioner, so
// a test can never migrate a different schema than production does.
func Options() []migrate.Option {
	return []migrate.Option{
		migrate.WithDir(Dir),
		migrate.WithName(Name),
		migrate.WithExclude(excluded...),
		// WithTableDrops is deliberately absent: drops stay suppressed, so a
		// mistake in the HCL cannot silently delete the inventory.
	}
}

// Apply reconciles the database with the declarative schema. It is safe to run
// on every boot — that is the point of a declarative bundle.
func Apply(ctx context.Context, connection string) error {
	if connection == "" {
		return fmt.Errorf("apply schema: no database connection")
	}
	if err := migrate.Apply(ctx, connection, migrations, Options()...); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

// NewProvisioner builds the content-addressed template provisioner dbtest uses:
// the bundle is applied once into a template database and each test clones it,
// rather than paying a full migration per suite.
func NewProvisioner() *migrate.SchemaProvisioner {
	return migrate.NewProvisioner(migrations, Options()...)
}
