// Package cli wires the command tree. Most commands are generated from the
// registered clicky entities; the handful defined here are the ones that have no
// entity behind them — serving, probing, the database itself, and engine provisioning.
package cli

import (
	"context"
	"fmt"
	"net/url"
	"regexp"

	"github.com/flanksource/clicky"
	"github.com/spf13/cobra"

	"github.com/flanksource/recon/internal/db"
	"github.com/flanksource/recon/internal/discovery"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/entities"
	"github.com/flanksource/recon/internal/probes"
	"github.com/flanksource/recon/internal/scan"
	"github.com/flanksource/recon/internal/store"
)

// Global flags shared by every command that touches the database.
var (
	databaseURL string
	dataDir     string
	binDir      string
	root        string
)

// New builds the root command.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reconctl",
		Short: "Attack-surface inventory, discovery and scanning",
		Long: "reconctl maintains an inventory of internet-facing hosts, keeps it current with\n" +
			"pluggable discovery engines, and scans a filtered selection of it.\n\n" +
			"Every resource is served identically on this CLI and over HTTP: `reconctl serve`\n" +
			"exposes the same operations as REST with an OpenAPI description.",
		SilenceUsage: true,
	}
	clicky.BindAllFlagsToCommand(cmd)

	flags := cmd.PersistentFlags()
	flags.StringVar(&databaseURL, "db-url", "",
		"external Postgres DSN; defaults to an embedded server (env "+db.EnvURL+")")
	flags.StringVar(&dataDir, "data-dir", "",
		"where the embedded Postgres cluster lives (default: the user cache directory)")
	flags.StringVar(&binDir, "bin-dir", ".bin",
		"where engine binaries are provisioned")
	flags.StringVar(&root, "root", ".",
		"working root for engine inputs and artifacts")

	// These administer the process rather than serve a resource, so they are
	// kept off the generated HTTP surface: publishing the CLI would otherwise
	// let an unauthenticated request migrate the schema, print the DSN, or start
	// a second server inside this one.
	for _, local := range []*cobra.Command{newMigrateCommand(), newDBCommand(), newServeCommand()} {
		clicky.MarkLocalOnly(local)
		cmd.AddCommand(local)
	}
	ping := addPingCommand(cmd)
	clicky.MarkLocalOnly(ping)

	// Entities are declared before the tree is generated and before any flag is
	// parsed, so their subcommands exist to be parsed into. The database they
	// need is attached later, in the PersistentPreRun below.
	provisioner := engines.NewProvisioner(binDir)
	scans = &scan.Runtime{Provisioner: provisioner, Root: root}
	sweeps = &discovery.Runner{Provisioner: provisioner, Root: root}
	liveness = &probes.Runner{}
	registry = &entities.Registry{
		Provisioner: provisioner,
		Runtimes:    entities.Runtimes{Scans: scans, Discovery: sweeps, Probes: liveness},
	}
	registry.Register()
	registerEngineCommands()
	clicky.GenerateCLI(cmd)

	cmd.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		clicky.Flags.UseFlags()
		if !needsDatabase(cmd) {
			return nil
		}
		config, err := databaseConfig(databaseOptions{})
		if err != nil {
			return err
		}
		handle, err := db.Open(cmd.Context(), config)
		if err != nil {
			return err
		}
		opened = handle
		st := store.New(handle.Gorm)
		registry.SetStore(st)
		scans.Store = st
		sweeps.Store = st
		liveness.Store = st

		// Seeded here as well as in serve: without an import step this is the
		// only source of a working configuration, and a CLI-only user who never
		// starts the server would otherwise be told every engine's own profile
		// does not exist. It never overwrites, so an edited profile survives.
		if _, err := st.SeedDefaultProfiles(cmd.Context()); err != nil {
			return fmt.Errorf("seed built-in profiles: %w", err)
		}
		return nil
	}

	cmd.PersistentPostRun = func(*cobra.Command, []string) {
		if opened != nil {
			_ = opened.Close()
			opened = nil
		}
	}

	return cmd
}

// registry and opened are process-global because the entity handlers are
// registered once, at construction, and have to reach whatever database the
// flags eventually name.
var (
	registry *entities.Registry
	scans    *scan.Runtime
	sweeps   *discovery.Runner
	liveness *probes.Runner
	opened   *db.Handle
)

// Runtimes returns the scan, discovery and probe runtimes the command tree
// built, so the server can serve their streaming and action routes. Valid only
// after New.
func Runtimes() (*scan.Runtime, *discovery.Runner, *probes.Runner) { return scans, sweeps, liveness }

// EntityRegistry returns the registry the command tree registered, so a test
// can serve the same entities against its own database. Valid only after New.
func EntityRegistry() *entities.Registry { return registry }

// needsDatabase reports whether this command needs a connection opened for it.
//
// The hand-written commands open their own — `db url` deliberately does so
// without migrating — and `engine` does not touch the inventory at all.
// Everything else is a generated entity command, which by definition reads a
// table. Opening Postgres to print a help page would be a slow way to answer a
// question that does not involve it.
func needsDatabase(cmd *cobra.Command) bool {
	if !cmd.Runnable() {
		return false
	}
	for current := cmd; current != nil; current = current.Parent() {
		switch current.Name() {
		case "migrate", "db", "serve", "engine", "ping":
			return false
		}
	}
	return true
}

type databaseOptions struct {
	SkipMigrate bool
}

// databaseConfig resolves the flags into a database configuration.
func databaseConfig(options databaseOptions) (db.Config, error) {
	directory := dataDir
	if directory == "" {
		resolved, err := db.DefaultDataDir()
		if err != nil {
			return db.Config{}, err
		}
		directory = resolved
	}
	return db.Config{URL: databaseURL, DataDir: directory, SkipMigrate: options.SkipMigrate}, nil
}

// withDatabase opens the database, runs fn, and always closes.
func withDatabase(ctx context.Context, options databaseOptions, fn func(*db.Handle) error) error {
	config, err := databaseConfig(options)
	if err != nil {
		return err
	}
	handle, err := db.Open(ctx, config)
	if err != nil {
		return err
	}
	defer func() { _ = handle.Close() }()
	return fn(handle)
}

func newMigrateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Apply the declarative schema",
		Long: "Reconciles the database with the embedded Atlas HCL bundle. Safe to run\n" +
			"repeatedly — that is the point of a declarative schema — and it runs\n" +
			"automatically on serve.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withDatabase(cmd.Context(), databaseOptions{}, func(handle *db.Handle) error {
				cmd.Printf("schema applied to %s\n", redact(handle.DSN))
				return nil
			})
		},
	}
}

func newDBCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Inspect the database",
		Args:  cobra.NoArgs,
	}

	url := &cobra.Command{
		Use:   "url",
		Short: "Print the connection string",
		Long: "Starts the embedded server if it is not already running, then prints its DSN —\n" +
			"which is also how to warm the cluster before going offline, since the first\n" +
			"start downloads a Postgres distribution.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// No migration: this is for pointing psql at the database, including
			// one this build must not modify.
			return withDatabase(cmd.Context(), databaseOptions{SkipMigrate: true}, func(handle *db.Handle) error {
				cmd.Println(handle.DSN)
				return nil
			})
		},
	}

	cmd.AddCommand(url)
	return cmd
}

// keyValuePassword matches the password in a libpq key/value DSN, which
// net/url leaves untouched because it has no userinfo section.
var keyValuePassword = regexp.MustCompile(`(?i)\bpassword\s*=\s*('[^']*'|\S+)`)

// redact hides the password in a DSN before it reaches a terminal or a log.
// `db url` prints the real DSN deliberately — that is its purpose — but every
// other message goes through here.
func redact(dsn string) string {
	if parsed, err := url.Parse(dsn); err == nil && parsed.User != nil {
		if _, hasPassword := parsed.User.Password(); hasPassword {
			parsed.User = url.User(parsed.User.Username())
			return parsed.String()
		}
		return dsn
	}
	return keyValuePassword.ReplaceAllString(dsn, "password=***")
}
