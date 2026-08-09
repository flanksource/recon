// Package cli wires the command tree. Most commands are generated from the
// registered clicky entities; the handful defined here are the ones that have no
// entity behind them — serving, the database itself, and engine provisioning.
package cli

import (
	"context"
	"net/url"
	"regexp"

	"github.com/flanksource/clicky"
	"github.com/spf13/cobra"

	"github.com/flanksource/recon/internal/db"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/entities"
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

	flags := cmd.PersistentFlags()
	flags.StringVar(&databaseURL, "db-url", "",
		"external Postgres DSN; defaults to an embedded server (env "+db.EnvURL+")")
	flags.StringVar(&dataDir, "data-dir", "",
		"where the embedded Postgres cluster lives (default: the user cache directory)")
	flags.StringVar(&binDir, "bin-dir", ".bin",
		"where engine binaries are provisioned")
	flags.StringVar(&root, "root", ".",
		"working root for engine inputs and artifacts")

	cmd.AddCommand(newMigrateCommand(), newDBCommand(), newServeCommand())

	// Entities are declared before the tree is generated and before any flag is
	// parsed, so their subcommands exist to be parsed into. The database they
	// need is attached later, in the PersistentPreRun below.
	registry = &entities.Registry{Provisioner: engines.NewProvisioner(binDir)}
	registry.Register()
	registerEngineCommands()
	clicky.GenerateCLI(cmd)

	cmd.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		if !needsDatabase(cmd) {
			return nil
		}
		config, err := databaseConfig(true)
		if err != nil {
			return err
		}
		handle, err := db.Open(cmd.Context(), config)
		if err != nil {
			return err
		}
		opened = handle
		registry.SetStore(store.New(handle.Gorm))
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
	opened   *db.Handle
)

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
		case "migrate", "db", "serve", "engine":
			return false
		}
	}
	return true
}

// databaseConfig resolves the flags into a database configuration.
func databaseConfig(migrate bool) (db.Config, error) {
	directory := dataDir
	if directory == "" {
		resolved, err := db.DefaultDataDir()
		if err != nil {
			return db.Config{}, err
		}
		directory = resolved
	}
	return db.Config{URL: databaseURL, DataDir: directory, Migrate: migrate}, nil
}

// withDatabase opens the database, runs fn, and always closes.
func withDatabase(ctx context.Context, migrate bool, fn func(*db.Handle) error) error {
	config, err := databaseConfig(migrate)
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
			return withDatabase(cmd.Context(), true, func(handle *db.Handle) error {
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
			return withDatabase(cmd.Context(), false, func(handle *db.Handle) error {
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
