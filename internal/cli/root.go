// Package cli wires the command tree. Most commands are generated from the
// registered clicky entities; the handful defined here are the ones that have no
// entity behind them — serving, the database itself, and engine provisioning.
package cli

import (
	"context"
	"net/url"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/flanksource/recon/internal/db"
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

	cmd.AddCommand(newMigrateCommand(), newDBCommand(), newEngineCommand())
	return cmd
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
