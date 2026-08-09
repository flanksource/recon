package cli

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	flanksourceContext "github.com/flanksource/commons/context"
	"github.com/flanksource/clicky/task"
	"github.com/spf13/cobra"

	"github.com/flanksource/recon/internal/engines"
	_ "github.com/flanksource/recon/internal/engines/all" // register the built-in engines
	"github.com/flanksource/recon/internal/engines/discovery"
	"github.com/flanksource/recon/internal/engines/scan"
)

// engineKind labels which registry a spec came from, which is the one thing
// Spec itself does not know.
type engineKind struct {
	engines.Spec
	Kind string
}

// allEngines returns every registered engine, discovery first, each ordered by
// name.
func allEngines() []engineKind {
	var all []engineKind
	for _, spec := range discovery.Specs() {
		all = append(all, engineKind{Spec: spec, Kind: "discovery"})
	}
	for _, spec := range scan.Specs() {
		all = append(all, engineKind{Spec: spec, Kind: "scan"})
	}
	return all
}

func specs(of []engineKind) []engines.Spec {
	out := make([]engines.Spec, 0, len(of))
	for _, engine := range of {
		out = append(out, engine.Spec)
	}
	return out
}

// selectEngines resolves command arguments to engines, rejecting unknown names
// rather than silently installing nothing.
func selectEngines(names []string) ([]engineKind, error) {
	all := allEngines()
	if len(names) == 0 {
		return all, nil
	}

	byName := map[string]engineKind{}
	for _, engine := range all {
		byName[engine.Name] = engine
	}

	var selected []engineKind
	var unknown []string
	for _, name := range names {
		engine, ok := byName[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		selected = append(selected, engine)
	}
	if len(unknown) > 0 {
		known := make([]string, 0, len(byName))
		for name := range byName {
			known = append(known, name)
		}
		sort.Strings(known)
		return nil, fmt.Errorf("unknown engine %s (known: %s)",
			strings.Join(unknown, ", "), strings.Join(known, ", "))
	}
	return selected, nil
}

func newEngineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engine",
		Short: "Inspect and provision the scanning and discovery engines",
		Long: "Engines are compiled in; their binaries are not. Each declares a versioned,\n" +
			"checksum-verified package, and an existing copy on PATH is used rather than\n" +
			"downloaded again.",
	}
	cmd.AddCommand(newEngineStatusCommand(), newEngineInstallCommand())
	return cmd
}

func newEngineStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status [engine...]",
		Short: "Report which engine binaries are installed",
		RunE: func(cmd *cobra.Command, args []string) error {
			selected, err := selectEngines(args)
			if err != nil {
				return err
			}

			provisioner := engines.NewProvisioner(binDir)
			out := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(out, "ENGINE\tKIND\tBINARY\tSOURCE\tPATH")

			missing := 0
			for _, engine := range selected {
				status := provisioner.Status(engine.Spec)
				switch {
				case !status.Installed:
					missing++
					fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\n",
						engine.Name, engine.Kind, engine.Binary, "missing", "")
				case status.Managed:
					fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\n",
						engine.Name, engine.Kind, engine.Binary, "managed", status.Path)
				default:
					fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\n",
						engine.Name, engine.Kind, engine.Binary, "path", status.Path)
				}
			}
			if err := out.Flush(); err != nil {
				return err
			}

			if missing > 0 {
				cmd.Printf("\n%d of %d engines are not installed: run `reconctl engine install`\n",
					missing, len(selected))
			}
			return nil
		},
	}
}

func newEngineInstallCommand() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "install [engine...]",
		Short: "Provision engine binaries",
		Long: "Installs every engine, or only those named. Engines already resolvable are\n" +
			"skipped unless --force is given.",
		RunE: func(cmd *cobra.Command, args []string) error {
			selected, err := selectEngines(args)
			if err != nil {
				return err
			}

			provisioner := engines.NewProvisioner(binDir)
			all := specs(allEngines())

			// Concurrency 4: these are downloads, and hammering the release API
			// from a dozen goroutines is how a rate limit gets hit.
			group := task.StartGroup[string]("install engines",
				task.WithKind("install"), task.WithConcurrency(4))

			for _, engine := range selected {
				spec := engine.Spec
				group.Add(spec.Name, func(ctx flanksourceContext.Context, t *task.Task) (string, error) {
					if !force {
						if path, err := provisioner.Resolve(spec); err == nil {
							t.Infof("already installed: %s", path)
							return path, nil
						}
					}
					path, err := provisioner.Install(ctx, spec, all)
					if err != nil {
						return "", err
					}
					t.Infof("installed %s", path)
					return path, nil
				})
			}

			result := group.WaitFor()
			if result.Error != nil {
				return result.Error
			}
			if result.FailureCount > 0 {
				return fmt.Errorf("%d of %d engines failed to install",
					result.FailureCount, result.TaskCount)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "reinstall even when a binary is already resolvable")
	return cmd
}
