package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/flanksource/clicky/entity"
	"github.com/flanksource/clicky/task"
	flanksourceContext "github.com/flanksource/commons/context"
	"github.com/spf13/cobra"

	"github.com/flanksource/recon/internal/engines"
	_ "github.com/flanksource/recon/internal/engines/all" // register the built-in engines
	"github.com/flanksource/recon/internal/engines/discovery"
	"github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/engines/scan/nuclei"
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

// registerEngineCommands attaches the provisioning commands to the generated
// `engine` entity command, rather than declaring a second command with the same
// name. Installing is an action on an engine, not a resource of its own.
func registerEngineCommands() {
	entity.RegisterSubCommand("engine", newEngineInstallCommand())
	entity.RegisterSubCommand("engine", newEngineTemplatesCommand())
}

// newEngineTemplatesCommand provisions what an in-process engine actually needs.
//
// Nuclei is linked into this binary, so `engine install` has nothing to fetch
// for it. The corpus is the artifact that can be missing or stale instead, and
// without it every scan matches nothing — which reads as a clean run rather than
// a broken install.
func newEngineTemplatesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "templates",
		Short: "Manage the nuclei template corpus",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "update",
		Short: "Download or update the nuclei templates",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := nuclei.InstallTemplates(); err != nil {
				return err
			}
			if err := nuclei.UpdateTemplates(); err != nil {
				return err
			}
			cmd.Printf("nuclei templates %s at %s\n",
				nuclei.TemplateVersion(), nuclei.TemplatesDir())
			return nil
		},
	})

	return cmd
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
