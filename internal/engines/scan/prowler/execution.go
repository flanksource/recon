package prowler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	osExec "os/exec"
	"regexp"

	"github.com/flanksource/commons-db/shell"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
)

var credentialEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var cloudflareAmbientEnvironment = []string{
	"CLOUDFLARE_API_TOKEN",
	"CLOUDFLARE_API_KEY",
	"CLOUDFLARE_API_EMAIL",
}

func (e Engine) validateProviderCredentials(provider string, subject providerContext) error {
	if subject.CredentialMode == api.CredentialAmbient {
		return nil
	}
	credentials := map[string]any{}
	if subject.Credentials != nil {
		encoded, err := json.Marshal(subject.Credentials)
		if err != nil {
			return fmt.Errorf("provider context %s credential schema: encode credentials: %w", subject.ID, err)
		}
		if err := json.Unmarshal(encoded, &credentials); err != nil {
			return fmt.Errorf("provider context %s credential schema: decode credentials: %w", subject.ID, err)
		}
	}
	canonical, err := arguments.NormalizeProvider(provider)
	if err != nil {
		return err
	}
	if err := e.spec.Options.ValidateCredentials(map[string]any{"provider": canonical}, credentials); err != nil {
		return fmt.Errorf("provider context %s credential schema: %w", subject.ID, err)
	}
	return nil
}

func executeProviderContext(
	ctx context.Context,
	run engines.Run,
	subject providerContext,
	workDir string,
	argv, safe []string,
	output io.Writer,
) (*shell.ExecDetails, error) {
	if run.Context.Context.Context == nil {
		return nil, fmt.Errorf("prowler execution context is required")
	}
	execution, err := providerShellExec(subject, run.WorkDir, workDir)
	if err != nil {
		return nil, err
	}
	execution.DisplayPath = run.Bin
	execution.DisplayArgs = safe
	command := osExec.Command(run.Bin, argv...)
	command.Stdout = output
	command.Stderr = output
	return shell.RunCmd(run.Context.Wrap(ctx), execution, command)
}

func providerShellExec(subject providerContext, baseDir, workDir string) (shell.Exec, error) {
	execution := shell.Exec{
		BaseDir: baseDir, Chroot: workDir, SuccessExitCodes: []int{0, 3},
	}
	if subject.CredentialMode == api.CredentialAmbient {
		if subject.Credentials != nil && !subject.Credentials.Empty() {
			return shell.Exec{}, fmt.Errorf("provider context %s has runtime credentials in ambient mode", subject.ID)
		}
		provider, err := arguments.NormalizeProvider(subject.Provider)
		if err != nil {
			return shell.Exec{}, err
		}
		if provider == "cloudflare" {
			execution.PassthroughEnv = append([]string(nil), cloudflareAmbientEnvironment...)
		}
		return execution, nil
	}
	if subject.CredentialMode != api.CredentialConfigured {
		return shell.Exec{}, fmt.Errorf("provider context %s has invalid credential mode %q", subject.ID, subject.CredentialMode)
	}
	if subject.Credentials == nil {
		return execution, nil
	}
	seen := make(map[string]struct{}, len(subject.Credentials.EnvVars))
	for _, variable := range subject.Credentials.EnvVars {
		if !credentialEnvironmentName.MatchString(variable.Name) {
			return shell.Exec{}, fmt.Errorf("provider context %s has invalid credential environment name %q", subject.ID, variable.Name)
		}
		if _, found := seen[variable.Name]; found {
			return shell.Exec{}, fmt.Errorf("provider context %s repeats credential environment %q", subject.ID, variable.Name)
		}
		if variable.IsEmpty() {
			return shell.Exec{}, fmt.Errorf("provider context %s credential environment %q has no value", subject.ID, variable.Name)
		}
		if variable.ValueStatic != "" && variable.ValueFrom != nil {
			return shell.Exec{}, fmt.Errorf("provider context %s credential environment %q has both value and valueFrom", subject.ID, variable.Name)
		}
		seen[variable.Name] = struct{}{}
		execution.EnvVars = append(execution.EnvVars, *variable.DeepCopy())
	}
	if subject.Credentials.Connections != nil {
		if subject.Credentials.Connections.EKSPodIdentity || subject.Credentials.Connections.ServiceAccount {
			return shell.Exec{}, fmt.Errorf("provider context %s configured credentials cannot inherit ambient credentials", subject.ID)
		}
		execution.Connections = *subject.Credentials.Connections.DeepCopy()
	}
	return execution, nil
}
