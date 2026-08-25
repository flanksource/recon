package prowler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	osExec "os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/flanksource/commons-db/connection"
	"github.com/flanksource/commons-db/shell"
	"github.com/flanksource/commons-db/types"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
	"github.com/flanksource/recon/internal/engines/scan/prowler/auth"
)

var credentialEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (e Engine) validateProviderCredentials(provider string, subject providerContext) error {
	if subject.CredentialMode == api.CredentialAmbient {
		return nil
	}
	credentials, err := credentialMap(subject.Credentials)
	if err != nil {
		return fmt.Errorf("provider context %s credential schema: %w", subject.ID, err)
	}
	canonical, err := arguments.NormalizeProvider(provider)
	if err != nil {
		return err
	}
	if err := e.spec.Options.ValidateCredentials(map[string]any{"provider": canonical}, credentials); err != nil {
		return fmt.Errorf("provider context %s credential schema: %w", subject.ID, err)
	}
	if _, err := auth.Match(canonical, subject.Arguments, credentials); err != nil {
		return fmt.Errorf("provider context %s credential policy: %w", subject.ID, err)
	}
	return nil
}

func credentialMap(credentials any) (map[string]any, error) {
	if credentials == nil {
		return map[string]any{}, nil
	}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		return nil, fmt.Errorf("encode credentials: %w", err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, fmt.Errorf("decode credentials: %w", err)
	}
	return result, nil
}

func executeProviderContext(
	ctx context.Context,
	run engines.Run,
	subject providerContext,
	workDir string,
	argv, safe []string,
	output io.Writer,
) (result *shell.ExecDetails, err error) {
	if run.Context.Context.Context == nil {
		return nil, fmt.Errorf("prowler execution context is required")
	}
	execution, err := providerShellExec(subject, run.WorkDir, workDir)
	if err != nil {
		return nil, err
	}
	prepared, err := prepareNativeCredentials(run.Context.Wrap(ctx), subject, workDir)
	if err != nil {
		return nil, fmt.Errorf("provider context %s credentials: %w", subject.ID, err)
	}
	if prepared.Cleanup != nil {
		defer func() {
			if cleanupErr := prepared.Cleanup(); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("clean up provider context %s credentials: %w", subject.ID, cleanupErr))
			}
		}()
	}
	if prepared.Native {
		execution.Connections = connection.ExecConnections{}
		execution.EnvVars = append(execution.EnvVars, prepared.EnvVars...)
	}
	if writer, ok := output.(interface{ AddSensitive([]string) }); ok {
		writer.AddSensitive(prepared.Sensitive)
	}
	execution.DisplayPath = run.Bin
	execution.DisplayArgs = safe
	command := osExec.Command(run.Bin, argv...)
	command.Stdout = output
	command.Stderr = output
	result, err = shell.RunCmd(run.Context.Wrap(ctx), execution, command)
	redactExecution(result, prepared.Sensitive)
	if err != nil {
		err = fmt.Errorf("%s", redactText(err.Error(), prepared.Sensitive))
	}
	return result, err
}

func redactExecution(result *shell.ExecDetails, values []string) {
	if result == nil {
		return
	}
	result.Stdout = redactText(result.Stdout, values)
	result.Stderr = redactText(result.Stderr, values)
}

func redactText(value string, sensitive []string) string {
	for _, secret := range sensitive {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, arguments.RedactedValue)
		}
	}
	return value
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
		if policy, ok := auth.ForProvider(provider); ok {
			execution.PassthroughEnv = append([]string(nil), policy.Ambient...)
		}
		if err := addSettingEnvironment(&execution, provider, subject.Arguments); err != nil {
			return shell.Exec{}, err
		}
		return execution, nil
	}
	if subject.CredentialMode != api.CredentialConfigured {
		return shell.Exec{}, fmt.Errorf("provider context %s has invalid credential mode %q", subject.ID, subject.CredentialMode)
	}
	if subject.Credentials == nil {
		if err := addSettingEnvironment(&execution, subject.Provider, subject.Arguments); err != nil {
			return shell.Exec{}, err
		}
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
	if err := addSettingEnvironment(&execution, subject.Provider, subject.Arguments); err != nil {
		return shell.Exec{}, err
	}
	return execution, nil
}

func addSettingEnvironment(execution *shell.Exec, provider string, arguments map[string]any) error {
	settings, err := auth.EnvironmentSettings(provider, arguments)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(settings))
	for name := range settings {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		execution.EnvVars = append(execution.EnvVars, types.EnvVar{Name: name, ValueStatic: settings[name]})
	}
	return nil
}
