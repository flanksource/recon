package engines

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/flanksource/commons/logger"
	"github.com/flanksource/deps"
	"github.com/flanksource/deps/pkg/config"
	"github.com/flanksource/deps/pkg/types"
)

// Provisioner installs and locates engine binaries.
//
// Managed engines declare a deps.Package rather than an install command, so a
// binary is version-pinned and checksum-verified. PATH-only prerequisites are
// resolved and version-checked but remain externally managed.
type Provisioner struct {
	BinDir string
	AppDir string

	once       sync.Once
	registered error
}

// NewProvisioner builds a provisioner rooted at binDir.
func NewProvisioner(binDir string) *Provisioner {
	return &Provisioner{
		BinDir: binDir,
		AppDir: filepath.Join(binDir, "apps"),
	}
}

// register merges every engine package into the deps registry. Done once and
// lazily: the registry is process-global, and merging twice would be wasted work.
//
// An engine's own package wins over a default deps already carries for the same
// name. The spec is the declaration recon tests — that every platform has an
// asset and that the download is checksum-verified — and deferring to the
// registry meant installing something those tests never described. It is not
// hypothetical: deps resolves trivy through a redirector whose file name is
// absent from the release's checksums file, so the install recon would have got
// was unverified while its own spec named the asset that carries a sum.
func (p *Provisioner) register(specs []Spec) error {
	p.once.Do(func() {
		registry := config.GetGlobalRegistry()
		if registry == nil {
			p.registered = fmt.Errorf("deps registry unavailable")
			return
		}
		if registry.Registry == nil {
			registry.Registry = map[string]types.Package{}
		}
		for _, spec := range specs {
			if spec.InProcess || spec.Provisioning == ProvisioningPathOnly {
				continue
			}
			registry.Registry[spec.Install.Name] = spec.Install
		}
		config.SetGlobalRegistry(registry)
	})
	return p.registered
}

// InProcessPath is the path reported for an engine that is linked in. It is not
// a filesystem path on purpose: nothing can exec it, and a plausible-looking
// path would invite something to try.
const InProcessPath = "(in-process)"

// Install provisions one engine's binary and returns its path. It is a no-op
// when a suitable binary is already present.
func (p *Provisioner) Install(ctx context.Context, spec Spec, all []Spec) (string, error) {
	if spec.InProcess {
		return InProcessPath, nil
	}
	if spec.Provisioning == ProvisioningPathOnly {
		path, err := p.Resolve(spec)
		if err != nil {
			return "", errors.New(spec.InstallInstructions)
		}
		return path, nil
	}
	if err := p.register(all); err != nil {
		return "", err
	}

	version := spec.Version
	if version == "" {
		version = "latest"
	}

	result, err := deps.InstallWithContext(ctx, spec.Install.Name, version,
		deps.WithBinDir(p.BinDir),
		deps.WithAppDir(p.AppDir),
	)
	if err != nil {
		return "", fmt.Errorf("install %s: %w", spec.Name, err)
	}
	if result == nil {
		return "", fmt.Errorf("install %s: no result", spec.Name)
	}

	return p.Resolve(spec)
}

// Resolve locates an engine's binary without installing: the provisioned copy
// first, then PATH. Returning the managed one first means a pinned version wins
// over whatever else is installed on the machine.
func (p *Provisioner) Resolve(spec Spec) (string, error) {
	if spec.InProcess {
		return InProcessPath, nil
	}
	if spec.Provisioning == ProvisioningPathOnly {
		found, err := pathOnlyExecutable(spec)
		if err != nil {
			return "", err
		}
		warning, err := verifyExternalVersion(spec, found)
		if err != nil {
			return "", err
		}
		if warning != "" {
			logger.Warnf("%s; continuing", warning)
		}
		return found, nil
	}

	managed := filepath.Join(p.BinDir, spec.Binary)
	if executable(managed) {
		return managed, nil
	}
	found, err := exec.LookPath(spec.Binary)
	if err != nil {
		return "", fmt.Errorf(
			"%s is not installed: run `reconctl engine install %s`", spec.Binary, spec.Name)
	}
	return found, nil
}

// Status reports whether an engine binary is present without running it.
type Status struct {
	Engine    string
	Binary    string
	Path      string
	Installed bool
	Managed   bool
	Problem   string
}

// Status inspects one engine's installation state. Resolve performs the full
// version check immediately before a PATH-only engine is used.
func (p *Provisioner) Status(spec Spec) Status {
	status := Status{Engine: spec.Name, Binary: spec.Binary}

	// A linked-in engine cannot be absent, out of date, or shadowed by a copy on
	// PATH. Reporting it as installed is not optimism — there is nothing that
	// could make it false.
	if spec.InProcess {
		status.Path = InProcessPath
		status.Installed = true
		status.Managed = true
		return status
	}

	var path string
	var err error
	if spec.Provisioning == ProvisioningPathOnly {
		path, err = pathOnlyExecutable(spec)
	} else {
		path, err = p.Resolve(spec)
	}
	if err != nil {
		status.Problem = err.Error()
		return status
	}
	status.Path = path
	status.Installed = true
	status.Managed = spec.Provisioning != ProvisioningPathOnly && filepath.Dir(path) == filepath.Clean(p.BinDir)
	return status
}

func pathOnlyExecutable(spec Spec) (string, error) {
	found, err := exec.LookPath(spec.Binary)
	if err != nil {
		return "", fmt.Errorf("%s is not installed on PATH: %s", spec.Binary, spec.InstallInstructions)
	}
	return found, nil
}

func verifyExternalVersion(spec Spec, path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, strings.Fields(spec.Install.VersionCommand)...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("check %s version: %w: %s", spec.Binary, err, strings.TrimSpace(string(output)))
	}

	pattern := spec.Install.VersionRegex
	if pattern == "" {
		pattern = `v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)`
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("check %s version: invalid pattern %q: %w", spec.Binary, pattern, err)
	}
	match := compiled.FindStringSubmatch(string(output))
	if len(match) < 2 {
		return "", fmt.Errorf("check %s version: output %q does not match %q", spec.Binary, strings.TrimSpace(string(output)), pattern)
	}
	installed := strings.TrimPrefix(match[1], "v")
	required := strings.TrimPrefix(spec.Version, "v")
	if installed != required {
		return fmt.Sprintf(
			"%s version %q does not match required %q: %s",
			spec.Binary, installed, required, spec.InstallInstructions), nil
	}
	return "", nil
}

func executable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}
