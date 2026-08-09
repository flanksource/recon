package engines

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/flanksource/deps"
	"github.com/flanksource/deps/pkg/config"
	"github.com/flanksource/deps/pkg/types"
)

// Provisioner installs and locates engine binaries.
//
// Engines declare a deps.Package rather than an install command, so a binary is
// version-pinned and checksum-verified instead of whatever `go install @latest`
// happened to fetch. An existing copy on PATH is honoured via the package's
// PreInstalled list — this does not insist on managing a tool the machine
// already has.
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
			// Do not shadow a package deps already knows how to install.
			if _, exists := registry.Registry[spec.Install.Name]; exists {
				continue
			}
			registry.Registry[spec.Install.Name] = spec.Install
		}
		config.SetGlobalRegistry(registry)
	})
	return p.registered
}

// Install provisions one engine's binary and returns its path. It is a no-op
// when a suitable binary is already present.
func (p *Provisioner) Install(ctx context.Context, spec Spec, all []Spec) (string, error) {
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

// Status reports what is installed, for `doctor`.
type Status struct {
	Engine    string
	Binary    string
	Path      string
	Installed bool
	Managed   bool
	Problem   string
}

// Status resolves one engine's installation state.
func (p *Provisioner) Status(spec Spec) Status {
	status := Status{Engine: spec.Name, Binary: spec.Binary}

	path, err := p.Resolve(spec)
	if err != nil {
		status.Problem = err.Error()
		return status
	}
	status.Path = path
	status.Installed = true
	status.Managed = filepath.Dir(path) == filepath.Clean(p.BinDir)
	return status
}

func executable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}
