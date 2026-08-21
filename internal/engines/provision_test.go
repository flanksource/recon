package engines_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	depsconfig "github.com/flanksource/deps/pkg/config"
	"github.com/flanksource/deps/pkg/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines"
)

var _ = Describe("PATH-only engine prerequisites", func() {
	externalSpec := func() engines.Spec {
		spec := spawned()
		spec.Binary = "prowler-test"
		spec.Provisioning = engines.ProvisioningPathOnly
		spec.Version = "5.40.0"
		spec.Install = types.Package{
			VersionCommand: "--version",
			VersionRegex:   `prowler\s+(\d+\.\d+\.\d+)`,
		}
		spec.InstallInstructions = "pipx install prowler==5.40.0"
		return spec
	}

	writeExecutable := func(dir, version string) string {
		if runtime.GOOS == "windows" {
			Skip("test executable is a POSIX shell script")
		}
		path := filepath.Join(dir, "prowler-test")
		Expect(os.WriteFile(path, []byte("#!/bin/sh\nprintf 'prowler "+version+"\\n'\n"), 0o755)).To(Succeed())
		return path
	}

	It("resolves only from PATH and reports the executable as unmanaged", func() {
		managedDir := GinkgoT().TempDir()
		pathDir := GinkgoT().TempDir()
		writeExecutable(managedDir, "4.0.0")
		external := writeExecutable(pathDir, "5.40.0")
		GinkgoT().Setenv("PATH", pathDir)

		provisioner := engines.NewProvisioner(managedDir)
		resolved, err := provisioner.Resolve(externalSpec())
		Expect(err).ToNot(HaveOccurred())
		Expect(resolved).To(Equal(external))
		Expect(provisioner.Status(externalSpec())).To(Equal(engines.Status{
			Engine: "example", Binary: "prowler-test", Path: external, Installed: true, Managed: false,
		}))
	})

	It("continues with a PATH executable whose version does not match", func() {
		pathDir := GinkgoT().TempDir()
		external := writeExecutable(pathDir, "5.39.0")
		GinkgoT().Setenv("PATH", pathDir)

		resolved, err := engines.NewProvisioner(GinkgoT().TempDir()).Resolve(externalSpec())
		Expect(err).ToNot(HaveOccurred())
		Expect(resolved).To(Equal(external))
	})

	It("reports a PATH-only executable even when its version command fails", func() {
		pathDir := GinkgoT().TempDir()
		external := filepath.Join(pathDir, "prowler-test")
		Expect(os.WriteFile(external, []byte("#!/bin/sh\nexit 19\n"), 0o755)).To(Succeed())
		GinkgoT().Setenv("PATH", pathDir)

		status := engines.NewProvisioner(GinkgoT().TempDir()).Status(externalSpec())
		Expect(status).To(Equal(engines.Status{
			Engine: "example", Binary: "prowler-test", Path: external, Installed: true, Managed: false,
		}))
	})

	It("returns the documented external instruction instead of invoking deps", func() {
		GinkgoT().Setenv("PATH", GinkgoT().TempDir())
		spec := externalSpec()

		_, err := engines.NewProvisioner(GinkgoT().TempDir()).Install(context.Background(), spec, []engines.Spec{spec})
		Expect(err).To(MatchError(spec.InstallInstructions))
	})
})

var _ = Describe("what an engine is installed from", func() {
	It("uses the engine's own package rather than a deps default of the same name", func() {
		// deps ships a default registry, and for a package recon also declares
		// the two can disagree — deps resolves trivy through a redirector whose
		// file name is not in the release's checksums file, where recon's spec
		// names the asset that carries a sum. Recon's spec is the one its tests
		// describe, so it has to be the one that installs.
		registry := depsconfig.GetGlobalRegistry()
		Expect(registry).ToNot(BeNil())
		Expect(registry.Registry).To(HaveKey("trivy"))
		Expect(registry.Registry["trivy"].URLTemplate).ToNot(BeEmpty(),
			"deps no longer resolves trivy through a URL template; this check has nothing left to prove")

		declared := spawned()
		declared.Install = types.Package{
			Name: "trivy", Manager: "github_release", Repo: "aquasecurity/trivy",
			AssetPatterns:  map[string]string{"darwin-arm64": "trivy_{{.version}}_macOS-ARM64.tar.gz"},
			ChecksumFile:   "trivy_{{.version}}_checksums.txt",
			VersionCommand: "version",
		}

		// Registering happens for every spec before the requested one is
		// installed, so the install itself is pointed at a manager that does not
		// exist: it fails immediately and offline, and what matters is what
		// registering left behind.
		unresolvable := spawned()
		unresolvable.Install = types.Package{
			Name: "example", Manager: "no-such-manager", VersionCommand: "version",
		}
		_, err := engines.NewProvisioner(GinkgoT().TempDir()).Install(
			context.Background(), unresolvable, []engines.Spec{unresolvable, declared})
		Expect(err).To(HaveOccurred())

		merged := depsconfig.GetGlobalRegistry().Registry["trivy"]
		Expect(merged.URLTemplate).To(BeEmpty())
		Expect(merged.AssetPatterns).To(HaveKeyWithValue(
			"darwin-arm64", "trivy_{{.version}}_macOS-ARM64.tar.gz"))
	})
})
