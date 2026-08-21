package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
)

// imageContext is one resolved provider context, as the runtime hands it over.
func imageContext(id, image string) engines.ProviderContext {
	return engines.ProviderContext{
		ID: id, Provider: ProviderImage, CredentialMode: api.CredentialAmbient,
		Arguments: map[string]any{"image": image},
	}
}

var _ = Describe("building a trivy command line", func() {
	build := func(providerID string, profile, arguments map[string]any) []string {
		GinkgoHelper()
		entry, err := find(providerID)
		Expect(err).ToNot(HaveOccurred())
		argv, err := entry.argv(profile, arguments, "/results/report.json")
		Expect(err).ToNot(HaveOccurred())
		return argv
	}

	It("renders the subcommand, the profile, the output contract and the subject", func() {
		argv := build(ProviderImage,
			map[string]any{
				"scanners":       []any{"vuln", "secret"},
				"severity":       []any{"CRITICAL", "HIGH"},
				"ignore-unfixed": true,
				"timeout":        "10m",
			},
			map[string]any{"image": "ghcr.io/acme/api:1.4"})

		Expect(argv).To(Equal([]string{
			"image",
			"--ignore-unfixed",
			"--scanners", "vuln,secret",
			"--severity", "CRITICAL,HIGH",
			"--timeout", "10m",
			"--format", "json", "--no-progress",
			"--output", "/results/report.json",
			"ghcr.io/acme/api:1.4",
		}))
	})

	It("orders flags deterministically so a recorded command is diffable", func() {
		first := build(ProviderFilesystem,
			map[string]any{"scanners": []any{"secret"}, "timeout": "1m", "offline-scan": true},
			map[string]any{"path": "/srv/checkout"})
		second := build(ProviderFilesystem,
			map[string]any{"offline-scan": true, "timeout": "1m", "scanners": []any{"secret"}},
			map[string]any{"path": "/srv/checkout"})

		Expect(first).To(Equal(second))
	})

	It("passes the context's own options as flags and its subject positionally", func() {
		argv := build(ProviderRepository,
			map[string]any{"scanners": []any{"secret"}},
			map[string]any{
				"repository": "https://github.com/acme/api",
				"commit":     "9f0a1b2",
			})

		Expect(argv).To(ContainElements("--commit", "9f0a1b2"))
		// The repository is what trivy takes as its argument, so it must not
		// also appear as --repository.
		Expect(argv).ToNot(ContainElement("--repository"))
		Expect(argv[len(argv)-1]).To(Equal("https://github.com/acme/api"))
	})

	It("omits a false boolean rather than passing --flag=false", func() {
		// Trivy treats these flags as switches: their presence is the setting,
		// so "false" has to mean "leave trivy's own default alone".
		argv := build(ProviderImage,
			map[string]any{"scanners": []any{"vuln"}, "ignore-unfixed": false},
			map[string]any{"image": "alpine:3.19"})

		Expect(argv).ToNot(ContainElement("--ignore-unfixed"))
	})

	It("renders a list as one comma-separated value, which is what trivy parses", func() {
		argv := build(ProviderImage,
			map[string]any{"scanners": []any{"vuln", "misconfig", "secret"}},
			map[string]any{"image": "alpine:3.19"})

		Expect(argv).To(ContainElements("--scanners", "vuln,misconfig,secret"))
	})

	It("refuses a context with nothing to scan", func() {
		entry, err := find(ProviderImage)
		Expect(err).ToNot(HaveOccurred())

		_, err = entry.argv(map[string]any{}, map[string]any{"image": "  "}, "/results/report.json")
		Expect(err).To(MatchError(ContainSubstring("image is required")))
	})

	It("refuses a relative filesystem path", func() {
		entry, err := find(ProviderFilesystem)
		Expect(err).ToNot(HaveOccurred())

		// A scan runs with its working directory set to its own artifact
		// directory, so "src" would resolve there and quietly scan nothing.
		_, err = entry.argv(map[string]any{}, map[string]any{"path": "src"}, "/results/report.json")
		Expect(err).To(MatchError(ContainSubstring("is relative")))
	})
})

var _ = Describe("resolving the contexts of a run", func() {
	image, err := find(ProviderImage)
	Expect(err).ToNot(HaveOccurred())

	It("accepts contexts of the provider the profile selected", func() {
		contexts, err := contextsForRun([]engines.ProviderContext{
			imageContext("api-image", "ghcr.io/acme/api:1.4"),
			imageContext("web-image", "ghcr.io/acme/web:2.0"),
		}, image)

		Expect(err).ToNot(HaveOccurred())
		Expect(contexts).To(HaveLen(2))
	})

	It("refuses a context belonging to another provider", func() {
		other := imageContext("api-repo", "ghcr.io/acme/api:1.4")
		other.Provider = ProviderRepository

		_, err := contextsForRun([]engines.ProviderContext{other}, image)
		Expect(err).To(MatchError(ContainSubstring("uses provider git-repository, not container-image")))
	})

	It("refuses the same context twice, which would double every finding", func() {
		_, err := contextsForRun([]engines.ProviderContext{
			imageContext("api-image", "ghcr.io/acme/api:1.4"),
			imageContext("api-image", "ghcr.io/acme/api:1.4"),
		}, image)

		Expect(err).To(MatchError(ContainSubstring("duplicate provider context")))
	})

	It("refuses a run with no contexts rather than reporting a clean scan", func() {
		_, err := contextsForRun(nil, image)
		Expect(err).To(MatchError(ContainSubstring("no in-memory provider contexts")))
	})
})

// sink collects what an engine reports, so a run can be asserted on without a
// database or an HTTP stream behind it.
type sink struct {
	findings []api.Finding
	stats    api.ScanStats
	log      []string
}

func (s *sink) Finding(finding api.Finding) error {
	s.findings = append(s.findings, finding)
	return nil
}
func (s *sink) Stats(stats api.ScanStats) { s.stats = stats }
func (s *sink) Log(text string)           { s.log = append(s.log, text) }

// installedTrivy is the binary these specs drive, or a skip.
//
// LookPath alone is not the question: it answers "is there a file called trivy
// with the execute bit", and a half-finished install — an archive saved under
// the binary's own name, which is what a download without extraction leaves —
// passes that and then fails to exec. Asking it for its version is the same
// question asked properly, and reports which of the two it hit.
func installedTrivy() string {
	GinkgoHelper()
	if testing.Short() {
		Skip("runs the engine binary")
	}
	bin, err := exec.LookPath("trivy")
	if err != nil {
		Skip("trivy is not installed")
	}
	if output, err := exec.Command(bin, "version").CombinedOutput(); err != nil {
		Skip(fmt.Sprintf("trivy at %s does not run: %v: %s", bin, err, strings.TrimSpace(string(output))))
	}
	return bin
}

// This is the check the option catalog cannot make: that trivy itself accepts
// the command line recon builds and writes the report recon then reads. Secrets
// only, because that scanner needs neither the vulnerability database nor the
// checks bundle, so the whole run is offline and takes about a second.
var _ = Describe("running trivy", Label("binaries"), func() {
	// The fixture has to look like a GitHub token to trivy's own rule, and this
	// file must not look like one to a secret scanner reading the repository.
	// Assembling it keeps both true: the credential shape only ever exists in
	// the temporary file trivy is pointed at, and it was never a real token.
	token := "ghp_" + strings.Repeat("aB3", 12)

	It("scans a directory and reports what it found", func(ctx SpecContext) {
		bin := installedTrivy()

		scanned := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(scanned, "credentials"),
			[]byte("github_token = "+token+"\n"), 0o600)).To(Succeed())

		workDir := GinkgoT().TempDir()
		run := engines.Run{
			Bin: bin, WorkDir: workDir,
			Config: map[string]any{
				"provider":     ProviderFilesystem,
				"scanners":     []any{"secret"},
				"offline-scan": true,
				"timeout":      "2m",
			},
			Out: filepath.Join(workDir, "findings.jsonl"),
			ProviderContexts: []engines.ProviderContext{{
				ID: "checkout", Provider: ProviderFilesystem, CredentialMode: api.CredentialAmbient,
				Arguments: map[string]any{"path": scanned},
			}},
		}

		engine, err := newEngine()
		Expect(err).ToNot(HaveOccurred())
		Expect(engine.Spec().ValidateConfig(run.Config)).To(Succeed())

		collected := &sink{}
		Expect(engine.Run(ctx, run, collected)).To(Succeed())

		Expect(collected.findings).To(HaveLen(1))
		found := collected.findings[0]
		Expect(found.TemplateID).To(Equal("github-pat"))
		Expect(found.Severity).To(Equal(api.SeverityCritical))
		Expect(found.TargetID).To(Equal("checkout"))
		Expect(found.MatcherName).To(Equal("secret"))
		// Trivy masks the value in its own report, so nothing recon keeps
		// carries the token itself.
		Expect(found.Raw["Match"]).ToNot(ContainSubstring(token))

		Expect(collected.stats.Matched).To(Equal(float64(1)))
		Expect(collected.stats.Percent).To(Equal(float64(100)))

		// The report trivy wrote is retained beside the findings, so the run can
		// be re-read without recon.
		Expect(filepath.Join(workDir, ReportFile("checkout"))).To(BeAnExistingFile())

		body, err := os.ReadFile(run.Out)
		Expect(err).ToNot(HaveOccurred())
		var written api.Finding
		Expect(json.Unmarshal([]byte(strings.TrimSpace(string(body))), &written)).To(Succeed())
		Expect(written.TemplateID).To(Equal("github-pat"))
	}, SpecTimeout(3*time.Minute))

	It("fails loudly when trivy cannot read the target", func(ctx SpecContext) {
		bin := installedTrivy()

		workDir := GinkgoT().TempDir()
		engine, err := newEngine()
		Expect(err).ToNot(HaveOccurred())

		err = engine.Run(ctx, engines.Run{
			Bin: bin, WorkDir: workDir,
			Config: map[string]any{
				"provider": ProviderFilesystem, "scanners": []any{"secret"}, "offline-scan": true,
			},
			Out: filepath.Join(workDir, "findings.jsonl"),
			ProviderContexts: []engines.ProviderContext{{
				ID: "missing", Provider: ProviderFilesystem, CredentialMode: api.CredentialAmbient,
				Arguments: map[string]any{"path": filepath.Join(workDir, "does-not-exist")},
			}},
		}, &sink{})

		Expect(err).To(MatchError(ContainSubstring("missing")))
	}, SpecTimeout(3*time.Minute))
})

var _ = Describe("recording what a run amounted to", func() {
	It("renders the command someone could re-run by hand", func() {
		engine, err := newEngine()
		Expect(err).ToNot(HaveOccurred())

		command := engine.Command(engines.Run{
			Bin:     "/usr/local/bin/trivy",
			WorkDir: "/results/trivy-run",
			Config: map[string]any{
				"provider": ProviderImage, "scanners": []any{"vuln"}, "ignore-unfixed": true,
			},
			ProviderContexts: []engines.ProviderContext{
				imageContext("api-image", "ghcr.io/acme/api:1.4"),
			},
		})

		Expect(command).To(Equal([]string{
			"/usr/local/bin/trivy", "image",
			"--ignore-unfixed", "--scanners", "vuln",
			"--format", "json", "--no-progress",
			"--output", "/results/trivy-run/trivy-api-image.json",
			"ghcr.io/acme/api:1.4",
		}))
	})

	It("says so rather than rendering a command that would not run", func() {
		engine, err := newEngine()
		Expect(err).ToNot(HaveOccurred())

		command := engine.Command(engines.Run{Bin: "trivy", Config: map[string]any{}})
		Expect(command).To(Equal([]string{"trivy", "<invalid trivy command>"}))
	})
})

var _ = Describe("cancelling a run", func() {
	It("stops before starting a context the caller no longer wants", func() {
		engine, err := newEngine()
		Expect(err).ToNot(HaveOccurred())

		cancelled, cancel := context.WithCancel(context.Background())
		cancel()

		workDir := GinkgoT().TempDir()
		err = engine.Run(cancelled, engines.Run{
			Bin: "trivy", WorkDir: workDir,
			Config: map[string]any{"provider": ProviderImage, "scanners": []any{"vuln"}},
			Out:    filepath.Join(workDir, "findings.jsonl"),
			ProviderContexts: []engines.ProviderContext{
				imageContext("api-image", "ghcr.io/acme/api:1.4"),
			},
		}, &sink{})

		Expect(err).To(MatchError(context.Canceled))
	})
})
