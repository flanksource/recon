package trivy

import (
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/mute"
)

var _ = Describe("pushing mute rules into trivy", func() {
	var workDir string

	BeforeEach(func() { workDir = GinkgoT().TempDir() })

	push := func(rules ...api.MuteRule) scan.Pushdown {
		GinkgoHelper()
		prepared := make([]mute.Rule, 0, len(rules))
		for _, rule := range rules {
			prepared = append(prepared, mute.Rule{MuteRule: rule})
		}
		result, err := Engine{}.Pushdown(scan.PushdownRequest{
			Config: map[string]any{}, WorkDir: workDir, Rules: prepared,
		})
		Expect(err).ToNot(HaveOccurred())
		return result
	}

	It("writes the checks it was given into an ignore file trivy accepts", func() {
		result := push(api.MuteRule{Name: "accepted", Templates: api.StringList{"CVE-2023-0001"}})

		Expect(result.Plan.PushedDown).To(HaveKeyWithValue("accepted", "ignorefile"))
		Expect(result.File).To(Equal(filepath.Join(workDir, IgnoreFile)))

		written, err := os.ReadFile(result.File)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(written)).To(ContainSubstring("CVE-2023-0001"))
		// Trivy's plain format is one id per line; anything else is a comment.
		for _, line := range strings.Split(strings.TrimSpace(string(written)), "\n") {
			Expect(strings.HasPrefix(line, "#") || line == "CVE-2023-0001").To(BeTrue(), line)
		}
	})

	It("collects the checks of every rule into one file", func() {
		result := push(
			api.MuteRule{Name: "a", Templates: api.StringList{"CVE-2023-0002"}},
			api.MuteRule{Name: "b", Templates: api.StringList{"CVE-2023-0001"}})

		written, err := os.ReadFile(result.File)
		Expect(err).ToNot(HaveOccurred())
		// Sorted, so re-running the same configuration writes the same file.
		Expect(string(written)).To(ContainSubstring("CVE-2023-0001\nCVE-2023-0002"))
		Expect(result.Plan.PushedDown).To(HaveLen(2))
	})

	It("writes no file when it can express nothing", func() {
		result := push(api.MuteRule{Name: "expr", Expr: `finding.host == "x"`})

		Expect(result.Plan.PushedDown).To(BeEmpty())
		Expect(result.File).To(BeEmpty())
		Expect(filepath.Join(workDir, IgnoreFile)).ToNot(BeAnExistingFile())
	})

	// Trivy ignores by exact id, and a recon-composed id such as license/GPL-3.0
	// is not what trivy calls the thing.
	It("leaves a glob or a composed id to be applied to the results", func() {
		Expect(push(api.MuteRule{Name: "g", Templates: api.StringList{"CVE-2023-*"}}).
			Plan.PushedDown).To(BeEmpty())
		Expect(push(api.MuteRule{Name: "l", Templates: api.StringList{"license/GPL-3.0"}}).
			Plan.PushedDown).To(BeEmpty())
	})

	It("hands the file to the runner rather than to the profile", func() {
		entry, err := find(ProviderImage)
		Expect(err).ToNot(HaveOccurred())

		argv, err := entry.argv(map[string]any{}, map[string]any{"image": "example:latest"},
			runnerOptions{Report: "/results/report.json", IgnoreFile: "/work/.trivyignore"})
		Expect(err).ToNot(HaveOccurred())

		command := strings.Join(argv, " ")
		Expect(command).To(ContainSubstring("--ignorefile /work/.trivyignore"))
	})

	// Command is what the UI shows and what someone reproduces by hand, so it
	// has to name the ignore file the run actually used.
	It("names the ignore file in the equivalent command line", func() {
		engine, err := newEngine()
		Expect(err).ToNot(HaveOccurred())

		command := strings.Join(engine.Command(engines.Run{
			Bin:     "trivy",
			WorkDir: workDir,
			Mutes:   "/work/.trivyignore",
			Config: map[string]any{
				"provider": ProviderImage, "scanners": []any{"vuln"},
			},
			ProviderContexts: []engines.ProviderContext{
				imageContext("api-image", "ghcr.io/acme/api:1.4"),
			},
		}), " ")

		Expect(command).To(ContainSubstring("--ignorefile /work/.trivyignore"))
	})
})
