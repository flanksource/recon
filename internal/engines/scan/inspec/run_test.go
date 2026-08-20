package inspec

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v3"

	"github.com/flanksource/recon/internal/engines"
)

// writeAccounts renders an account list the way the scan runtime does, so the
// engine is driven by the same file it will see in a real run.
func writeAccounts(dir string, accounts ...string) string {
	path, err := engines.WriteList(dir, "targets.txt", accounts)
	Expect(err).ToNot(HaveOccurred())
	return path
}

var _ = Describe("an InSpec run", func() {
	const (
		project      = "example-project"
		otherProject = "example-sandbox"
	)

	var (
		workDir string
		run     engines.Run
	)

	BeforeEach(func() {
		workDir = GinkgoT().TempDir()
		run = engines.Run{
			Bin:     "/opt/cinc-auditor/bin/cinc-auditor",
			WorkDir: workDir,
			In:      writeAccounts(workDir, "gcp://"+project),
			Out:     filepath.Join(workDir, "findings.jsonl"),
			Config: map[string]any{
				"profile":                     GCPCISProfile,
				"sa-key-older-than-seconds":   7776000,
				"kms-rotation-period-seconds": 7776000,
			},
		}
	})

	Describe("reading the account list", func() {
		It("strips the transport scheme the runtime wrote", func() {
			// The rendered list holds gcp:// URIs so it reads as something a
			// person could paste, but the benchmark's input is a bare project id
			// — passing the URI through would audit a project named "gcp://x".
			Expect(readAccounts(run.In)).To(Equal([]string{project}))
		})

		It("accepts a bare project id", func() {
			path := writeAccounts(GinkgoT().TempDir(), project)

			Expect(readAccounts(path)).To(Equal([]string{project}))
		})

		It("reads every account a selector matched", func() {
			path := writeAccounts(GinkgoT().TempDir(), "gcp://"+project, "gcp://"+otherProject)

			Expect(readAccounts(path)).To(Equal([]string{project, otherProject}))
		})

		It("refuses a list with nothing in it", func() {
			// An engine given no input reports no findings, which reads exactly
			// like a clean audit.
			path := filepath.Join(GinkgoT().TempDir(), "targets.txt")
			Expect(os.WriteFile(path, []byte("\n  \n"), 0o644)).To(Succeed())

			_, err := readAccounts(path)

			Expect(err).To(MatchError(ContainSubstring("nothing to audit")))
		})
	})

	Describe("the command line", func() {
		It("targets gcp and reports exec-json to the artifact directory", func() {
			built := args(run.Config, project, filepath.Join(workDir, InputsFile),
				filepath.Join(workDir, ReportFile(project)))

			Expect(built).To(Equal([]string{
				"exec", GCPCISProfile,
				"--target", "gcp://",
				"--input-file", filepath.Join(workDir, InputsFile),
				"--reporter", "json:" + filepath.Join(workDir, ReportFile(project)),
				"--no-color",
				"--chef-license", "accept-silent",
			}))
		})

		It("passes a control filter through when the profile sets one", func() {
			run.Config["controls"] = []any{"cis-gcp-1.4-iam", "cis-gcp-2.2-logging"}

			built := args(run.Config, project, "inputs.yml", "report.json")

			Expect(built).To(ContainElements("--controls", "cis-gcp-1.4-iam", "cis-gcp-2.2-logging"))
		})

		It("omits the control filter when the profile runs the whole benchmark", func() {
			// A bare --controls with no values makes InSpec run nothing.
			Expect(args(run.Config, project, "inputs.yml", "report.json")).
				ToNot(ContainElement("--controls"))
		})

		It("records a reproducible invocation naming the resolved binary", func() {
			Expect(Engine{}.Command(run)).To(HaveLen(len(args(run.Config, project,
				filepath.Join(workDir, InputsFile),
				filepath.Join(workDir, ReportFile(project)))) + 1))
			Expect(Engine{}.Command(run)[0]).To(Equal(run.Bin))
		})
	})

	Describe("the inputs file", func() {
		var inputs map[string]any

		JustBeforeEach(func() {
			path, err := writeInputs(run)
			Expect(err).ToNot(HaveOccurred())

			body, err := os.ReadFile(path)
			Expect(err).ToNot(HaveOccurred())

			// Decoded into a fresh map: yaml.Unmarshal merges into a non-nil
			// one, so reusing the closure's variable would carry the previous
			// spec's keys into this one and make an absent input look present.
			inputs = map[string]any{}
			Expect(yaml.Unmarshal(body, &inputs)).To(Succeed())
		})

		It("renders each option under the input name the benchmark declares", func() {
			// The profile's input names are its contract; recon's option keys
			// are the form's. Passing the option key would set an input the
			// benchmark ignores, silently auditing against its own defaults.
			Expect(inputs).To(Equal(map[string]any{
				"sa_key_older_than_seconds":   7776000,
				"kms_rotation_period_seconds": 7776000,
			}))
		})

		Context("with list-valued inputs", func() {
			BeforeEach(func() {
				run.Config["gce-zones"] = []any{"europe-west1-b", "us-central1-a"}
			})

			It("keeps a list a list", func() {
				// A repeated --input flag would deliver one comma-joined zone
				// name, which matches no zone at all.
				Expect(inputs).To(HaveKeyWithValue("gce_zones",
					[]any{"europe-west1-b", "us-central1-a"}))
			})
		})

		Context("with an empty list", func() {
			BeforeEach(func() { run.Config["gce-zones"] = []any{} })

			It("omits it so the benchmark's own default applies", func() {
				// The GCP profile reads an empty zone list as "search every
				// zone", and writing [] would override its default with a value
				// that means the same thing by accident rather than by intent.
				Expect(inputs).ToNot(HaveKey("gce_zones"))
			})
		})
	})

	Describe("exit codes", func() {
		DescribeTable("distinguishes a benchmark's verdict from a broken run",
			func(code int, completed bool) {
				Expect(ranToCompletion(code)).To(Equal(completed))
			},
			// InSpec reports what it found in the exit code. Treating a control
			// failure as a run failure would mark every non-compliant account as
			// a broken scan and discard its findings.
			Entry("everything passed", 0, true),
			Entry("controls failed", 100, true),
			Entry("controls were skipped", 101, true),
			Entry("usage or runtime error", 1, false),
			Entry("killed", 137, false),
		)
	})

	Describe("credentials", func() {
		It("names the project without handling the credentials themselves", func() {
			// The transport authenticates through Application Default
			// Credentials, which its own SDK locates. Copying a key into the
			// environment would mean recon handling a secret it has no reason to
			// touch.
			env := credentials(project)

			Expect(env).To(Equal(map[string]string{
				"GOOGLE_CLOUD_PROJECT":  project,
				"CLOUDSDK_CORE_PROJECT": project,
			}))
			Expect(env).ToNot(HaveKey("GOOGLE_APPLICATION_CREDENTIALS"))
		})
	})
})

var _ = Describe("the InSpec engine spec", func() {
	var spec engines.Spec

	BeforeEach(func() { spec = Engine{}.Spec() })

	It("scans accounts rather than endpoints", func() {
		Expect(spec.Subject).To(Equal(engines.SubjectAccounts))
	})

	It("is never intrusive", func() {
		// Every control is a read against a provider's management API. If a
		// profile could ever execute against a host, this has to be revisited.
		Expect(Engine{}.Risk(spec.Defaults.Config).Intrusive).To(BeFalse())
	})

	It("seeds a benchmark that validates against its own catalog", func() {
		Expect(spec.Validate()).To(Succeed())
		Expect(spec.Defaults.Config).To(HaveKeyWithValue("profile", GCPCISProfile))
	})

	Describe("profile validation", func() {
		It("requires a profile", func() {
			// There is no default benchmark, so an empty profile would run
			// nothing and report a clean audit.
			Expect(spec.ValidateConfig(map[string]any{"profile": "  "})).
				To(MatchError(ContainSubstring("profile is required")))
		})

		DescribeTable("refuses a profile URL that points at a moving branch",
			func(profile string) {
				// A branch resolves to different controls on different days, so
				// two runs against it are not comparable.
				Expect(spec.ValidateConfig(map[string]any{"profile": profile})).
					To(MatchError(ContainSubstring("pin a tag or commit")))
			},
			Entry("main", "https://github.com/example/benchmark/archive/refs/heads/main.tar.gz"),
			Entry("master", "https://github.com/example/benchmark/archive/master.tar.gz"),
		)

		It("accepts a commit-pinned URL", func() {
			Expect(spec.ValidateConfig(map[string]any{"profile": GCPCISProfile})).To(Succeed())
		})

		It("accepts a local path", func() {
			// A path is how someone runs a benchmark they are still writing.
			Expect(spec.ValidateConfig(map[string]any{"profile": "./inspec/gcp-cis"})).To(Succeed())
		})
	})
})
