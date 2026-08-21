package prowler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	dbcontext "github.com/flanksource/commons-db/context"
	"github.com/flanksource/commons-db/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	credentialstore "github.com/flanksource/recon/internal/credentials"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
	prowlerschema "github.com/flanksource/recon/internal/engines/scan/prowler/schema"
)

type recordingSink struct {
	findings []api.Finding
	stats    api.ScanStats
	logs     []string
}

func (s *recordingSink) Finding(finding api.Finding) error {
	s.findings = append(s.findings, finding)
	return nil
}
func (s *recordingSink) Stats(stats api.ScanStats) { s.stats = stats }
func (s *recordingSink) Log(line string)           { s.logs = append(s.logs, line) }

var _ = Describe("a Prowler run", func() {
	var (
		workDir string
		run     engines.Run
		sink    *recordingSink
		engine  Engine
		argsLog string
	)

	BeforeEach(func() {
		workDir = GinkgoT().TempDir()
		binary := filepath.Join(workDir, "prowler")
		source, err := os.ReadFile(filepath.Join("testdata", "fake-prowler.sh"))
		Expect(err).ToNot(HaveOccurred())
		Expect(os.WriteFile(binary, source, 0o755)).To(Succeed())
		argsLog = filepath.Join(workDir, "argv.log")
		report, err := os.ReadFile(filepath.Join("testdata", "findings.ocsf.json"))
		Expect(err).ToNot(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(workDir, "findings.ocsf.json"), report, 0o600)).To(Succeed())

		contexts := []providerContext{
			{ID: "gcp-prod", Provider: "gcp", CredentialMode: api.CredentialAmbient,
				Arguments: map[string]any{"project-ids": []any{"example-prod"}}},
			{ID: "gcp-dev", Provider: "gcp", CredentialMode: api.CredentialAmbient,
				Arguments: map[string]any{"project-ids": []any{"example-dev"}}},
		}
		input := filepath.Join(workDir, "targets.jsonl")
		file, err := os.Create(input)
		Expect(err).ToNot(HaveOccurred())
		encoder := json.NewEncoder(file)
		for _, subject := range contexts {
			Expect(encoder.Encode(subject)).To(Succeed())
		}
		Expect(file.Close()).To(Succeed())

		catalogue := testArgumentCatalogue()
		options, err := prowlerschema.OptionCatalog()
		Expect(err).ToNot(HaveOccurred())
		engine = Engine{arguments: &catalogue, spec: engines.Spec{Options: options}}
		run = engines.Run{
			Context: dbcontext.NewContext(context.Background()),
			Bin:     binary, WorkDir: workDir, In: input,
			Out: filepath.Join(workDir, "findings.jsonl"),
			ProviderContexts: []engines.ProviderContext{
				{ID: "gcp-prod", Provider: "gcp", CredentialMode: api.CredentialAmbient,
					Arguments: map[string]any{"project-ids": []any{"example-prod"}}, Class: api.ClassProd},
				{ID: "gcp-dev", Provider: "gcp", CredentialMode: api.CredentialAmbient,
					Arguments: map[string]any{"project-ids": []any{"example-dev"}}, Class: api.ClassNonProd},
			},
			Config: map[string]any{
				"provider": "gcp", "compliance": []any{"cis_5.0_gcp"},
				"skip-api-check": true, "verbose": true, "log-level": "DEBUG",
				"output-formats": []any{"csv", "json-ocsf", "html"},
			},
		}
		sink = &recordingSink{}
	})

	It("runs one deterministic invocation per context and retains nested outputs", func() {
		Expect(engine.Run(context.Background(), run, sink)).To(Succeed())

		body, err := os.ReadFile(argsLog)
		Expect(err).ToNot(HaveOccurred())
		Expect(strings.Split(strings.TrimSpace(string(body)), "\n")).To(Equal([]string{
			"__invocation__", "gcp", "--project-ids", "example-prod", "--skip-api-check",
			"--output-formats", "csv", "json-ocsf", "html", "--output-directory", "output",
			"--verbose", "--no-banner", "--no-color", "--log-level", "DEBUG", "--compliance", "cis_5.0_gcp",
			"__invocation__", "gcp", "--project-ids", "example-dev", "--skip-api-check",
			"--output-formats", "csv", "json-ocsf", "html", "--output-directory", "output",
			"--verbose", "--no-banner", "--no-color", "--log-level", "DEBUG", "--compliance", "cis_5.0_gcp",
		}))
		for _, contextDir := range []string{"0001", "0002"} {
			for _, name := range []string{"report.ocsf.json", "report.csv", "report.html"} {
				Expect(filepath.Join(workDir, "contexts", contextDir, "output", name)).To(BeARegularFile())
			}
		}

		Expect(sink.findings).To(HaveLen(4))
		Expect([]string{sink.findings[0].TargetID, sink.findings[2].TargetID}).
			To(Equal([]string{"gcp-prod", "gcp-dev"}))
		Expect(sink.stats).To(Equal(api.ScanStats{
			Requests: 8, Total: 8, Percent: 100, Matched: 4, Hosts: 2, Templates: 4,
		}))
		output, err := os.ReadFile(run.Out)
		Expect(err).ToNot(HaveOccurred())
		Expect(strings.Count(strings.TrimSpace(string(output)), "\n") + 1).To(Equal(4))
	})

	It("uses typed in-memory subjects instead of the sanitized artifact as execution input", func() {
		run.ProviderContexts = []engines.ProviderContext{{
			ID: "gcp-memory", Provider: "gcp", CredentialMode: api.CredentialAmbient,
			Arguments: map[string]any{"project-ids": []any{"example-memory"}}, Class: api.ClassProd,
		}}

		Expect(engine.Run(context.Background(), run, sink)).To(Succeed())

		body, err := os.ReadFile(argsLog)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(ContainSubstring("example-memory"))
		Expect(string(body)).ToNot(ContainSubstring("example-prod"))
		Expect(string(body)).ToNot(ContainSubstring("example-dev"))
	})

	It("passes only Cloudflare's credential environment in ambient mode", func() {
		for name, value := range map[string]string{
			"CLOUDFLARE_API_TOKEN": "ambient-token", "CLOUDFLARE_API_KEY": "ambient-key",
			"CLOUDFLARE_API_EMAIL": "operator@example.test", "PROWLER_UNRELATED": "must-not-pass",
		} {
			Expect(os.Setenv(name, value)).To(Succeed())
			DeferCleanup(os.Unsetenv, name)
		}
		run.Config["provider"] = "cloudflare"
		delete(run.Config, "skip-api-check")
		run.ProviderContexts = []engines.ProviderContext{{
			ID: "cloudflare-prod", Provider: "cloudflare", CredentialMode: api.CredentialAmbient,
			Arguments: map[string]any{"account-id": "example-account"}, Class: api.ClassProd,
		}}

		Expect(engine.Run(context.Background(), run, sink)).To(Succeed())

		body, err := os.ReadFile(filepath.Join(workDir, "environment.log"))
		Expect(err).ToNot(HaveOccurred())
		Expect(strings.TrimSpace(string(body))).To(Equal(
			"cloudflare-token=set cloudflare-key=set cloudflare-email=set unrelated=unset provider-token=unset"))
	})

	It("isolates configured credentials and redacts them from every recorded surface", func() {
		credentialValue := "runtime-value"
		for name, value := range map[string]string{
			"CLOUDFLARE_API_TOKEN": "ambient-token", "CLOUDFLARE_API_KEY": "ambient-key",
			"CLOUDFLARE_API_EMAIL": "operator@example.test", "PROWLER_UNRELATED": "must-not-pass",
		} {
			Expect(os.Setenv(name, value)).To(Succeed())
			DeferCleanup(os.Unsetenv, name)
		}
		Expect(os.WriteFile(filepath.Join(workDir, "exit-code"), []byte("2\n"), 0o600)).To(Succeed())
		run.Config["provider"] = "cloudflare"
		delete(run.Config, "skip-api-check")
		run.ProviderContexts = []engines.ProviderContext{{
			ID: "cloudflare-configured", Provider: "cloudflare", CredentialMode: api.CredentialConfigured,
			Arguments: map[string]any{"account-id": "example-configured"}, Class: api.ClassProd,
			Credentials: &credentialstore.ProviderCredentials{EnvVars: []types.EnvVar{{
				Name: "CLOUDFLARE_API_TOKEN", ValueStatic: credentialValue,
			}}},
		}}

		err := engine.Run(context.Background(), run, sink)
		Expect(err).To(MatchError(And(ContainSubstring("cloudflare-configured exited 2"), Not(ContainSubstring(credentialValue)))))
		Expect(strings.Join(sink.logs, "\n")).To(And(
			ContainSubstring(arguments.RedactedValue), Not(ContainSubstring(credentialValue))))
		Expect(engine.Command(run)).ToNot(ContainElement(credentialValue))

		environment, readErr := os.ReadFile(filepath.Join(workDir, "environment.log"))
		Expect(readErr).ToNot(HaveOccurred())
		Expect(strings.TrimSpace(string(environment))).To(Equal(
			"cloudflare-token=set cloudflare-key=unset cloudflare-email=unset unrelated=unset provider-token=unset"))
		Expect(filepath.Walk(workDir, func(path string, info os.FileInfo, walkErr error) error {
			Expect(walkErr).ToNot(HaveOccurred())
			if !info.Mode().IsRegular() {
				return nil
			}
			body, fileErr := os.ReadFile(path)
			Expect(fileErr).ToNot(HaveOccurred())
			Expect(string(body)).ToNot(ContainSubstring(credentialValue), path)
			return nil
		})).To(Succeed())
	})

	It("repeats credential mode validation for in-memory subjects", func() {
		run.ProviderContexts[0].CredentialMode = api.CredentialMode("inline")

		err := engine.Run(context.Background(), run, sink)

		Expect(err).To(MatchError(ContainSubstring(`invalid credential mode "inline"`)))
		Expect(argsLog).ToNot(BeAnExistingFile())
	})

	It("requires configured Cloudflare credentials at the execution boundary", func() {
		run.Config["provider"] = "cloudflare"
		delete(run.Config, "skip-api-check")
		run.ProviderContexts = []engines.ProviderContext{{
			ID: "cloudflare-configured", Provider: "cloudflare", CredentialMode: api.CredentialConfigured,
			Arguments: map[string]any{"account-id": "example-configured"}, Class: api.ClassProd,
		}}

		err := engine.Run(context.Background(), run, sink)

		Expect(err).To(MatchError(ContainSubstring("requires an explicit credential selector")))
		Expect(argsLog).ToNot(BeAnExistingFile())
	})

	It("rejects a configured credential name outside the generated provider schema", func() {
		run.Config["provider"] = "cloudflare"
		delete(run.Config, "skip-api-check")
		run.ProviderContexts = []engines.ProviderContext{{
			ID: "cloudflare-configured", Provider: "cloudflare", CredentialMode: api.CredentialConfigured,
			Arguments: map[string]any{"account-id": "example-configured"}, Class: api.ClassProd,
			Credentials: &credentialstore.ProviderCredentials{EnvVars: []types.EnvVar{{
				Name: "PROVIDER_TOKEN", ValueStatic: "runtime-value",
			}}},
		}}

		err := engine.Run(context.Background(), run, sink)

		Expect(err).To(MatchError(ContainSubstring("credential schema")))
		Expect(argsLog).ToNot(BeAnExistingFile())
	})

	It("retains and emits evidence before reporting a provider runtime failure", func() {
		Expect(os.WriteFile(filepath.Join(workDir, "exit-code"), []byte("2\n"), 0o600)).To(Succeed())

		err := engine.Run(context.Background(), run, sink)
		Expect(err).To(MatchError(ContainSubstring("gcp-prod exited 2")))
		Expect(sink.findings).To(HaveLen(2))
		Expect(filepath.Join(workDir, "contexts", "0001", "output", "report.ocsf.json")).To(BeARegularFile())
	})

	DescribeTable("classifies Prowler outcome exit codes",
		func(code int, completed bool) { Expect(ranToCompletion(code)).To(Equal(completed)) },
		Entry("clean", 0, true),
		Entry("findings", 3, true),
		Entry("usage error", 2, false),
		Entry("killed", 137, false),
	)

	It("redacts configured credential paths from commands and chunked logs", func() {
		catalogue := testArgumentCatalogue()
		credentialPath := "/credentials/provider.json"
		raw, safe, err := buildArgv(&catalogue, "gcp", map[string]any{}, providerContext{
			ID: "gcp-prod", Provider: "gcp", CredentialMode: api.CredentialConfigured,
			Arguments: map[string]any{"project-ids": []any{"example-prod"}, "credentials-file": credentialPath},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(raw).To(ContainElement(credentialPath))
		Expect(safe).To(ContainElement(arguments.RedactedValue))
		Expect(safe).ToNot(ContainElement(credentialPath))

		logs := &recordingSink{}
		writer := newRedactingLogWriter(logs, redactedValues(raw, safe))
		_, err = writer.Write([]byte("using /credentials/"))
		Expect(err).ToNot(HaveOccurred())
		_, err = writer.Write([]byte("provider.json\n"))
		Expect(err).ToNot(HaveOccurred())
		writer.Close()
		Expect(logs.logs).To(Equal([]string{"using " + arguments.RedactedValue}))
	})

	It("records only the first context invocation with credential selectors redacted", func() {
		credentialPath := "/credentials/provider.json"
		run.ProviderContexts = []engines.ProviderContext{{
			ID: "gcp-prod", Provider: "gcp", CredentialMode: api.CredentialConfigured,
			Arguments: map[string]any{
				"project-ids": []any{"example-prod"}, "credentials-file": credentialPath,
			},
			Class: api.ClassProd,
		}}

		command := engine.Command(run)

		Expect(command[0]).To(Equal(run.Bin))
		Expect(command).To(ContainElement(arguments.RedactedValue))
		Expect(command).ToNot(ContainElement(credentialPath))
		Expect(strings.Join(command, " ")).To(ContainSubstring("gcp --project-ids example-prod"))
	})
})

func testArgumentCatalogue() arguments.Catalogue {
	argument := func(key, flag string, order int, owner arguments.Owner, action arguments.Action, nargs arguments.NArgs, kind arguments.ValueType) arguments.Argument {
		return arguments.Argument{
			Key: key, Destination: strings.ReplaceAll(key, "-", "_"), Flags: []string{flag}, Canonical: flag,
			Order: order, Action: action, NArgs: nargs, Type: kind, Policy: arguments.Policy{Owner: owner},
		}
	}
	common := []arguments.Argument{
		argument("output-formats", "--output-formats", 0, arguments.OwnerProfile, arguments.ActionStore, arguments.NArgsOneOrMore, arguments.TypeString),
		argument("output-directory", "--output-directory", 1, arguments.OwnerRunner, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString),
		argument("verbose", "--verbose", 2, arguments.OwnerProfile, arguments.ActionStoreTrue, arguments.NArgsNone, arguments.TypeBoolean),
		argument("no-banner", "--no-banner", 3, arguments.OwnerRunner, arguments.ActionStoreTrue, arguments.NArgsNone, arguments.TypeBoolean),
		argument("no-color", "--no-color", 4, arguments.OwnerRunner, arguments.ActionStoreTrue, arguments.NArgsNone, arguments.TypeBoolean),
		argument("log-level", "--log-level", 5, arguments.OwnerProfile, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString),
		argument("compliance", "--compliance", 6, arguments.OwnerProfile, arguments.ActionStore, arguments.NArgsOneOrMore, arguments.TypeString),
	}
	credential := argument("credentials-file", "--credentials-file", 2, arguments.OwnerContext, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString)
	credential.Policy.Redact = true
	credential.Policy.CredentialSelector = true
	return arguments.Catalogue{
		Common: common,
		Providers: []arguments.Provider{
			{Name: "gcp", Arguments: []arguments.Argument{
				argument("project-ids", "--project-ids", 0, arguments.OwnerContext, arguments.ActionStore, arguments.NArgsOneOrMore, arguments.TypeString),
				argument("skip-api-check", "--skip-api-check", 1, arguments.OwnerProfile, arguments.ActionStoreTrue, arguments.NArgsNone, arguments.TypeBoolean),
				credential,
			}},
			{Name: "cloudflare", Arguments: []arguments.Argument{
				argument("account-id", "--account-id", 0, arguments.OwnerContext, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString),
			}},
		},
	}
}
