package cli_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/flanksource/clicky/rpc"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/cli"
)

func TestCLI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "cli")
}

var _ = Describe("execution resources", func() {
	It("runs scan and discovery at the root while retaining list history", func() {
		root := cli.New()
		for _, name := range []string{"scan", "discover"} {
			command, _, err := root.Find([]string{name})
			Expect(err).ToNot(HaveOccurred())
			Expect(command.RunE).ToNot(BeNil(), name)
			var children []string
			for _, child := range command.Commands() {
				children = append(children, child.Name())
			}
			Expect(children).To(ContainElement("list"), name)
			for _, flag := range []string{"selector", "host", "domain", "cidr", "profile"} {
				Expect(command.Flag(flag)).ToNot(BeNil(), "%s --%s", name, flag)
			}
		}

		scan, _, err := root.Find([]string{"scan"})
		Expect(err).ToNot(HaveOccurred())
		Expect(scan.Flag("discovery-profile")).ToNot(BeNil())

		// A probe refreshes liveness without a discovery engine. It is served over
		// HTTP as well as on the CLI — the UI's ping button is this operation —
		// which is safe only because it takes a selector rather than a URL.
		probe, _, err := root.Find([]string{"probe"})
		Expect(err).ToNot(HaveOccurred())
		Expect(probe.RunE).ToNot(BeNil())
		for _, flag := range []string{"host", "class", "selector", "timeout", "concurrency"} {
			Expect(probe.Flag(flag)).ToNot(BeNil(), "probe --%s", flag)
		}

		// --dev swaps the embedded build for a Vite dev server, which is the only
		// way a source change shows up without recompiling the binary.
		serve, _, err := root.Find([]string{"serve"})
		Expect(err).ToNot(HaveOccurred())
		Expect(serve.Flag("dev")).ToNot(BeNil())
		Expect(serve.Flag("dev").DefValue).To(Equal("false"))

		target, _, err := root.Find([]string{"target"})
		Expect(err).ToNot(HaveOccurred())
		for _, command := range target.Commands() {
			Expect(command.Name()).ToNot(BeElementOf("scan", "discover"))
		}

		service, err := rpc.NewConverter(rpc.DefaultConfig()).ConvertCommandTree(root)
		Expect(err).ToNot(HaveOccurred())
		for _, resource := range []string{"scan", "discover"} {
			var methods []string
			for _, operation := range service.Operations {
				if operation.Path == "/api/v1/"+resource {
					methods = append(methods, operation.Method)
				}
				Expect(operation.Path).ToNot(Equal("/api/v1/target/" + resource))
			}
			Expect(methods).To(ConsistOf(http.MethodGet, http.MethodPost), resource)
		}
	})

	It("offers a custom run the same choices on the CLI and over HTTP", func() {
		// A custom run chooses which engines sweep and scan, and configures
		// them for that run only. Both halves have to reach the API: the dialog
		// builds its request from these parameters, so one the command accepts
		// but the RPC surface drops is a control the UI cannot offer.
		choices := map[string][]string{
			"scan":     {"engine", "profile", "override", "discovery-engine", "discovery-profile", "discovery-override"},
			"discover": {"engine", "profile", "override"},
			// --wait is load-bearing over HTTP, not a convenience: the dialog sends
			// wait=false and follows the run by id, because a sweep of the estate
			// outlasts any sensible request timeout.
			"probe": {"host", "class", "selector", "timeout", "concurrency", "follow-redirects", "wait"},
		}

		root := cli.New()
		service, err := rpc.NewConverter(rpc.DefaultConfig()).ConvertCommandTree(root)
		Expect(err).ToNot(HaveOccurred())

		for resource, expected := range choices {
			command, _, err := root.Find([]string{resource})
			Expect(err).ToNot(HaveOccurred())
			for _, choice := range expected {
				Expect(command.Flag(choice)).ToNot(BeNil(), "%s --%s", resource, choice)
			}

			declared := map[string]bool{}
			for _, operation := range service.Operations {
				if operation.Path != "/api/v1/"+resource || operation.Method != http.MethodPost {
					continue
				}
				for _, parameter := range operation.Parameters {
					declared[parameter.Name] = true
				}
			}
			for _, choice := range expected {
				Expect(declared).To(HaveKey(choice), "POST /api/v1/%s drops %s", resource, choice)
			}
		}
	})

	It("serves scans serially unless scan concurrency is configured", func() {
		root := cli.New()
		serve, _, err := root.Find([]string{"serve"})
		Expect(err).ToNot(HaveOccurred())

		flag := serve.Flag("scan-concurrency")
		Expect(flag).ToNot(BeNil())
		Expect(flag.DefValue).To(Equal("1"))
	})

	It("rejects an invalid scan concurrency before opening the database", func() {
		root := cli.New()
		root.SetArgs([]string{"serve", "--scan-concurrency=0"})
		Expect(root.ExecuteContext(context.Background())).To(MatchError(
			"scan concurrency must be at least 1, got 0",
		))
	})
})
