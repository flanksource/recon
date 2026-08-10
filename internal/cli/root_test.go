package cli_test

import (
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
})
