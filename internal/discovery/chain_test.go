package discovery_test

import (
	"context"
	"fmt"
	"io"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/discovery"
	"github.com/flanksource/recon/internal/engines"
	_ "github.com/flanksource/recon/internal/engines/all" // populate the registry
	enginediscovery "github.com/flanksource/recon/internal/engines/discovery"
)

// fakeEngine stands in for a real tool: it declares where it sits in a chain
// and runs /bin/sh, so the specs exercise the actual spawn, pipe and parse path
// without needing seven binaries installed.
type fakeEngine struct {
	name     string
	accepts  enginediscovery.Kind
	emits    enginediscovery.Kind
	script   string
	captured *string
}

func (f fakeEngine) Spec() engines.Spec {
	return engines.Spec{Name: f.name, Binary: "sh", Title: f.name}
}

func (f fakeEngine) Accepts() enginediscovery.Kind { return f.accepts }
func (f fakeEngine) Emits() enginediscovery.Kind   { return f.emits }

// Args substitutes the rendered input list into the script, because a real
// engine is given a file with -list rather than being fed on stdin.
func (f fakeEngine) Args(run engines.Run) []string {
	if f.captured != nil {
		*f.captured = run.In
	}
	return []string{"-c", strings.ReplaceAll(f.script, "{{in}}", run.In)}
}

func (f fakeEngine) Parse(r io.Reader, emit func(enginediscovery.Record) error) error {
	return engines.ScanLines(r, func(line string) error {
		host := strings.TrimSpace(line)
		if host == "" {
			return nil
		}
		return emit(enginediscovery.Record{
			Host: host, Fields: map[string]any{"input": host, "source": f.name},
		})
	})
}

// newProvisioner resolves every fake engine to /bin/sh: the real provisioner
// falls back to PATH, and the fakes declare `sh` as their binary.
func newProvisioner() *engines.Provisioner {
	return engines.NewProvisioner(GinkgoT().TempDir())
}

var _ = Describe("composing a discovery chain", func() {
	It("rejects a chain whose stages do not fit together", func() {
		// A chain that produces nothing while reporting success is the worst way
		// for discovery to fail: it looks like an estate with no hosts in it.
		chain := discovery.Chain{Name: "broken", Engines: []enginediscovery.Engine{
			fakeEngine{name: "b", accepts: enginediscovery.Endpoints, emits: enginediscovery.Observations},
		}}
		Expect(chain.Validate()).To(MatchError(ContainSubstring(
			"consumes endpoints, which no earlier stage produces")))
	})

	It("accepts a stage fed by the runtime rather than an engine", func() {
		// Zones are configured and origins come from the inventory, so neither
		// needs a preceding stage.
		chain := discovery.Chain{Name: "seeded", Engines: []enginediscovery.Engine{
			fakeEngine{name: "a", accepts: enginediscovery.Zones, emits: enginediscovery.Hosts},
		}}
		Expect(chain.Validate()).To(Succeed())
	})

	It("rejects an empty chain", func() {
		Expect(discovery.Chain{Name: "empty"}.Validate()).
			To(MatchError(ContainSubstring("no stages")))
	})

	It("builds the real full chain from the registry", func() {
		chain, err := discovery.NewChain("full", "subfinder", "naabu", "httpx", "tlsx")
		Expect(err).ToNot(HaveOccurred())
		Expect(chain.Engines).To(HaveLen(4))
	})

	It("refuses to build a chain naming an engine that does not exist", func() {
		_, err := discovery.NewChain("bogus", "nmap")
		Expect(err).To(MatchError(ContainSubstring("unknown discovery engine: nmap")))
	})
})

var _ = Describe("running a discovery chain", func() {
	ctx := context.Background()

	run := func(chain discovery.Chain, input []string) ([]discovery.Stage, error) {
		return chain.Run(ctx, discovery.RunOptions{
			Root:        GinkgoT().TempDir(),
			Provisioner: newProvisioner(),
			Input:       input,
			ID:          "test",
		})
	}

	It("feeds each stage what the previous one emitted", func() {
		var secondInput string
		chain := discovery.Chain{Name: "two", Engines: []enginediscovery.Engine{
			fakeEngine{
				name: "first", accepts: enginediscovery.Zones, emits: enginediscovery.Hosts,
				script: "echo a.example.test; echo b.example.test",
			},
			fakeEngine{
				name: "second", accepts: enginediscovery.Hosts, emits: enginediscovery.Endpoints,
				script: "sed 's/^/port-/' {{in}}", captured: &secondInput,
			},
		}}

		stages, err := run(chain, []string{"example.test"})
		Expect(err).ToNot(HaveOccurred())
		Expect(stages).To(HaveLen(2))

		Expect(stages[0].Hosts).To(Equal([]string{"a.example.test", "b.example.test"}))
		Expect(stages[1].Hosts).To(Equal([]string{"port-a.example.test", "port-b.example.test"}))
		Expect(secondInput).ToNot(BeEmpty(), "the second stage was given an input list")
	})

	It("does not let an observing stage narrow what the next one sees", func() {
		// httpx and tlsx describe hosts that are already known; they do not
		// extend the host list, so a later stage must still see the full set.
		var lastInput string
		chain := discovery.Chain{Name: "observe", Engines: []enginediscovery.Engine{
			fakeEngine{
				name: "finder", accepts: enginediscovery.Zones, emits: enginediscovery.Hosts,
				script: "echo a.example.test; echo b.example.test",
			},
			fakeEngine{
				name: "prober", accepts: enginediscovery.Hosts, emits: enginediscovery.Observations,
				script: "head -1 {{in}}",
			},
			fakeEngine{
				name: "later", accepts: enginediscovery.Hosts, emits: enginediscovery.Observations,
				script: "cat {{in}}", captured: &lastInput,
			},
		}}

		stages, err := run(chain, []string{"example.test"})
		Expect(err).ToNot(HaveOccurred())
		Expect(stages[2].Hosts).To(Equal([]string{"a.example.test", "b.example.test"}),
			"the observing stage in the middle must not have narrowed the input")
	})

	It("treats exit code 3 as success, because it means differences were found", func() {
		chain := discovery.Chain{Name: "drift", Engines: []enginediscovery.Engine{
			fakeEngine{
				name: "drifty", accepts: enginediscovery.Zones, emits: enginediscovery.Hosts,
				script: "echo a.example.test; exit 3",
			},
		}}

		stages, err := run(chain, []string{"example.test"})
		Expect(err).ToNot(HaveOccurred())
		Expect(stages[0].ExitCode).To(Equal(3))
		Expect(stages[0].Hosts).To(Equal([]string{"a.example.test"}))
	})

	It("fails the chain when a stage exits badly", func() {
		chain := discovery.Chain{Name: "broken", Engines: []enginediscovery.Engine{
			fakeEngine{
				name: "failing", accepts: enginediscovery.Zones, emits: enginediscovery.Hosts,
				script: "exit 1",
			},
		}}

		_, err := run(chain, []string{"example.test"})
		Expect(err).To(MatchError(ContainSubstring("exited 1")))
	})

	It("stops feeding stages once one finds nothing, without calling it an error", func() {
		chain := discovery.Chain{Name: "empty", Engines: []enginediscovery.Engine{
			fakeEngine{
				name: "quiet", accepts: enginediscovery.Zones, emits: enginediscovery.Hosts,
				script: "true",
			},
			fakeEngine{
				name: "next", accepts: enginediscovery.Hosts, emits: enginediscovery.Endpoints,
				script: "echo should-not-run.example.test",
			},
		}}

		stages, err := run(chain, []string{"example.test"})
		Expect(err).ToNot(HaveOccurred())
		Expect(stages).To(HaveLen(2))
		Expect(stages[1].Hosts).To(BeEmpty(), "the second stage must not have run")
	})

	It("refuses to run with nothing to start from", func() {
		chain := discovery.Chain{Name: "seedless", Engines: []enginediscovery.Engine{
			fakeEngine{name: "a", accepts: enginediscovery.Zones, emits: enginediscovery.Hosts},
		}}
		_, err := run(chain, nil)
		Expect(err).To(MatchError(ContainSubstring("nothing to start from")))
	})

	It("refuses to run without a provisioner rather than resolving nothing", func() {
		chain := discovery.Chain{Name: "unprovisioned", Engines: []enginediscovery.Engine{
			fakeEngine{name: "a", accepts: enginediscovery.Zones, emits: enginediscovery.Hosts},
		}}
		_, err := chain.Run(ctx, discovery.RunOptions{Input: []string{"example.test"}})
		Expect(err).To(MatchError(ContainSubstring("no provisioner")))
	})

	It("stops the chain when a profile cannot be resolved", func() {
		// Running an engine with no configuration would silently use its own
		// defaults instead of the ones on record.
		chain := discovery.Chain{Name: "unconfigured", Engines: []enginediscovery.Engine{
			fakeEngine{name: "a", accepts: enginediscovery.Zones, emits: enginediscovery.Hosts, script: "true"},
		}}

		_, err := chain.Run(ctx, discovery.RunOptions{
			Root:        GinkgoT().TempDir(),
			Provisioner: newProvisioner(),
			Input:       []string{"example.test"},
			Profiles: func(string) (map[string]any, error) {
				return nil, fmt.Errorf("no profile stored")
			},
		})
		Expect(err).To(MatchError(ContainSubstring("no profile stored")))
	})
})
