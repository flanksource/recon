package entities

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	_ "github.com/flanksource/recon/internal/engines/all" // populate the registry
)

var _ = Describe("listing the engines a run can choose from", func() {
	discoveryEngines := func() map[string]api.EngineSpec {
		specs, err := (&Registry{}).listEngines(context.Background(), EngineOpts{Kind: []string{"discovery"}})
		Expect(err).ToNot(HaveOccurred())

		byName := map[string]api.EngineSpec{}
		for _, spec := range specs {
			byName[spec.Name] = spec
		}
		return byName
	}

	// The picker opens on this, so it has to be the set the server actually
	// runs — a second list in the UI would show engines a sweep never drives.
	It("marks the engines a sweep runs when the caller chooses none", func() {
		engines := discoveryEngines()

		on := []string{}
		for name, spec := range engines {
			if spec.Default {
				on = append(on, name)
			}
		}
		Expect(on).To(ConsistOf("subfinder", "naabu", "httpx", "tlsx"))

		// Registered, reachable, and off until someone asks for them.
		Expect(engines).To(HaveKey("katana"))
		Expect(engines).To(HaveKey("dnsx"))
		Expect(engines["katana"].Default).To(BeFalse())
		Expect(engines["dnsx"].Default).To(BeFalse())
	})

	It("reports where each engine sits in a sweep, so a selection can be ordered", func() {
		engines := discoveryEngines()
		Expect(engines["subfinder"].Accepts).To(Equal("zones"))
		Expect(engines["subfinder"].Emits).To(Equal("hosts"))
		Expect(engines["katana"].Accepts).To(Equal("origins"))
		Expect(engines["katana"].Emits).To(Equal("endpoints"))
	})
})
