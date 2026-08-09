package scan_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/scan"
)

// The snapshot is what the browser renders off the event stream, so its shape
// is a contract. Two ways it has already broken silently: an embedded type's
// MarshalJSON being promoted and swallowing the outer fields, and Go emitting
// null where the frontend indexes a collection.
var _ = Describe("the status snapshot", func() {
	encode := func(status scan.Status) map[string]any {
		encoded, err := json.Marshal(status)
		Expect(err).ToNot(HaveOccurred())

		var fields map[string]any
		Expect(json.Unmarshal(encoded, &fields)).To(Succeed())
		return fields
	}

	It("carries the output fields alongside the scan", func() {
		// api.Scan has its own MarshalJSON. Embedding it promotes that method
		// onto Status, so without an override the log, the output and the
		// running flag disappear from every frame with no error raised.
		fields := encode(scan.Status{
			Scan:    api.Scan{Name: "nuclei-safe-1", Phase: api.PhaseRunning},
			Log:     "[INF] started",
			Events:  []scan.OutputEvent{{Sequence: 1, Stream: scan.StreamStdout, Text: "hi"}},
			Running: true,
		})

		Expect(fields).To(HaveKeyWithValue("name", "nuclei-safe-1"))
		Expect(fields).To(HaveKeyWithValue("phase", "running"))
		Expect(fields).To(HaveKeyWithValue("log", "[INF] started"))
		Expect(fields).To(HaveKeyWithValue("running", true))
		Expect(fields["output"]).To(HaveLen(1))
	})

	It("emits empty collections rather than null", func() {
		// The frontend maps over hosts and indexes severities without checking,
		// so a null is a runtime error there rather than an empty list.
		fields := encode(scan.Status{Scan: api.Scan{Phase: api.PhaseIdle}})

		Expect(fields).To(HaveKeyWithValue("hosts", BeEmpty()))
		Expect(fields).To(HaveKeyWithValue("selector", BeEmpty()))
		Expect(fields).To(HaveKeyWithValue("output", BeEmpty()))
		for _, key := range []string{"hosts", "selector", "output", "severities"} {
			Expect(fields[key]).ToNot(BeNil(), "%s must not be null", key)
		}
	})

	It("reports every severity even when nothing was found", func() {
		fields := encode(scan.Status{Scan: api.Scan{Phase: api.PhaseDone}})

		severities, ok := fields["severities"].(map[string]any)
		Expect(ok).To(BeTrue())
		for _, severity := range api.Severities() {
			Expect(severities).To(HaveKeyWithValue(string(severity), BeNumerically("==", 0)))
		}
	})

	It("uses the vocabulary the browser and the schema already agree on", func() {
		// Not clicky's task vocabulary: the frontend switches on these strings
		// and the scans table has a check constraint listing them.
		Expect(api.Phases()).To(Equal([]api.Phase{
			"idle", "running", "done", "failed", "cancelled",
		}))
		Expect(api.PhaseRunning.Terminal()).To(BeFalse())
		Expect(api.PhaseIdle.Terminal()).To(BeFalse())
		for _, phase := range []api.Phase{api.PhaseDone, api.PhaseFailed, api.PhaseCancelled} {
			Expect(phase.Terminal()).To(BeTrue(), string(phase))
		}
	})
})
