package scan

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/ocsf"
)

// stubEngine runs whatever the spec gives it, so a session can be driven through
// each of its endings without a template corpus or a network.
type stubEngine struct {
	run func(context.Context, enginescan.Sink) error
}

func (stubEngine) Spec() engines.Spec               { return engines.Spec{Name: "stub"} }
func (stubEngine) Risk(map[string]any) engines.Risk { return engines.Risk{} }
func (e stubEngine) Run(ctx context.Context, _ engines.Run, sink enginescan.Sink) error {
	return e.run(ctx, sink)
}

// reported is what an adapter hands the sink: a Detection Finding carrying the
// attributes OCSF requires of every one, and nothing else. Declaring no profile
// is what a probe of a URL honestly does — it has no cloud account to name.
func reported(checkID string) api.Finding {
	return api.Finding{
		DetectionFinding: ocsf.DetectionFinding{
			ClassUID:    ocsf.ClassUID,
			CategoryUID: ocsf.CategoryUID,
			ActivityID:  ocsf.ActivityIDCreate,
			TypeUID:     ocsf.TypeUID(ocsf.ActivityIDCreate),
			SeverityID:  ocsf.SeverityIDHigh,
			Time:        1786000000000,
			FindingInfo: &ocsf.FindingInfo{UID: checkID, Title: checkID},
			Metadata: &ocsf.Metadata{
				Version: ocsf.Version,
				Product: &ocsf.Product{Name: "stub", VendorName: api.Vendor},
			},
		},
		Engine:  "stub",
		CheckID: checkID,
	}
}

var _ = Describe("a scan session", func() {
	var current *session

	BeforeEach(func() {
		current = newSession(NewOutput(), "nuclei", []string{"nuclei"})
	})

	It("reports a run that finished as neither cancelled nor failed", func() {
		Expect(current.Run(context.Background(), stubEngine{
			run: func(context.Context, enginescan.Sink) error { return nil },
		}, engines.Run{})).To(Succeed())

		Expect(current.Cancelled()).To(BeFalse())
	})

	It("does not call a failed run cancelled", func() {
		failure := errors.New("nuclei scan: templates are not installed")
		Expect(current.Run(context.Background(), stubEngine{
			run: func(context.Context, enginescan.Sink) error { return failure },
		}, engines.Run{})).To(MatchError(failure))

		Expect(current.Cancelled()).To(BeFalse())
	})

	// The session derives its own context so that cancelling one run cannot stop
	// the caller's other work. That means the caller's context stays clean, and a
	// supervisor that reads it instead of asking the session records every
	// cancelled scan as failed.
	It("reports a cancelled run as cancelled, leaving the caller's context clean", func() {
		caller := context.Background()
		started := make(chan struct{})

		done := make(chan error, 1)
		go func() {
			done <- current.Run(caller, stubEngine{
				run: func(ctx context.Context, _ enginescan.Sink) error {
					close(started)
					<-ctx.Done()
					return ctx.Err()
				},
			}, engines.Run{})
		}()

		<-started
		Expect(current.Cancel()).To(Succeed())

		Eventually(done).Should(Receive(MatchError(context.Canceled)))
		Expect(current.Cancelled()).To(BeTrue())
		Expect(caller.Err()).To(BeNil())
	})

	It("is safe to cancel before a run starts and after it ends", func() {
		Expect(current.Cancel()).To(Succeed())
		Expect(current.Run(context.Background(), stubEngine{
			run: func(context.Context, enginescan.Sink) error { return nil },
		}, engines.Run{})).To(Succeed())
		Expect(current.Cancel()).To(Succeed())
	})

	It("keeps every finding the engine reported, in order", func() {
		Expect(current.Run(context.Background(), stubEngine{
			run: func(_ context.Context, sink enginescan.Sink) error {
				Expect(sink.Finding(reported("tls-version"))).To(Succeed())
				Expect(sink.Finding(reported("cookie-flags"))).To(Succeed())
				return nil
			},
		}, engines.Run{})).To(Succeed())

		Expect(current.Findings()).To(HaveLen(2))
		Expect(current.Findings()[0].CheckID).To(Equal("tls-version"))
		Expect(current.Findings()[1].CheckID).To(Equal("cookie-flags"))
	})

	// The sink is where every engine's output converges, so it is where a record
	// that is not a valid OCSF finding has to be stopped: storing a half-record
	// means a consumer reading `finding_info.title` gets nothing and cannot tell
	// that from a finding that genuinely has no title.
	It("refuses a finding that is not a valid OCSF record", func() {
		err := current.Run(context.Background(), stubEngine{
			run: func(_ context.Context, sink enginescan.Sink) error {
				incomplete := reported("tls-version")
				incomplete.FindingInfo = nil
				return sink.Finding(incomplete)
			},
		}, engines.Run{})
		Expect(err).To(MatchError(ContainSubstring("finding_info is required")))
		Expect(current.Findings()).To(BeEmpty())
	})

	It("fills the readable half of each enum pair from the integer", func() {
		Expect(current.Run(context.Background(), stubEngine{
			run: func(_ context.Context, sink enginescan.Sink) error {
				return sink.Finding(reported("tls-version"))
			},
		}, engines.Run{})).To(Succeed())

		// OCSF's caption of severity_id 4, which no adapter writes out.
		Expect(current.Findings()[0].Severity).To(Equal("High"))
		Expect(current.Findings()[0].ActivityName).To(Equal("Create"))
	})
})
