package scan

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
)

// stubEngine runs whatever the spec gives it, so a session can be driven through
// each of its endings without a template corpus or a network.
type stubEngine struct {
	run func(context.Context, enginescan.Sink) error
}

func (stubEngine) Spec() engines.Spec                              { return engines.Spec{Name: "stub"} }
func (stubEngine) Risk(map[string]any) engines.Risk                { return engines.Risk{} }
func (e stubEngine) Run(ctx context.Context, _ engines.Run, sink enginescan.Sink) error {
	return e.run(ctx, sink)
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
				Expect(sink.Finding(api.Finding{TemplateID: "tls-version"})).To(Succeed())
				Expect(sink.Finding(api.Finding{TemplateID: "cookie-flags"})).To(Succeed())
				return nil
			},
		}, engines.Run{})).To(Succeed())

		Expect(current.Findings()).To(HaveLen(2))
		Expect(current.Findings()[0].TemplateID).To(Equal("tls-version"))
		Expect(current.Findings()[1].TemplateID).To(Equal("cookie-flags"))
	})
})
