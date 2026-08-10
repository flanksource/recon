package cli

import (
	"testing"
	"time"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/task"
	"github.com/flanksource/commons/duration"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const delayedPingURL = "https://httpbin.flanksource.com/delay/4"

var _ = Describe("reconctl ping integration", Ordered, Label("integration"), func() {
	BeforeAll(func() {
		if testing.Short() {
			Skip("requires network access")
		}
		task.SetNoRender(true)
	})

	AfterAll(func() {
		clicky.ClearGlobalTasks()
		task.SetNoRender(false)
	})

	It("applies the timeout to the complete delayed request", func(ctx SpecContext) {
		options := testPingOptions(delayedPingURL)
		options.Timeout = duration.Duration(15 * time.Second)
		results, err := runPing(ctx, options)
		Expect(err).ToNot(HaveOccurred())
		Expect(results).To(HaveLen(1))
		Expect(results[0].Up).To(BeTrue())
		Expect(results[0].ResponseTime).To(BeNumerically(">=", 4*time.Second))

		started := time.Now()
		results, err = runPing(ctx, testPingOptions(delayedPingURL))
		Expect(err).To(MatchError("1 of 1 probes failed"))
		Expect(results).To(HaveLen(1))
		Expect(results[0].Up).To(BeFalse())
		Expect(results[0].Error).To(ContainSubstring("deadline exceeded"))
		Expect(time.Since(started)).To(BeNumerically(">=", defaultPingTimeout))
		Expect(time.Since(started)).To(BeNumerically("<", 5*time.Second))
	}, SpecTimeout(25*time.Second))
})
