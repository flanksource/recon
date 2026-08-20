package probes

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/flanksource/clicky/task"
	flanksourceContext "github.com/flanksource/commons/context"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

// hostPort strips the scheme from an httptest URL, leaving the bare host the
// inventory would hold.
func hostPort(raw string) string {
	parsed, err := url.Parse(raw)
	Expect(err).ToNot(HaveOccurred())
	return parsed.Host
}

func probeResultDown(host, reason string) api.ProbeResult {
	return api.ProbeResult{Host: host, URL: "http://" + host, Error: reason}
}

var _ = Describe("the probe task group", func() {
	It("is addressed by the run's own id", func() {
		// The group id is the probes row id, so /api/v1/tasks/{id} and
		// /api/v1/probe/{id} name the same run. Without it the browser would have
		// to be told two ids for one sweep.
		group := newTaskGroup("01JABCDEF", "class non-prod", 12, 4)
		DeferCleanup(group.Cancel)

		Expect(group.ID()).To(Equal("01JABCDEF"))
	})

	It("carries the vocabulary the task list filters on", func() {
		group := newTaskGroup("01JABCDEG", "class non-prod", 12, 4)
		DeferCleanup(group.Cancel)

		snapshots := task.SnapshotByID(group.ID())
		Expect(snapshots).ToNot(BeEmpty())
		Expect(snapshots[0].Kind).To(Equal("probe"))
		Expect(snapshots[0].Labels).To(Equal(map[string]string{
			"hosts": "12", "selector": "class non-prod",
		}))
		Expect(snapshots[0].Name).To(Equal("probe class non-prod"))
	})
})

var _ = Describe("per-host task options", func() {
	// Asserted through the manager rather than by reading the options back:
	// clicky's Task keeps them unexported, and what matters is what the worker
	// does with them anyway.
	run := func(timeout time.Duration, work func(*task.Task) error) task.TypedTask[api.ProbeResult] {
		GinkgoHelper()
		group := newTaskGroup("01J"+strconv.Itoa(int(timeout)), "test", 1, 1)
		DeferCleanup(group.Cancel)
		handle := group.Add("host", func(_ flanksourceContext.Context, t *task.Task) (api.ProbeResult, error) {
			return api.ProbeResult{}, work(t)
		}, taskOptions(timeout)...)
		handle.WaitFor()
		return handle
	}

	// Clicky retries three times by default on errors whose text contains
	// "timeout" or "connection" — exactly what a host that is down produces. A
	// sweep that inherited that default would probe every dead host four times
	// and spend its slowest minutes re-confirming what it already knew.
	It("attempts a host once even when it fails the way a dead host fails", func() {
		var attempts atomic.Int32
		handle := run(time.Second, func(*task.Task) error {
			attempts.Add(1)
			return errors.New("dial tcp: connect: connection refused")
		})

		Expect(handle.Status()).To(Equal(task.StatusFailed))
		Expect(attempts.Load()).To(BeEquivalentTo(1))
	})

	// A bare host is tried over HTTPS and then HTTP, so a budget equal to one
	// probe's would kill the second leg before it started.
	It("gives a host long enough for both of its legs", func() {
		handle := run(60*time.Millisecond, func(*task.Task) error {
			time.Sleep(90 * time.Millisecond)
			return nil
		})

		Expect(handle.Status()).To(Equal(task.StatusSuccess))
	})
})

var _ = Describe("the summary a host's task shows", func() {
	It("reads as the answer for a host that responded", func() {
		Expect(describe(api.ProbeResult{Up: true, StatusCode: 200, ResponseTimeMs: 42})).
			To(Equal("200 in 42ms"))
	})

	It("says why for a host that did not", func() {
		Expect(describe(probeResultDown("a.example.test", "connection refused"))).
			To(Equal("connection refused"))
	})

	It("still says something when there is no reason to give", func() {
		Expect(describe(api.ProbeResult{Host: "a.example.test"})).To(Equal("no answer"))
		Expect(strings.TrimSpace(describe(api.ProbeResult{}))).ToNot(BeEmpty())
	})
})
