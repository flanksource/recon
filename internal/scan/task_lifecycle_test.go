package scan

import (
	"context"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/flanksource/clicky/task"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

var _ = Describe("scan task lifecycle", func() {
	It("keeps later scans pending until the configured slot is free", func() {
		queue, err := newScanQueue(1)
		Expect(err).ToNot(HaveOccurred())
		release := make(chan struct{})
		firstStarted := make(chan struct{})
		secondStarted := make(chan struct{})

		first := queue.Add("first", "nuclei", "safe", func(context.Context, *task.Task) (api.Scan, error) {
			close(firstStarted)
			<-release
			return api.Scan{Name: "first", Phase: api.PhaseDone}, nil
		}, func() error { return nil })
		Eventually(firstStarted).Should(BeClosed())

		second := queue.Add("second", "nuclei", "safe", func(context.Context, *task.Task) (api.Scan, error) {
			close(secondStarted)
			return api.Scan{Name: "second", Phase: api.PhaseDone}, nil
		}, func() error { return nil })
		Consistently(secondStarted, 100*time.Millisecond).ShouldNot(BeClosed())
		Expect(second.Status()).To(Equal(task.StatusPending))

		close(release)
		Eventually(secondStarted).Should(BeClosed())
		Eventually(first.WaitFor).ShouldNot(BeNil())
		Eventually(second.WaitFor).ShouldNot(BeNil())
	})

	It("runs up to the configured number of scans", func() {
		queue, err := newScanQueue(2)
		Expect(err).ToNot(HaveOccurred())
		release := make(chan struct{})
		var active atomic.Int32
		var maximum atomic.Int32
		started := make(chan struct{}, 2)
		work := func(context.Context, *task.Task) (api.Scan, error) {
			current := active.Add(1)
			for current > maximum.Load() && !maximum.CompareAndSwap(maximum.Load(), current) {
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
			return api.Scan{Phase: api.PhaseDone}, nil
		}

		first := queue.Add("first", "nuclei", "safe", work, func() error { return nil })
		second := queue.Add("second", "nuclei", "safe", work, func() error { return nil })
		Eventually(started).Should(Receive())
		Eventually(started).Should(Receive())
		Expect(maximum.Load()).To(Equal(int32(2)))

		close(release)
		Eventually(first.WaitFor).ShouldNot(BeNil())
		Eventually(second.WaitFor).ShouldNot(BeNil())
	})

	It("removes a cancelled pending scan and starts a fresh visible batch", func() {
		queue, err := newScanQueue(1)
		Expect(err).ToNot(HaveOccurred())
		release := make(chan struct{})
		started := make(chan struct{})
		first := queue.Add("first", "nuclei", "safe", func(context.Context, *task.Task) (api.Scan, error) {
			close(started)
			<-release
			return api.Scan{Phase: api.PhaseDone}, nil
		}, func() error { return nil })
		Eventually(started).Should(BeClosed())

		cancelled := queue.Add("cancelled", "nuclei", "safe", func(context.Context, *task.Task) (api.Scan, error) {
			Fail("a cancelled pending scan must not start")
			return api.Scan{}, nil
		}, func() error { return nil })
		batchID := queue.group.ID()
		cancelled.Cancel()
		cancelled.complete()
		close(release)
		Expect(first.WaitFor()).ToNot(BeNil())
		Expect(cancelled.WaitFor().Status).To(Equal(task.StatusCancelled))

		thirdStarted := make(chan struct{})
		third := queue.Add("third", "nuclei", "safe", func(context.Context, *task.Task) (api.Scan, error) {
			close(thirdStarted)
			return api.Scan{Phase: api.PhaseDone}, nil
		}, func() error { return nil })
		Eventually(thirdStarted).Should(BeClosed())
		Expect(queue.group.ID()).ToNot(Equal(batchID))
		Expect(third.WaitFor()).ToNot(BeNil())
	})

	It("registers one queued child with scan task metadata", func() {
		queue, err := newScanQueue(1)
		Expect(err).ToNot(HaveOccurred())
		release := make(chan struct{})
		started := make(chan struct{})
		queued := queue.Add("nuclei-safe-1", "nuclei", "safe", func(context.Context, *task.Task) (api.Scan, error) {
			close(started)
			<-release
			return api.Scan{Phase: api.PhaseDone}, nil
		}, func() error { return nil })
		Eventually(started).Should(BeClosed())

		snapshots := task.SnapshotByID(queue.group.ID())
		Expect(snapshots).To(HaveLen(2))
		Expect(struct {
			Name, Kind, Status string
			Total, Running     int
		}{snapshots[0].Name, snapshots[0].Kind, snapshots[0].Status, snapshots[0].Total, snapshots[0].Running}).
			To(Equal(struct {
				Name, Kind, Status string
				Total, Running     int
			}{"Scans", "scan", string(task.StatusRunning), 1, 1}))
		Expect(snapshots[1].Description).To(Equal("nuclei / safe"))
		Expect(snapshots[1].Controls).To(Equal([]task.ControlAction{task.ControlStop}))

		close(release)
		Eventually(queued.Status).Should(Equal(task.StatusSuccess))
	})

	It("binds engine output, scan details, progress, and exact-task cancellation", func() {
		queue, err := newScanQueue(1)
		Expect(err).ToNot(HaveOccurred())
		start := make(chan struct{})
		release := make(chan struct{})
		var stops atomic.Int32
		current := newSession(NewOutput(), GinkgoT().TempDir(),
			[]string{"nuclei", "-list", "targets.txt", "-severity", "high"})
		scanState := api.Scan{
			ID: "scan-2", Engine: "nuclei", Profile: "safe", Phase: api.PhaseRunning,
			DurationMS: 1250, EndpointCount: 4, Findings: 2,
			Severities: map[string]int{"high": 1, "medium": 1},
			Stats:      &api.ScanStats{Requests: 25, Total: 100, Templates: 18, Matched: 2},
		}
		queued := queue.Add("bound scan", "nuclei", "safe", func(context.Context, *task.Task) (api.Scan, error) {
			<-start
			current.Log("output\n")
			<-release
			return scanState, nil
		}, func() error {
			stops.Add(1)
			close(release)
			return nil
		})
		bindScanTask(queued.Task, scanTaskBinding{
			Session:  current,
			Snapshot: func() api.Scan { return scanState },
		})
		updateTaskProgress(queued.Task, scanState.Stats)
		close(start)

		// The engine runs in this process, so everything it says arrives on one
		// stream. There is no second pipe to attribute anything to.
		Eventually(func() []string {
			snapshot := task.SnapshotByID(queue.group.ID())[1]
			return []string{snapshot.Stdout, snapshot.Stderr}
		}).Should(Equal([]string{"output\n", ""}))
		snapshot := task.SnapshotByID(queue.group.ID())[1]
		Expect([]int{snapshot.Progress, snapshot.MaxValue}).To(Equal([]int{25, 100}))
		details, ok := snapshot.Details.(scanTaskDetails)
		Expect(ok).To(BeTrue())
		Expect(struct {
			Command       string
			Args          []string
			ScanID        string
			DurationMS    int64
			EndpointCount int
			Findings      int
			Stats         *api.ScanStats
		}{
			details.Command, details.Args, details.ScanID, details.DurationMS,
			details.EndpointCount, details.Findings, details.Stats,
		}).To(Equal(struct {
			Command       string
			Args          []string
			ScanID        string
			DurationMS    int64
			EndpointCount int
			Findings      int
			Stats         *api.ScanStats
		}{
			"nuclei", []string{"-list", "targets.txt", "-severity", "high"}, "scan-2", 1250, 4, 2,
			&api.ScanStats{Requests: 25, Total: 100, Templates: 18, Matched: 2},
		}))

		Expect(task.ControlTask(context.Background(), queue.group.ID(), queued.ID(), task.ControlStop)).To(Succeed())
		Expect(stops.Load()).To(Equal(int32(1)))
		Eventually(queued.Status).Should(Equal(task.StatusSuccess))
		Expect(task.SnapshotByID(queue.group.ID())[1].Controls).To(BeEmpty())
	})

	It("does not pass Nuclei's zero-total percentage overflow to Clicky", func() {
		queue, err := newScanQueue(1)
		Expect(err).ToNot(HaveOccurred())
		release := make(chan struct{})
		started := make(chan struct{})
		queued := queue.Add("invalid progress", "nuclei", "safe", func(context.Context, *task.Task) (api.Scan, error) {
			close(started)
			<-release
			return api.Scan{Phase: api.PhaseDone}, nil
		}, func() error { return nil })
		Eventually(started).Should(BeClosed())

		updateTaskProgress(queued.Task, &api.ScanStats{Percent: 9223372036854775808})
		snapshot := task.SnapshotByID(queue.group.ID())[1]
		Expect([]int{snapshot.Progress, snapshot.MaxValue}).To(Equal([]int{0, 100}))

		close(release)
		Eventually(queued.Status).Should(Equal(task.StatusSuccess))
	})

	DescribeTable("maps scan outcomes onto terminal task statuses",
		func(phase api.Phase, problem string, expected task.Status) {
			queue, err := newScanQueue(1)
			Expect(err).ToNot(HaveOccurred())
			queued := queue.Add("scan outcome", "nuclei", "safe", func(_ context.Context, scanTask *task.Task) (api.Scan, error) {
				result := api.Scan{Name: "scan outcome", Phase: phase, Error: problem}
				return result, finishScanTask(scanTask, result)
			}, func() error { return nil })

			Expect(queued.WaitFor()).ToNot(BeNil())
			Expect(queued.Status()).To(Equal(expected))
		},
		Entry("successful", api.PhaseDone, "", task.StatusSuccess),
		Entry("completed with a warning", api.PhaseDone, "partial output", task.StatusWarning),
		Entry("failed", api.PhaseFailed, "engine exited 1", task.StatusFailed),
		Entry("cancelled", api.PhaseCancelled, "context canceled", task.StatusCancelled),
	)
})

var _ = Describe("persisted scan output", func() {
	It("keeps a valid UTF-8 tail of at most 1 MiB for each stream", func() {
		captured := retainedScanOutput(task.OutputSnapshot{
			Stdout: "é" + strings.Repeat("x", task.SnapshotStreamLimit-1),
			Stderr: strings.Repeat("y", task.SnapshotStreamLimit+5),
		})

		Expect(captured.StdoutTruncated).To(BeTrue())
		Expect(captured.StderrTruncated).To(BeTrue())
		Expect(len(captured.Stdout)).To(BeNumerically("<=", task.SnapshotStreamLimit))
		Expect(len(captured.Stderr)).To(Equal(task.SnapshotStreamLimit))
		Expect(utf8.ValidString(captured.Stdout)).To(BeTrue())
		Expect(captured.Stdout).To(Equal(strings.Repeat("x", task.SnapshotStreamLimit-1)))
		Expect(captured.Stderr).To(Equal(strings.Repeat("y", task.SnapshotStreamLimit)))
	})
})
