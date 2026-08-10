package scan

import (
	"context"

	"github.com/flanksource/clicky/task"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
)

type taskProgressFixture struct{}

func (taskProgressFixture) Progress(string) (api.ScanStats, bool) {
	return api.ScanStats{Requests: 25, Total: 100}, true
}

var _ = Describe("scan task lifecycle", func() {
	It("registers one running child with scan metadata", func() {
		run := startManagedScan("nuclei-safe-1", "nuclei", "safe", func() error { return nil })
		DeferCleanup(func() { run.Finish(task.StatusCancelled, nil) })

		snapshots := task.SnapshotByID(run.ID())
		Expect(snapshots).To(HaveLen(2))
		Expect(struct {
			Name, Kind, Status string
			Labels             map[string]string
			Total, Running     int
		}{
			snapshots[0].Name,
			snapshots[0].Kind,
			snapshots[0].Status,
			snapshots[0].Labels,
			snapshots[0].Total,
			snapshots[0].Running,
		}).To(Equal(struct {
			Name, Kind, Status string
			Labels             map[string]string
			Total, Running     int
		}{
			"nuclei-safe-1",
			"scan",
			string(task.StatusRunning),
			map[string]string{"engine": "nuclei", "profile": "safe"},
			1,
			1,
		}))
		Expect(snapshots[1].Status).To(Equal(string(task.StatusRunning)))
		Expect(snapshots[0].Controls).To(Equal([]task.ControlAction{task.ControlStop}))
		Expect(snapshots[1].Controls).To(Equal([]task.ControlAction{task.ControlStop}))
	})

	It("binds process output, details, progress, and exact-run cancellation", func() {
		stops := 0
		run := startManagedScan("bound scan", "nuclei", "safe", func() error {
			stops++
			return nil
		})
		invocation := &engines.Invocation{
			Bin: "/bin/sh", Args: []string{"-c", "echo output; echo problem >&2"}, WorkDir: GinkgoT().TempDir(),
		}
		bindManagedScan(run, invocation)
		Expect(invocation.Run(context.Background()).ExitCode).To(Equal(0))
		progress := streamWriter{output: NewOutput(taskProgressFixture{}), stream: StreamStdout, task: run.Task(), runtime: &Runtime{}}
		_, err := progress.Write([]byte("progress\n"))
		Expect(err).ToNot(HaveOccurred())

		snapshots := task.SnapshotByID(run.ID())
		Expect(snapshots[1].Stdout).To(Equal("output\n"))
		Expect(snapshots[1].Stderr).To(Equal("problem\n"))
		Expect([]int{snapshots[1].Progress, snapshots[1].MaxValue}).To(Equal([]int{25, 100}))
		Expect(snapshots[1].Details).ToNot(BeNil())

		Expect(task.ControlRun(context.Background(), run.ID(), task.ControlStop)).To(Succeed())
		Expect(stops).To(Equal(1))
		Expect(task.SnapshotByID(run.ID())[0].Controls).To(BeEmpty())
		finishManagedScan(run, api.PhaseCancelled, "context canceled")
	})

	It("does not pass Nuclei's zero-total percentage overflow to Clicky", func() {
		run := startManagedScan("invalid progress", "nuclei", "safe", func() error { return nil })
		DeferCleanup(func() { run.Finish(task.StatusCancelled, nil) })

		updateTaskProgress(run.Task(), &api.ScanStats{
			Percent: 9223372036854775808,
		})

		snapshot := task.SnapshotByID(run.ID())[1]
		Expect([]int{snapshot.Progress, snapshot.MaxValue}).To(Equal([]int{0, 100}))
	})

	DescribeTable("maps scan outcomes onto terminal task statuses",
		func(phase api.Phase, problem string, expected task.Status) {
			run := startManagedScan("scan outcome", "nuclei", "safe", func() error { return nil })
			finishManagedScan(run, phase, problem)

			snapshots := task.SnapshotByID(run.ID())
			Expect(snapshots).To(HaveLen(2))
			Expect([]string{snapshots[0].Status, snapshots[1].Status}).To(Equal([]string{
				string(expected), string(expected),
			}))
		},
		Entry("successful", api.PhaseDone, "", task.StatusSuccess),
		Entry("completed with a warning", api.PhaseDone, "partial output", task.StatusWarning),
		Entry("failed", api.PhaseFailed, "engine exited 1", task.StatusFailed),
		Entry("cancelled", api.PhaseCancelled, "context canceled", task.StatusCancelled),
	)
})
