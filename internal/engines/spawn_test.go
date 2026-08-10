package engines_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flanksource/clicky/task"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines"
)

func TestSpawn(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "engines/spawn")
}

var _ = Describe("the per-run scratch directory", func() {
	It("gives each run its own, so two runs cannot overwrite each other", func() {
		// The previous implementation reused one fixed path, so a scan from the
		// CLI and one from the UI clobbered each other's input list.
		root := GinkgoT().TempDir()

		first, err := engines.NewWorkDir(root, "scan", "01")
		Expect(err).ToNot(HaveOccurred())
		second, err := engines.NewWorkDir(root, "scan", "02")
		Expect(err).ToNot(HaveOccurred())
		Expect(first).ToNot(Equal(second))

		firstList, err := engines.WriteList(first, "hosts.txt", []string{"a.example.test"})
		Expect(err).ToNot(HaveOccurred())
		_, err = engines.WriteList(second, "hosts.txt", []string{"b.example.test"})
		Expect(err).ToNot(HaveOccurred())

		body, err := os.ReadFile(firstList)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal("a.example.test\n"))
	})

	It("refuses to write an empty input list", func() {
		// An engine given no input exits cleanly having found nothing, which is
		// indistinguishable from a clean bill of health.
		_, err := engines.WriteList(GinkgoT().TempDir(), "hosts.txt", nil)
		Expect(err).To(MatchError(ContainSubstring("refusing to write an empty")))
	})

	It("removes itself on cleanup", func() {
		root := GinkgoT().TempDir()
		dir, err := engines.NewWorkDir(root, "discover", "03")
		Expect(err).ToNot(HaveOccurred())

		invocation := &engines.Invocation{WorkDir: dir}
		invocation.Cleanup()
		Expect(dir).ToNot(BeADirectory())
	})
})

var _ = Describe("running an engine", func() {
	It("reports the exit code and the command that produced it", func() {
		invocation := &engines.Invocation{
			Bin: "/bin/sh", Args: []string{"-c", "exit 3"}, WorkDir: GinkgoT().TempDir(),
		}
		result := invocation.Run(context.Background())

		Expect(result.ExitCode).To(Equal(3))
		Expect(result.Command).To(Equal([]string{"/bin/sh", "-c", "exit 3"}))
	})

	It("streams output as it arrives", func() {
		var out strings.Builder
		invocation := &engines.Invocation{
			Bin: "/bin/sh", Args: []string{"-c", "echo hello"},
			WorkDir: GinkgoT().TempDir(), Stdout: &out,
		}
		Expect(invocation.Run(context.Background()).ExitCode).To(Equal(0))
		Expect(out.String()).To(ContainSubstring("hello"))
	})

	It("projects captured output and process details for task snapshots", func() {
		invocation := &engines.Invocation{
			Bin: "/bin/sh", Args: []string{"-c", "echo output; echo problem >&2"},
			WorkDir: GinkgoT().TempDir(),
		}
		Expect(invocation.Run(context.Background()).ExitCode).To(Equal(0))

		Expect(invocation.OutputSnapshot()).To(Equal(task.OutputSnapshot{
			Stdout: "output\n", Stderr: "problem\n",
		}))
		details := invocation.TaskDetails()
		Expect(struct {
			Command  string
			Args     []string
			Status   string
			ExitCode int
		}{details.Command, details.Args, details.Status, details.ExitCode}).To(Equal(struct {
			Command  string
			Args     []string
			Status   string
			ExitCode int
		}{"/bin/sh", []string{"-c", "echo output; echo problem >&2"}, "success", 0}))
	})

	// naabu forks raw-socket workers and nuclei spawns helpers. A cancel that
	// kills only the parent leaves those running against live infrastructure —
	// which is the failure that matters here, not a stray process on a laptop.
	It("kills the whole process group, not just the child it started", func() {
		dir := GinkgoT().TempDir()
		marker := filepath.Join(dir, "grandchild.pid")

		// The shell backgrounds a grandchild that outlives it, then sleeps.
		// Without a process group the grandchild survives the kill.
		script := fmt.Sprintf(`sh -c 'echo $$ > %s; sleep 30' & sleep 30`, marker)
		invocation := &engines.Invocation{
			Bin: "/bin/sh", Args: []string{"-c", script}, WorkDir: dir,
		}

		ctx, cancel := context.WithCancel(context.Background())
		finished := make(chan engines.Result, 1)
		go func() { finished <- invocation.Run(ctx) }()

		Eventually(func() bool {
			_, err := os.Stat(marker)
			return err == nil
		}, 10*time.Second, 50*time.Millisecond).Should(BeTrue(), "grandchild never started")

		pid := strings.TrimSpace(readFile(marker))
		Expect(pid).ToNot(BeEmpty())

		cancel()
		Eventually(finished, 15*time.Second).Should(Receive())

		Eventually(func() bool {
			return alive(pid)
		}, 10*time.Second, 100*time.Millisecond).Should(BeFalse(),
			"the grandchild survived cancellation and is still running")
	})
})

func readFile(path string) string {
	body, err := os.ReadFile(path)
	Expect(err).ToNot(HaveOccurred())
	return string(body)
}

// alive reports whether a pid is still running. `kill -0` is the portable ask.
func alive(pid string) bool {
	return exec.Command("kill", "-0", pid).Run() == nil
}
