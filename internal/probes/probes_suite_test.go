package probes

import (
	"testing"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/task"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestProbes(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "probes")
}

// The task renderer draws to stderr on a ticker. Left on, a suite that starts
// dozens of groups spends its time repainting and interleaves its output with
// Ginkgo's.
var _ = BeforeSuite(func() { task.SetNoRender(true) })

var _ = AfterSuite(func() {
	clicky.ClearGlobalTasks()
	task.SetNoRender(false)
})
