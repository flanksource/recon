package all_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/discovery"
	"github.com/flanksource/recon/internal/engines/scan"
)

// Every engine's default profile must be one the engine itself accepts.
//
// Validating a profile against its own catalog is not enough: the catalog knows
// each option's type and range, but not which combinations the tool refuses.
// tlsx shipped a default that set -san and -cn, which it rejects alongside any
// other probe — schema-valid, and it could never start. Nothing caught it until
// a sweep failed with "could not validate options".
//
// These tools validate their options before doing any work, so the question is
// only whether the engine gets past startup. Each is given a loopback target so
// "no valid targets" cannot be mistaken for a bad option set, and reaching the
// timeout counts as success: it means the engine accepted the profile and
// started working. Only a prompt non-zero exit is a failure.
var _ = Describe("the default profiles", Label("binaries"), func() {
	for _, engine := range allEngines() {
		spec, args, input := engine.spec, engine.args, engine.input

		It(fmt.Sprintf("%s starts with the profile it ships", spec.Name), func(ctx SpecContext) {
			if testing.Short() {
				Skip("runs the engine binary")
			}

			bin, err := exec.LookPath(spec.Binary)
			if err != nil {
				Skip(spec.Binary + " is not installed")
			}

			dir := GinkgoT().TempDir()
			list := filepath.Join(dir, "input.txt")
			Expect(os.WriteFile(list, []byte(input+"\n"), 0o600)).To(Succeed())

			run := engines.Run{
				Bin: bin, WorkDir: dir, Config: spec.Defaults.Config,
				In: list, Out: filepath.Join(dir, "output.jsonl"),
			}

			deadline, cancel := context.WithTimeout(ctx, engineStartTimeout)
			defer cancel()

			command := exec.CommandContext(deadline, bin, args(run)...)
			command.Dir = dir
			output, err := command.CombinedOutput()

			// Hitting the deadline means it was still working, which answers the
			// question: the options were accepted.
			if errors.Is(deadline.Err(), context.DeadlineExceeded) {
				return
			}
			Expect(err).ToNot(HaveOccurred(),
				"%s rejected its own default profile:\n%s", spec.Name, output)
		}, SpecTimeout(engineStartTimeout+30*time.Second))
	}
})

type engineUnderTest struct {
	spec  engines.Spec
	args  func(engines.Run) []string
	input string
}

// loopbackFor is a target of the kind the engine consumes, always pointing at
// this machine so the check contacts nothing.
func loopbackFor(accepts discovery.Kind) string {
	switch accepts {
	case discovery.Zones:
		return "localhost"
	case discovery.Origins:
		return "http://127.0.0.1"
	case discovery.Endpoints:
		return "127.0.0.1:80"
	default:
		return "127.0.0.1"
	}
}

func allEngines() []engineUnderTest {
	var all []engineUnderTest
	for _, engine := range discovery.All() {
		all = append(all, engineUnderTest{engine.Spec(), engine.Args, loopbackFor(engine.Accepts())})
	}
	for _, engine := range scan.All() {
		all = append(all, engineUnderTest{engine.Spec(), engine.Args, "http://127.0.0.1"})
	}
	return all
}

const engineStartTimeout = 25 * time.Second
