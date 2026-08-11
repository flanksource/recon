package engines_test

import (
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines"
)

// ScanJSONLines reads the output of every engine that still runs as a
// subprocess — httpx, naabu, dnsx, katana and tlsx. Cancelling one of those
// truncates whatever line it was mid-write on, so how it handles damage is the
// difference between losing a sweep's results and losing one record of them.
var _ = Describe("reading engine JSONL", func() {
	collect := func(body string) ([]string, error) {
		var lines []string
		err := engines.ScanJSONLines(strings.NewReader(body), func(line []byte) error {
			lines = append(lines, string(line))
			return nil
		})
		return lines, err
	}

	good := `{"host":"h1.example.test"}`

	It("keeps the records either side of a truncated line and reports it", func() {
		lines, err := collect(good + "\n" + `{"host":"h2` + "\n" + good)

		Expect(lines).To(HaveLen(2))
		Expect(err).To(MatchError(ContainSubstring("line 2 is not valid JSON")))
	})

	It("skips banners and blank lines silently", func() {
		lines, err := collect("[INF] Templates loaded: 100\n\n" + good + "\n")

		Expect(lines).To(HaveLen(1))
		Expect(err).ToNot(HaveOccurred())
	})

	It("fails outright when the caller cannot accept a record", func() {
		// A storage failure is not the engine's to absorb.
		err := engines.ScanJSONLines(strings.NewReader(good), func([]byte) error {
			return os.ErrClosed
		})

		Expect(err).To(MatchError(os.ErrClosed))
	})
})
