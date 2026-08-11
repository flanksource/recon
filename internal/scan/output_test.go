package scan_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/scan"
)

func TestScanOutput(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "scan output")
}

// wrote is an event without its timestamp, so a whole event list can be
// asserted in one comparison.
type wrote struct {
	Sequence int
	Stream   scan.Stream
	Text     string
}

func writes(events []scan.OutputEvent) []wrote {
	out := make([]wrote, len(events))
	for i, event := range events {
		out[i] = wrote{Sequence: event.Sequence, Stream: event.Stream, Text: event.Text}
	}
	return out
}

var _ = Describe("reassembling output written in chunks", func() {
	// Ported from app/server/scan-runtime.test.ts.
	It("does not combine lines written on different streams", func() {
		out := scan.NewOutput()

		out.Append(scan.StreamStdout, "loaded ")
		out.Append(scan.StreamStderr, "retrying ")
		out.Append(scan.StreamStdout, "4314 templates\n")
		out.Append(scan.StreamStderr, "request\n")
		out.Flush()

		state := out.Snapshot()
		Expect(state.Log).To(Equal("loaded 4314 templates\nretrying request\n"))
		Expect(writes(state.Events)).To(Equal([]wrote{
			{Sequence: 1, Stream: scan.StreamStdout, Text: "loaded "},
			{Sequence: 2, Stream: scan.StreamStderr, Text: "retrying "},
			{Sequence: 3, Stream: scan.StreamStdout, Text: "4314 templates\n"},
			{Sequence: 4, Stream: scan.StreamStderr, Text: "request\n"},
		}))
	})

	It("holds a line back until its newline arrives", func() {
		out := scan.NewOutput()
		out.Append(scan.StreamStdout, "half a ")

		Expect(out.Snapshot().Log).To(BeEmpty())

		out.Append(scan.StreamStdout, "line\n")
		Expect(out.Snapshot().Log).To(Equal("half a line\n"))
	})

	It("interprets the trailing partial line on flush, once", func() {
		out := scan.NewOutput()
		out.Append(scan.StreamStderr, "engine died mid-")

		out.Flush()
		out.Flush()

		Expect(out.Snapshot().Log).To(Equal("engine died mid-\n"))
	})

	It("ignores an empty write rather than spending a sequence number on it", func() {
		out := scan.NewOutput()
		out.Append(scan.StreamStdout, "")
		out.Append(scan.StreamStdout, "first\n")

		Expect(writes(out.Snapshot().Events)).To(Equal([]wrote{
			{Sequence: 1, Stream: scan.StreamStdout, Text: "first\n"},
		}))
	})

	It("drops blank lines from the log", func() {
		out := scan.NewOutput()
		out.Append(scan.StreamStdout, "one\n\n   \ntwo\n")

		Expect(out.Snapshot().Log).To(Equal("one\ntwo\n"))
	})

	It("logs a system message whole without waiting for a newline", func() {
		out := scan.NewOutput()
		out.Append(scan.StreamStdout, "partial")
		out.Append(scan.StreamSystem, "cancelled by user")

		state := out.Snapshot()
		Expect(state.Log).To(Equal("cancelled by user\n"))
		Expect(state.Events[1].Stream).To(Equal(scan.StreamSystem))

		// The system message must not have consumed the stdout partial line.
		out.Append(scan.StreamStdout, " line\n")
		Expect(out.Snapshot().Log).To(Equal("cancelled by user\npartial line\n"))
	})

	It("stamps every event with the time it arrived", func() {
		out := scan.NewOutput()
		before := time.Now().UTC()
		out.Append(scan.StreamStdout, "a\n")
		out.Append(scan.StreamStderr, "b\n")

		events := out.Snapshot().Events
		Expect(events[0].Timestamp).To(BeTemporally(">=", before))
		Expect(events[1].Timestamp).To(BeTemporally(">=", events[0].Timestamp))

		encoded, err := json.Marshal(events[0])
		Expect(err).ToNot(HaveOccurred())
		var decoded struct {
			Timestamp string `json:"timestamp"`
		}
		Expect(json.Unmarshal(encoded, &decoded)).To(Succeed())
		Expect(time.Parse(time.RFC3339, decoded.Timestamp)).To(BeTemporally("==", events[0].Timestamp))
	})

	It("rejects a stream it cannot buffer rather than inventing one", func() {
		out := scan.NewOutput()
		Expect(func() { out.Append(scan.Stream("stdin"), "x\n") }).To(PanicWith(ContainSubstring(`unknown output stream "stdin"`)))
	})
})

var _ = Describe("progress reported by the engine", func() {
	It("keeps only the latest report", func() {
		out := scan.NewOutput()
		out.SetStats(api.ScanStats{Requests: 5, Total: 10, Duration: "12s"})
		out.SetStats(api.ScanStats{Requests: 9, Total: 10, Duration: "30s"})

		Expect(out.Snapshot().Stats).To(Equal(&api.ScanStats{
			Requests: 9, Total: 10, Duration: "30s",
		}))
	})

	It("reports nothing until the engine says something", func() {
		// No stats means no progress bar, which is the honest answer: a bar that
		// never moves is worse than none.
		out := scan.NewOutput()
		out.Append(scan.StreamStdout, "loading templates\n")

		state := out.Snapshot()
		Expect(state.Stats).To(BeNil())
		Expect(state.Log).To(Equal("loading templates\n"))
	})

	It("logs JSON the engine writes rather than mistaking it for progress", func() {
		// Progress arrives as counters now, so no line on this stream is ever
		// interpreted — one that looks like stats is just a line.
		line := `{"requests":"5","total":"10"}`
		out := scan.NewOutput()
		out.Append(scan.StreamStdout, line+"\n")

		Expect(out.Snapshot().Stats).To(BeNil())
		Expect(out.Snapshot().Log).To(Equal(line + "\n"))
	})
})

var _ = Describe("bounding what is kept", func() {
	It("truncates a long line by runes, so the tail it counts in bytes is longer", func() {
		out := scan.NewOutput()
		out.Append(scan.StreamStdout, strings.Repeat("é", scan.LogLineChars+100)+"\n")

		logged := strings.TrimSuffix(out.Snapshot().Log, "\n")
		Expect(logged).To(Equal(strings.Repeat("é", scan.LogLineChars) + "…"))
		Expect(utf8.RuneCountInString(logged)).To(Equal(scan.LogLineChars + 1))
		Expect(len(logged)).To(Equal(scan.LogLineChars*2 + len("…")))
	})

	It("leaves a line at the limit alone", func() {
		out := scan.NewOutput()
		line := strings.Repeat("x", scan.LogLineChars)
		out.Append(scan.StreamStdout, line+"\n")

		Expect(out.Snapshot().Log).To(Equal(line + "\n"))
	})

	It("keeps the last 20000 bytes of the log", func() {
		out := scan.NewOutput()
		line := strings.Repeat("x", 99)
		for i := 0; i < 1000; i++ {
			out.Append(scan.StreamStdout, line+"\n")
		}

		// 100 bytes a line divides the tail exactly, so the survivors are whole
		// lines and the count is arithmetic, not observed.
		Expect(out.Snapshot().Log).To(Equal(strings.Repeat(line+"\n", scan.OutputTailChars/100)))
	})

	It("bounds the log in bytes, not runes", func() {
		out := scan.NewOutput()
		for i := 0; i < 200; i++ {
			out.Append(scan.StreamStdout, strings.Repeat("é", 100)+"\n")
		}

		logged := out.Snapshot().Log
		Expect(len(logged)).To(Equal(scan.OutputTailChars))
		Expect(utf8.RuneCountInString(logged)).To(BeNumerically("<", scan.OutputTailChars))
	})

	It("slices into the oldest surviving write rather than dropping it whole", func() {
		out := scan.NewOutput()
		out.Append(scan.StreamStdout, strings.Repeat("a", 15_000))
		out.Append(scan.StreamStdout, strings.Repeat("b", 10_000))

		events := out.Snapshot().Events
		Expect(events).To(HaveLen(2))
		Expect(events[0].Text).To(Equal(strings.Repeat("a", 10_000)))
		Expect(events[1].Text).To(Equal(strings.Repeat("b", 10_000)))
	})

	It("drops a write that has fallen entirely out of the tail, keeping its sequence gap", func() {
		out := scan.NewOutput()
		for _, char := range []string{"a", "b", "c"} {
			out.Append(scan.StreamStdout, strings.Repeat(char, 10_000))
		}

		events := out.Snapshot().Events
		Expect(events).To(HaveLen(2))
		Expect(events[0].Sequence).To(Equal(2))
		Expect(events[0].Text).To(Equal(strings.Repeat("b", 10_000)))
	})

	It("trims a single oversized write down to the tail", func() {
		out := scan.NewOutput()
		out.Append(scan.StreamStdout, strings.Repeat("a", 25_000)+strings.Repeat("z", 1))

		events := out.Snapshot().Events
		Expect(events).To(HaveLen(1))
		Expect(len(events[0].Text)).To(Equal(scan.OutputTailChars))
		Expect(events[0].Text).To(HaveSuffix("z"))
	})
})

var _ = Describe("concurrent writers", func() {
	const perStream = 200

	It("keeps every line while both pipes write and a reader snapshots", func() {
		out := scan.NewOutput()

		var wg sync.WaitGroup
		for _, stream := range []scan.Stream{scan.StreamStdout, scan.StreamStderr} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < perStream; i++ {
					out.Append(stream, fmt.Sprintf("%s %03d\n", stream, i))
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perStream; i++ {
				out.Snapshot()
			}
		}()
		wg.Wait()

		state := out.Snapshot()
		Expect(state.Events).To(HaveLen(2 * perStream))
		Expect(strings.Count(state.Log, "\n")).To(Equal(2 * perStream))

		seen := map[int]bool{}
		for _, event := range state.Events {
			Expect(seen[event.Sequence]).To(BeFalse(), "duplicate sequence %d", event.Sequence)
			seen[event.Sequence] = true
		}
		Expect(seen).To(HaveLen(2 * perStream))
	})

	It("hands the reader a copy that later writes cannot rewrite", func() {
		out := scan.NewOutput()
		out.Append(scan.StreamStdout, strings.Repeat("a", 15_000))
		taken := out.Snapshot()

		out.Append(scan.StreamStdout, strings.Repeat("b", 10_000))

		Expect(taken.Events).To(HaveLen(1))
		Expect(taken.Events[0].Text).To(Equal(strings.Repeat("a", 15_000)))
	})
})
