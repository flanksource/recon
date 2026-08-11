// Package scan turns a running engine's output into the state the UI renders.
package scan

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/flanksource/recon/internal/api"
)

const (
	// OutputTailChars bounds both the raw output kept for the live console and
	// the log built from it. A scan emits megabytes and the complete output is
	// on disk; what the UI needs is the end of it, cheap enough to send on
	// every poll.
	OutputTailChars = 20_000

	// LogLineChars bounds one log line. A response body echoed into the output
	// as a single line must not evict the whole tail on its own.
	LogLineChars = 300
)

// Stream says where a chunk of output came from. system is the runtime's own
// commentary — the command line, a cancellation — not the engine's.
type Stream string

const (
	StreamStdout Stream = "stdout"
	StreamStderr Stream = "stderr"
	StreamSystem Stream = "system"
)

// OutputEvent is one write, kept as it arrived. The console replays these
// verbatim, so they are not line-split: the sequence is what orders two pipes
// that have no shared clock.
type OutputEvent struct {
	Sequence  int       `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	Stream    Stream    `json:"stream"`
	Text      string    `json:"text"`
}

// OutputSnapshot is one consistent read of a buffer that is still being
// written to.
type OutputSnapshot struct {
	Stats  *api.ScanStats `json:"stats,omitempty"`
	Log    string         `json:"log"`
	Events []OutputEvent  `json:"output"`
}

// Output accumulates a running engine's output into what the UI renders. It is
// written by the engine as it runs and read by whoever is serving the status, so
// every method takes the lock.
type Output struct {
	mu      sync.Mutex
	stats   *api.ScanStats
	log     []byte
	pending map[Stream]string
	events  []OutputEvent
	next    int
}

// NewOutput returns an empty buffer.
func NewOutput() *Output {
	return &Output{
		pending: map[Stream]string{StreamStdout: "", StreamStderr: ""},
		next:    1,
	}
}

// SetStats records the engine's latest progress.
//
// Progress arrives as counters from the engine rather than being recovered from
// its log output, so there is no chance of a stats line being mistaken for
// something worth showing the user, or of a malformed one silently freezing the
// progress bar.
func (o *Output) SetStats(stats api.ScanStats) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stats = &stats
}

// Append records one write from a pipe.
//
// A chunk breaks wherever the pipe happened to split it, so a line is only
// interpreted once its newline arrives, and each stream buffers its own partial
// line: stdout and stderr interleave, and joining them would splice one tool's
// half-written JSON onto another's log message.
func (o *Output) Append(stream Stream, text string) {
	switch stream {
	case StreamStdout, StreamStderr, StreamSystem:
	default:
		panic(fmt.Sprintf("scan: unknown output stream %q", stream))
	}
	if text == "" {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	o.events = append(o.events, OutputEvent{
		Sequence:  o.next,
		Timestamp: time.Now().UTC(),
		Stream:    stream,
		Text:      text,
	})
	o.next++
	o.trimEvents()

	// The runtime writes system messages whole, so there is nothing to
	// reassemble and no reason to withhold the last line until a newline that
	// may never come.
	if stream == StreamSystem {
		for _, line := range strings.Split(text, "\n") {
			o.appendLine(line)
		}
		return
	}

	lines := strings.Split(o.pending[stream]+text, "\n")
	o.pending[stream] = lines[len(lines)-1]
	for _, line := range lines[:len(lines)-1] {
		o.appendLine(line)
	}
}

// Flush interprets whatever is left in the partial-line buffers. An engine that
// dies mid-line still wrote that line, and it is usually the one saying why.
func (o *Output) Flush() {
	o.mu.Lock()
	defer o.mu.Unlock()

	for _, stream := range []Stream{StreamStdout, StreamStderr} {
		line := o.pending[stream]
		if line == "" {
			continue
		}
		o.pending[stream] = ""
		o.appendLine(line)
	}
}

// Snapshot copies the state for a reader. The copy is the point: the pipe
// goroutines keep writing, and trimming rewrites the oldest event in place.
func (o *Output) Snapshot() OutputSnapshot {
	o.mu.Lock()
	defer o.mu.Unlock()

	snapshot := OutputSnapshot{
		Log:    string(o.log),
		Events: make([]OutputEvent, len(o.events)),
	}
	copy(snapshot.Events, o.events)
	if o.stats != nil {
		stats := *o.stats
		snapshot.Stats = &stats
	}
	return snapshot
}

// appendLine interprets one completed line.
func (o *Output) appendLine(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}

	// Runes here, unlike the byte-counted tails below: this truncation lands in
	// the middle of text a human reads, and cutting a codepoint in half would
	// show as a replacement character.
	if runes := []rune(line); len(runes) > LogLineChars {
		line = string(runes[:LogLineChars]) + "…"
	}

	o.log = append(append(o.log, line...), '\n')
	if len(o.log) > OutputTailChars {
		o.log = o.log[len(o.log)-OutputTailChars:]
	}
}

// trimEvents drops the oldest output until the retained text fits the tail. The
// oldest surviving event is sliced rather than dropped whole so the console
// keeps exactly the last OutputTailChars, not the last whole write that fits.
func (o *Output) trimEvents() {
	total := 0
	for _, event := range o.events {
		total += len(event.Text)
	}

	for total > OutputTailChars && len(o.events) > 0 {
		overflow := total - OutputTailChars
		if len(o.events[0].Text) <= overflow {
			total -= len(o.events[0].Text)
			o.events = o.events[1:]
			continue
		}
		o.events[0].Text = o.events[0].Text[overflow:]
		total -= overflow
	}
}
