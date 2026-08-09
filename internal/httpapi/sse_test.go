package httpapi_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/httpapi"
)

func TestHTTPAPI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "httpapi")
}

// golden reads a capture of the TypeScript server this package replaces. The
// browser is not being changed with it, so those bytes are the specification.
func golden(name string) []byte {
	dir, err := os.Getwd()
	Expect(err).ToNot(HaveOccurred())
	for filepath.Base(dir) != "recon" {
		parent := filepath.Dir(dir)
		Expect(parent).ToNot(Equal(dir), "repo root not found")
		dir = parent
	}

	content, err := os.ReadFile(filepath.Join(dir, "contract/golden/full", name))
	Expect(err).ToNot(HaveOccurred())
	return content
}

// scanStatus is the wire shape the captured stream carries, declared here rather
// than in the package under test: the broadcaster takes any JSON-serialisable
// snapshot, and pinning it to a type would defeat that. Field order is the
// order JSON.stringify emitted, because the assertion is on bytes.
type scanStatus struct {
	Phase        string         `json:"phase"`
	Profile      *string        `json:"profile"`
	Group        *string        `json:"group"`
	Hosts        []string       `json:"hosts"`
	File         *string        `json:"file"`
	StartedAt    *string        `json:"startedAt"`
	FinishedAt   *string        `json:"finishedAt"`
	Stats        *api.ScanStats `json:"stats"`
	Findings     []api.Finding  `json:"findings"`
	Log          string         `json:"log"`
	Error        *string        `json:"error"`
	Command      []string       `json:"command"`
	ExitCode     *int           `json:"exitCode"`
	Observations any            `json:"observations"`
	Output       []any          `json:"output"`
}

// idle is the snapshot the capture was taken against: a server that has not run
// anything yet.
func idle() scanStatus {
	return scanStatus{
		Phase:    "idle",
		Hosts:    []string{},
		Findings: []api.Finding{},
		Output:   []any{},
	}
}

// stream opens a live SSE connection to broadcaster and returns the body plus the
// cancel that plays the part of a browser closing the tab.
func stream(broadcaster *httpapi.Broadcaster) (*http.Response, context.CancelFunc) {
	server := httptest.NewServer(broadcaster)
	// Close blocks until every in-flight request has returned, so a handler that
	// outlived its client would hang the suite here rather than pass quietly.
	DeferCleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	DeferCleanup(cancel)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/scan/events", nil)
	Expect(err).ToNot(HaveOccurred())

	// A read that never completes should fail the spec, not hang it.
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(response.Body.Close)
	return response, cancel
}

func read(body io.Reader, count int) []byte {
	buffer := make([]byte, count)
	_, err := io.ReadFull(body, buffer)
	Expect(err).ToNot(HaveOccurred())
	return buffer
}

var _ = Describe("the scan event stream", func() {
	var broadcaster *httpapi.Broadcaster

	BeforeEach(func() {
		// An hour of keep-alive keeps the comment out of specs that assert on
		// frame bytes; the keep-alive spec sets its own interval.
		broadcaster = httpapi.NewBroadcaster(httpapi.BroadcasterOptions{KeepAlive: time.Hour})
	})

	Describe("the bytes on the wire", func() {
		It("reproduces the captured idle frame exactly", func() {
			// The capture is one whole frame and nothing else, so it can be
			// compared as a single byte string: the `data: ` prefix, compact JSON
			// with no event name, and the blank line that ends the event.
			want := golden("scan-events.txt")
			Expect(broadcaster.Publish(idle())).To(Succeed())

			response, _ := stream(broadcaster)
			Expect(read(response.Body, len(want))).To(Equal(want))
		})

		It("names no event, because onmessage only fires for unnamed ones", func() {
			want := golden("scan-events.txt")
			Expect(broadcaster.Publish(idle())).To(Succeed())

			response, _ := stream(broadcaster)
			frame := read(response.Body, len(want))
			Expect(frame).To(HavePrefix("data: "))
			Expect(string(frame)).ToNot(ContainSubstring("event:"))
			Expect(bytes.Count(frame, []byte("\n"))).To(Equal(2), "one data line, then the blank line")
		})

		It("leaves HTML-significant characters as the capture has them", func() {
			// The populated capture's log starts with a nuclei banner line, so
			// Go's default HTML escaping would rewrite bytes the browser has
			// been receiving unescaped all along.
			Expect(string(golden("scan-events-populated.txt"))).To(ContainSubstring(`"log":">>> nuclei full scan of 1 host(s)`))

			status := idle()
			status.Log = ">>> nuclei full scan of 1 host(s)"
			status.Error = ptr("bad <input> & worse")
			Expect(broadcaster.Publish(status)).To(Succeed())

			response, _ := stream(broadcaster)
			frame := string(read(response.Body, 260))
			Expect(frame).To(ContainSubstring(`"log":">>> nuclei full scan of 1 host(s)"`))
			Expect(frame).To(ContainSubstring(`"error":"bad <input> & worse"`))
			Expect(frame).ToNot(ContainSubstring("\\u003"), "Go's default HTML escaping must be off")
		})

		It("sets the headers the proxy and the browser both need", func() {
			response, _ := stream(broadcaster)
			Expect(response.Header.Get("Content-Type")).To(Equal("text/event-stream"))
			Expect(response.Header.Get("Cache-Control")).To(Equal("no-cache, no-transform"))
			// Without this the Vite dev proxy buffers everything until close.
			Expect(response.Header.Get("X-Accel-Buffering")).To(Equal("no"))
		})
	})

	Describe("what a client gets when it connects", func() {
		It("replays the last published snapshot immediately", func() {
			Expect(broadcaster.Publish(idle())).To(Succeed())
			running := idle()
			running.Phase = string(api.PhaseRunning)
			Expect(broadcaster.Publish(running)).To(Succeed())

			response, _ := stream(broadcaster)
			Expect(string(read(response.Body, 30))).To(HavePrefix(`data: {"phase":"running"`))
		})

		It("emits a keep-alive comment while nothing is happening", func() {
			broadcaster = httpapi.NewBroadcaster(httpapi.BroadcasterOptions{KeepAlive: 50 * time.Millisecond})

			// Nothing has been published, so the first bytes on the stream are
			// the comment itself.
			response, _ := stream(broadcaster)
			Expect(string(read(response.Body, len(": keep-alive\n\n")))).To(Equal(": keep-alive\n\n"))
		})
	})

	Describe("a slow client", func() {
		It("receives the newest snapshot and not the ones it missed", func() {
			// Driven through a writer that blocks inside Write, because a real
			// socket would swallow small frames into its buffer and never make
			// the handler wait.
			Expect(broadcaster.Publish(scan("first", api.PhaseIdle))).To(Succeed())

			writer := newGatedWriter()
			request := httptest.NewRequest(http.MethodGet, "/api/scan/events", nil)
			ctx, cancel := context.WithCancel(request.Context())
			DeferCleanup(cancel)

			served := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(served)
				broadcaster.ServeHTTP(writer, request.WithContext(ctx))
			}()

			// Receiving this means the handler has taken the frame off its
			// channel and is now stuck writing it.
			Expect(string(<-writer.writes)).To(ContainSubstring(`"name":"first"`))

			for _, name := range []string{"second", "third", "fourth"} {
				Expect(broadcaster.Publish(scan(name, api.PhaseRunning))).To(Succeed())
			}

			writer.release <- struct{}{}
			next := string(<-writer.writes)
			Expect(next).To(ContainSubstring(`"name":"fourth"`))
			Expect(next).ToNot(ContainSubstring(`"name":"second"`))
			Expect(next).ToNot(ContainSubstring(`"name":"third"`))

			writer.release <- struct{}{}
			cancel()
			Eventually(served).Should(BeClosed())
			Expect(broadcaster.Subscribers()).To(BeZero())
		})
	})

	Describe("a client that goes away", func() {
		It("drops the subscription and lets the handler return", func() {
			Expect(broadcaster.Publish(idle())).To(Succeed())

			response, disconnect := stream(broadcaster)
			read(response.Body, len("data: "))
			Expect(broadcaster.Subscribers()).To(Equal(1))

			disconnect()
			Eventually(broadcaster.Subscribers).Should(BeZero())

			// Publishing into a stream nobody is reading must not block the
			// producer, which is the failure this whole design exists to avoid.
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				for i := 0; i < 100; i++ {
					Expect(broadcaster.Publish(idle())).To(Succeed())
				}
			}()
			Eventually(done).Should(BeClosed())
			Expect(broadcaster.Subscribers()).To(BeZero())
		})
	})

	Describe("an unencodable snapshot", func() {
		It("is reported and published to nobody", func() {
			Expect(broadcaster.Publish(idle())).To(Succeed())
			Expect(broadcaster.Publish(make(chan int))).To(MatchError(ContainSubstring("encoding sse snapshot")))

			response, _ := stream(broadcaster)
			Expect(string(read(response.Body, 22))).To(Equal(`data: {"phase":"idle",`))
		})
	})
})

func ptr[T any](value T) *T { return &value }

// scan is a realistic snapshot from the type the scan runtime will own. The
// broadcaster never names it — this is only here so the specs stream something
// with the shape and size of the real thing.
func scan(name string, phase api.Phase) api.Scan {
	return api.Scan{
		ID:            name,
		Name:          name,
		Engine:        "nuclei",
		Profile:       "full",
		Selector:      map[string]any{"group": "non-prod"},
		SelectorLabel: "non-prod",
		EndpointCount: 1,
		Phase:         phase,
		StartedAt:     "2026-08-09T11:28:18.690Z",
		Hosts:         []string{"beta.example.test"},
		Severities:    map[string]int{"high": 0},
		Stats:         &api.ScanStats{Hosts: 1, Duration: "0:00:04"},
	}
}

// gatedWriter is a ResponseWriter whose Write hands the bytes over and then
// blocks until the spec releases it, which is how a client too slow to drain the
// socket behaves.
type gatedWriter struct {
	header  http.Header
	writes  chan []byte
	release chan struct{}
}

func newGatedWriter() *gatedWriter {
	return &gatedWriter{
		header: http.Header{},
		// Unbuffered so the handoff is exact: a receive proves the handler is
		// inside Write and cannot be draining its channel.
		writes:  make(chan []byte),
		release: make(chan struct{}),
	}
}

func (g *gatedWriter) Header() http.Header { return g.header }

func (g *gatedWriter) WriteHeader(int) {}

func (g *gatedWriter) Flush() {}

func (g *gatedWriter) Write(frame []byte) (int, error) {
	g.writes <- bytes.Clone(frame)
	<-g.release
	return len(frame), nil
}
