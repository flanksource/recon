// Package httpapi serves the hand-written browser endpoints — the ones that are
// not generated from the command tree because they are not request/response.
//
// # Server configuration
//
// An http.Server serving this package's handler MUST leave WriteTimeout at zero.
// WriteTimeout is an absolute deadline on the whole response, not an idle
// timeout, so on a stream it fires mid-flight and truncates a frame in the
// middle of its JSON — the browser then reports a parse error rather than a
// disconnect. Use ReadHeaderTimeout to bound slow clients instead.
package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DefaultKeepAlive matches the TypeScript endpoint this replaces. Proxies and
// load balancers cut idle connections, and a scan can sit in one phase for
// minutes, so the stream has to say something even when nothing has changed.
const DefaultKeepAlive = 15 * time.Second

// BroadcasterOptions configures a Broadcaster.
type BroadcasterOptions struct {
	// KeepAlive is the comment interval. Zero means DefaultKeepAlive; tests
	// shorten it so a spec does not have to wait fifteen seconds.
	KeepAlive time.Duration
}

// Broadcaster fans scan snapshots out to every connected browser as
// server-sent events. It is the seam the scan runtime publishes through: give
// Publish any JSON-serialisable value and every open stream receives it. The
// snapshot type is deliberately not named here, so the runtime can evolve its
// wire type without touching the transport.
//
// The zero value is not usable; call NewBroadcaster.
type Broadcaster struct {
	keepAlive time.Duration

	mu   sync.Mutex
	subs map[*subscriber]struct{}
	// latest is replayed to a client the moment it connects. The TypeScript
	// endpoint called its listener with the current status on subscribe, and the
	// UI relies on that: it renders from the first frame rather than staying
	// blank until the scan next changes. Whatever wires this up must therefore
	// Publish the starting snapshot at startup.
	latest []byte
}

// NewBroadcaster returns a Broadcaster with no subscribers and no snapshot yet.
func NewBroadcaster(opts BroadcasterOptions) *Broadcaster {
	if opts.KeepAlive < 0 {
		panic(fmt.Sprintf("httpapi: negative keep-alive interval %s", opts.KeepAlive))
	}
	if opts.KeepAlive == 0 {
		opts.KeepAlive = DefaultKeepAlive
	}
	return &Broadcaster{keepAlive: opts.KeepAlive, subs: map[*subscriber]struct{}{}}
}

// Publish encodes v once and hands the frame to every open stream. It never
// blocks on a slow client. An unencodable snapshot is returned as an error and
// published to nobody, rather than being dropped quietly: a stream that silently
// stopped updating is indistinguishable from a scan that stopped running.
func (b *Broadcaster) Publish(v any) error {
	frame, err := encodeFrame(v)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.latest = frame
	for sub := range b.subs {
		sub.offer(frame)
	}
	return nil
}

// Subscribers is the number of open streams. Exposed so a caller can report it
// and so a test can assert a disconnected client was actually torn down.
func (b *Broadcaster) Subscribers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

// encodeFrame renders one snapshot as a single unnamed SSE event.
//
// Unnamed is not a style choice: the browser consumer reads the stream with
// EventSource.onmessage, which by specification only fires for events carrying
// no `event:` name. A named event would be delivered to the page and then
// dropped on the floor with nothing to show for it.
func encodeFrame(v any) ([]byte, error) {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	// JSON.stringify leaves <, > and & alone; Go escapes them by default. The
	// captured stream has a nuclei log line starting ">>> nuclei", which would
	// come out as >>> and no longer match the recorded bytes.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, fmt.Errorf("encoding sse snapshot: %w", err)
	}

	// Encode appends exactly one newline, and compact JSON contains none of its
	// own, so the payload is always a single `data:` line.
	payload := body.Bytes()[:body.Len()-1]

	frame := make([]byte, 0, len("data: ")+len(payload)+2)
	frame = append(frame, "data: "...)
	frame = append(frame, payload...)
	return append(frame, '\n', '\n'), nil
}

// subscriber is one connected stream.
type subscriber struct {
	frames chan []byte
}

// offer hands frame to a stream without ever blocking the publisher. The channel
// holds one frame, and a new frame replaces an undelivered older one instead of
// queueing behind it: every frame is a complete snapshot, so the dropped one
// carries nothing the newer one does not. Queueing would make a slow reader
// stall the scan, and would spend the backlog replaying states the user has
// already scrolled past.
func (s *subscriber) offer(frame []byte) {
	select {
	case s.frames <- frame:
		return
	default:
	}
	select {
	case <-s.frames:
	default:
	}
	select {
	case s.frames <- frame:
	default:
	}
}

func (b *Broadcaster) subscribe() *subscriber {
	sub := &subscriber{frames: make(chan []byte, 1)}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.latest != nil {
		sub.frames <- b.latest
	}
	b.subs[sub] = struct{}{}
	return sub
}

func (b *Broadcaster) unsubscribe(sub *subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subs, sub)
}

// ServeHTTP streams snapshots until the client goes away. See the package
// comment: the http.Server running this must have no WriteTimeout.
func (b *Broadcaster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache, no-transform")
	// Without this the Vite dev proxy buffers the whole response and the browser
	// sees nothing until the connection closes — which, for a stream that stays
	// open, is never. nginx honours it the same way.
	header.Set("X-Accel-Buffering", "no")
	// Connection is hop-by-hop and net/http owns it; setting it here would only
	// confuse the transport.
	w.WriteHeader(http.StatusOK)
	// Flush the headers now so the client's EventSource opens immediately rather
	// than waiting for the first snapshot.
	flusher.Flush()

	sub := b.subscribe()
	defer b.unsubscribe(sub)

	keepAlive := time.NewTicker(b.keepAlive)
	defer keepAlive.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-sub.frames:
			if _, err := w.Write(frame); err != nil {
				return
			}
		case <-keepAlive.C:
			// A comment line: the browser parses and discards it, which is all it
			// is for. It keeps the connection accounted for as active.
			if _, err := io.WriteString(w, ": keep-alive\n\n"); err != nil {
				return
			}
		}
		// Every frame is flushed on its own. Buffering two together would make
		// progress arrive in bursts, which is exactly what the stream exists to
		// avoid.
		flusher.Flush()
	}
}
