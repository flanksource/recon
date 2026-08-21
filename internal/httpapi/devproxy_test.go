package httpapi_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/httpapi"
)

var _ = Describe("serving the interface from a dev server", func() {
	// A stand-in for Vite: it reports what it was asked for, so the assertions
	// are about what the proxy forwarded rather than about Vite's own output.
	newUpstream := func() (*httptest.Server, *http.Request) {
		var seen http.Request
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = *r
			w.Header().Set("content-type", "text/javascript")
			_, _ = w.Write([]byte("export const path = " + r.URL.Path))
		}))
		DeferCleanup(server.Close)
		return server, &seen
	}

	proxyTo := func(server *httptest.Server) http.Handler {
		target, err := url.Parse(server.URL)
		Expect(err).ToNot(HaveOccurred())
		return httpapi.DevProxy(target)
	}

	It("passes the module request through and returns what the dev server served", func() {
		upstream, seen := newUpstream()

		recorder := httptest.NewRecorder()
		proxyTo(upstream).ServeHTTP(recorder,
			httptest.NewRequest(http.MethodGet, "/src/main.tsx", nil))

		Expect(recorder.Code).To(Equal(http.StatusOK))
		Expect(recorder.Body.String()).To(Equal("export const path = /src/main.tsx"))
		Expect(recorder.Header().Get("content-type")).To(Equal("text/javascript"))
		Expect(seen.URL.Path).To(Equal("/src/main.tsx"))
	})

	// Vite rejects a request whose Host it does not recognise, and it is reached
	// on a different port than the one the browser asked for.
	It("rewrites Host to the dev server rather than forwarding the browser's", func() {
		upstream, seen := newUpstream()

		request := httptest.NewRequest(http.MethodGet, "/@vite/client", nil)
		request.Host = "localhost:8280"
		proxyTo(upstream).ServeHTTP(httptest.NewRecorder(), request)

		Expect(seen.Host).ToNot(Equal("localhost:8280"))
		Expect(seen.Host).To(Equal(upstream.Listener.Addr().String()))
	})

	// A dev server killed mid-session must not read as a broken application.
	It("names the unreachable dev server instead of an empty 502", func() {
		upstream, _ := newUpstream()
		handler := proxyTo(upstream)
		upstream.Close()

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

		Expect(recorder.Code).To(Equal(http.StatusBadGateway))
		body, err := io.ReadAll(recorder.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(ContainSubstring("vite dev server at " + upstream.URL))
		Expect(string(body)).To(ContainSubstring("is not answering"))
	})
})
