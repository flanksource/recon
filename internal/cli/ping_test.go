package cli

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/api"
	"github.com/flanksource/clicky/entity"
	"github.com/flanksource/clicky/task"
	"github.com/flanksource/commons/duration"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
)

var _ = Describe("reconctl ping", Ordered, func() {
	BeforeAll(func() {
		task.SetNoRender(true)
	})

	AfterAll(func() {
		clicky.ClearGlobalTasks()
		task.SetNoRender(false)
	})

	It("provides its own table schema and typed row", func() {
		result := PingResult{
			Up:           true,
			URL:          "https://example.test/health",
			IP:           "192.0.2.10",
			TLSCN:        "example.test",
			ResponseCode: http.StatusNoContent,
			ResponseTime: 1500 * time.Millisecond,
			ResponseSize: 2048,
		}

		Expect(result.Columns()).To(Equal([]api.ColumnDef{
			api.Column("up").Label("Up").Build(),
			api.Column("url").Label("URL").Build(),
			api.Column("ip").Label("IP").Build(),
			api.Column("tls_cn").Label("TLS CN").Build(),
			api.Column("response_code").Label("Response Code").Build(),
			api.Column("response_time").Label("Response Time").Build(),
			api.Column("response_size").Label("Response Size").Build(),
			api.Column("error").Label("Error").Build(),
		}))
		Expect(result.Row()).To(Equal(map[string]any{
			"up":            true,
			"url":           "https://example.test/health",
			"ip":            "192.0.2.10",
			"tls_cn":        "example.test",
			"response_code": http.StatusNoContent,
			"response_time": clicky.Human(1500 * time.Millisecond),
			"response_size": api.HumanizeBytes(2048),
			"error":         "",
		}))
	})

	It("normalizes supported targets and rejects invalid input", func() {
		targets, err := pingTargets([]string{"example.test/path", "HTTP://example.test/ready"})
		Expect(err).ToNot(HaveOccurred())
		Expect(targets).To(Equal([]string{
			"https://example.test/path",
			"http://example.test/path",
			"http://example.test/ready",
		}))

		for _, input := range []string{"ftp://example.test", "https://user:secret@example.test", "https:///missing-host"} {
			_, err := pingTargets([]string{input})
			Expect(err).To(HaveOccurred(), input)
		}
		_, err = pingTargets(nil)
		Expect(err).To(MatchError("no hosts or URLs supplied"))
	})

	It("registers a named command with Clicky formats for args and stdin", func(ctx SpecContext) {
		var finalRequests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redirect" {
				http.Redirect(w, r, "/final", http.StatusFound)
				return
			}
			finalRequests.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("healthy"))
		}))
		DeferCleanup(server.Close)

		originalRender := entity.RenderResult
		DeferCleanup(func() { entity.RenderResult = originalRender })
		var rendered any
		entity.RenderResult = func(result any) error {
			rendered = result
			return nil
		}

		root, ping := newPingTestCommand()
		Expect(ping.Flag("concurrency").DefValue).To(Equal("10"))
		Expect(ping.Flag("timeout").DefValue).To(Equal("3s"))
		Expect(ping.Flag("follow-redirects").DefValue).To(Equal("true"))
		for _, name := range []string{
			"format", "filter", "no-color", "dump-schema",
			"json", "yaml", "csv", "markdown", "pretty", "html", "pdf", "tree", "table",
		} {
			Expect(ping.Flag(name)).ToNot(BeNil(), name)
			Expect(root.Flag(name)).ToNot(BeNil(), name)
		}
		root.SetArgs([]string{"ping", server.URL})
		Expect(root.ExecuteContext(ctx)).To(Succeed())
		results, ok := rendered.([]PingResult)
		Expect(ok).To(BeTrue(), "NamedCommand must return []PingResult")
		Expect(results).To(HaveLen(1))
		Expect(results[0].ResponseCode).To(Equal(http.StatusOK))

		root, _ = newPingTestCommand()
		root.SetArgs([]string{"ping", server.URL + "/redirect"})
		Expect(root.ExecuteContext(ctx)).To(Succeed())
		results, ok = rendered.([]PingResult)
		Expect(ok).To(BeTrue())
		Expect(results[0].ResponseCode).To(Equal(http.StatusOK))

		root, _ = newPingTestCommand()
		root.SetArgs([]string{"ping", "--follow-redirects=false", server.URL + "/redirect"})
		Expect(root.ExecuteContext(ctx)).To(MatchError("1 of 1 probes failed"))
		failedResults, ok := rendered.(pingFailure)
		Expect(ok).To(BeTrue())
		Expect(failedResults[0].ResponseCode).To(Equal(http.StatusFound))
		Expect(failedResults[0].Up).To(BeFalse())

		read, write, err := os.Pipe()
		Expect(err).ToNot(HaveOccurred())
		previousStdin := os.Stdin
		DeferCleanup(func() {
			os.Stdin = previousStdin
			_ = read.Close()
			_ = write.Close()
		})
		_, err = write.WriteString(server.URL + "\n")
		Expect(err).ToNot(HaveOccurred())
		Expect(write.Close()).To(Succeed())
		os.Stdin = read

		root, _ = newPingTestCommand()
		root.SetArgs([]string{"ping"})
		Expect(root.ExecuteContext(ctx)).To(Succeed())
		results, ok = rendered.([]PingResult)
		Expect(ok).To(BeTrue(), "stdin NamedCommand must return []PingResult")
		Expect(results).To(HaveLen(1))
		Expect(finalRequests.Load()).To(Equal(int32(3)))
	})

	It("expands hosts and reports every probe in input order", func(ctx SpecContext) {
		var finalRequests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redirect" {
				http.Redirect(w, r, "/final", http.StatusFound)
				return
			}
			finalRequests.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("healthy"))
		}))
		DeferCleanup(server.Close)

		redirectURL := server.URL + "/redirect"
		bareHost := strings.TrimPrefix(server.URL, "http://")
		results, err := runPing(ctx, testPingOptions(redirectURL, bareHost))
		Expect(err).To(MatchError("1 of 3 probes failed"))
		Expect(api.TryTypedValue(err)).ToNot(BeNil(), "failed probes must remain renderable")
		jsonOutput, formatErr := clicky.Format(err, clicky.FormatOptions{JSON: true})
		Expect(formatErr).ToNot(HaveOccurred())
		Expect(strings.TrimSpace(jsonOutput)).To(HavePrefix("["), "failure JSON must retain the result-row array")
		Expect(finalRequests.Load()).To(Equal(int32(2)))
		Expect(results).To(HaveLen(3))
		Expect(results[0].URL).To(Equal(redirectURL))
		Expect(results[0].ResponseCode).To(Equal(http.StatusOK))
		Expect(results[1].URL).To(Equal("https://" + bareHost))
		Expect(results[1].Up).To(BeFalse())
		Expect(results[2].URL).To(Equal("http://" + bareHost))
		Expect(results[2].ResponseCode).To(Equal(http.StatusOK))
		Expect(results[2].IP).To(Equal("127.0.0.1"))
		Expect(results[2].ResponseSize).To(Equal(int64(len("healthy"))))
	})

	It("does not follow redirects when disabled", func(ctx SpecContext) {
		var finalRequests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redirect" {
				http.Redirect(w, r, "/final", http.StatusFound)
				return
			}
			finalRequests.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		DeferCleanup(server.Close)

		options := testPingOptions(server.URL + "/redirect")
		options.FollowRedirects = false
		results, err := runPing(ctx, options)
		Expect(err).To(MatchError("1 of 1 probes failed"))
		Expect(results).To(HaveLen(1))
		Expect(results[0].ResponseCode).To(Equal(http.StatusFound))
		Expect(results[0].Up).To(BeFalse())
		Expect(results[0].Error).To(ContainSubstring("HTTP status 302"))
		Expect(finalRequests.Load()).To(BeZero())
	})

	It("only considers 200 through 299 healthy", func(ctx SpecContext) {
		for _, test := range []struct {
			status int
			up     bool
		}{
			{status: 199, up: false},
			{status: http.StatusOK, up: true},
			{status: 299, up: true},
			{status: http.StatusMultipleChoices, up: false},
		} {
			Expect(isSuccessfulPingStatus(test.status)).To(Equal(test.up), "status %d", test.status)
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte("response"))
		}))
		DeferCleanup(server.Close)

		results, err := runPing(ctx, testPingOptions(server.URL))
		Expect(err).To(MatchError("1 of 1 probes failed"))
		Expect(results).To(HaveLen(1))
		Expect(results[0].Up).To(BeFalse())
		Expect(results[0].ResponseCode).To(Equal(http.StatusTeapot))
		Expect(results[0].ResponseSize).To(Equal(int64(len("response"))))
		Expect(results[0].Error).To(ContainSubstring("HTTP status 418"))
	})

	It("verifies TLS and returns a row before failing", func(ctx SpecContext) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		DeferCleanup(server.Close)

		results, err := runPing(ctx, testPingOptions(server.URL))
		Expect(err).To(MatchError("1 of 1 probes failed"))
		Expect(results).To(HaveLen(1))
		Expect(results[0].URL).To(Equal(server.URL))
		Expect(results[0].Error).To(ContainSubstring("certificate"))
	})

	It("enforces option validation and the per-probe timeout", func(ctx SpecContext) {
		options := testPingOptions("http://example.test")
		options.Concurrency = 0
		_, err := runPing(ctx, options)
		Expect(err).To(MatchError("concurrency must be greater than zero, got 0"))

		requestStarted := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			close(requestStarted)
			<-request.Context().Done()
		}))
		DeferCleanup(server.Close)

		started := time.Now()
		options = testPingOptions(server.URL)
		options.Timeout = duration.Duration(25 * time.Millisecond)
		results, err := runPing(ctx, options)
		Expect(requestStarted).To(BeClosed())
		Expect(err).To(MatchError("1 of 1 probes failed"))
		Expect(results[0].Error).To(ContainSubstring("deadline exceeded"))
		Expect(time.Since(started)).To(BeNumerically("<", time.Second))
	})

	It("extracts the TLS common name and socket IP", func() {
		state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{CommonName: "service.example.test"},
		}}}
		Expect(tlsCommonName(state)).To(Equal("service.example.test"))
		Expect(tlsCommonName(nil)).To(BeEmpty())
		Expect(addressIP("[2001:db8::10]:443")).To(Equal("2001:db8::10"))
	})
})

func testPingOptions(targets ...string) pingOptions {
	return pingOptions{
		Targets:         targets,
		Concurrency:     defaultPingConcurrency,
		Timeout:         duration.Duration(defaultPingTimeout),
		FollowRedirects: true,
	}
}

func newPingTestCommand() (*cobra.Command, *cobra.Command) {
	root := &cobra.Command{Use: "reconctl"}
	clicky.BindAllFlagsToCommand(root)
	root.PersistentPreRun = func(*cobra.Command, []string) { clicky.Flags.UseFlags() }
	return root, addPingCommand(root)
}
