package nuclei

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The traffic counters answer the question the findings cannot: a scan that
// reports nothing because every host was reachable and clean looks identical to
// one that reports nothing because every request was refused.
var _ = Describe("scan traffic statistics", func() {
	var traffic *httpStats

	BeforeEach(func() { traffic = newHTTPStats() })

	It("counts attempts by protocol and responses by status code", func() {
		traffic.Request("headers.yaml", "https://a.example.test", "http", nil)
		traffic.Request("headers.yaml", "https://b.example.test", "http", nil)
		traffic.Request("spf.yaml", "example.test", "dns", nil)
		traffic.RequestStatsLog("200", "HTTP/1.1 200 OK\r\n\r\nhello")
		traffic.RequestStatsLog("200", "HTTP/1.1 200 OK\r\n\r\nagain")
		traffic.RequestStatsLog("404", "HTTP/1.1 404 Not Found\r\n\r\n")

		stats := traffic.Snapshot()
		Expect(stats.Requests).To(Equal(3))
		Expect(stats.Protocols).To(Equal(map[string]int{"http": 2, "dns": 1}))
		Expect(stats.Responses).To(Equal(3))
		Expect(stats.StatusCodes).To(Equal(map[string]int{"200": 2, "404": 1}))
		Expect(stats.Failed).To(BeZero())
		Expect(stats.Errors).To(BeEmpty())
	})

	It("sums the bytes read off the wire", func() {
		first := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
		second := "HTTP/1.1 500 Internal Server Error\r\n\r\n"
		traffic.RequestStatsLog("200", first)
		traffic.RequestStatsLog("500", second)

		Expect(traffic.Snapshot().Bytes).To(BeEquivalentTo(len(first) + len(second)))
	})

	// Errors are keyed by kind, not by message. Nuclei's own tracker keys them
	// by the text of the error, so one unreachable estate contributes a distinct
	// key per address and the breakdown becomes unchartable.
	It("classifies failures into a bounded vocabulary", func() {
		refused := &net.OpError{
			Op: "dial", Net: "tcp",
			Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443},
			Err:  errors.New("connect: connection refused"),
		}
		for port := 1; port <= 3; port++ {
			traffic.Request("panel.yaml", fmt.Sprintf("https://host-%d.example.test", port), "http", refused)
		}
		traffic.Request("panel.yaml", "https://slow.example.test", "http", context.DeadlineExceeded)

		stats := traffic.Snapshot()
		Expect(stats.Requests).To(Equal(4))
		Expect(stats.Failed).To(Equal(4))
		Expect(stats.Errors).To(HaveLen(2), "one key per kind, not per address: %v", stats.Errors)
		Expect(total(stats.Errors)).To(Equal(4))
	})

	It("names the firewall that answered", func() {
		traffic.RequestStatsLog("403", "HTTP/1.1 403 Forbidden\r\n\r\n<title>Attention Required! | Cloudflare</title>")

		Expect(total(traffic.Snapshot().WAF)).To(Equal(1))
	})

	// Fingerprints are headers and block-page banners, so matching the whole
	// body would cost more than the scan without finding anything extra.
	It("only fingerprints the front of a response", func() {
		buried := strings.Repeat("x", wafScanLimit) + "Attention Required! | Cloudflare"
		traffic.RequestStatsLog("200", buried)

		Expect(traffic.Snapshot().WAF).To(BeEmpty())
	})

	It("survives the engine's worker pool writing to it at once", func() {
		var group sync.WaitGroup
		for worker := 0; worker < 8; worker++ {
			group.Add(1)
			go func() {
				defer group.Done()
				defer GinkgoRecover()
				for i := 0; i < 200; i++ {
					traffic.Request("t.yaml", "https://a.example.test", "http", nil)
					traffic.RequestStatsLog("200", "HTTP/1.1 200 OK\r\n\r\n")
				}
			}()
		}
		group.Wait()

		stats := traffic.Snapshot()
		Expect(stats.Requests).To(Equal(1600))
		Expect(stats.Responses).To(Equal(1600))
		Expect(stats.StatusCodes).To(Equal(map[string]int{"200": 1600}))
	})

	// The SDK wraps this writer and its own mock writer in a MultiWriter, which
	// answers ResultCount from the first writer reporting more than zero. A
	// non-zero answer here would mask the count of what the scan actually found.
	It("claims none of the results it is not counting", func() {
		Expect(traffic.ResultCount()).To(BeZero())
		Expect(traffic.Write(nil)).To(Succeed())
		Expect(traffic.WriteFailure(nil)).To(Succeed())
	})
})

func total(counts map[string]int) int {
	sum := 0
	for _, count := range counts {
		sum += count
	}
	return sum
}
