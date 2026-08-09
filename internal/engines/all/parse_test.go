package all_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines/discovery"
)

// collect runs a registered engine's parser over body and returns what it
// emitted. Going through the registry rather than the concrete type is
// deliberate: it is the registry the runtime will use.
func collect(engine, body string) ([]discovery.Record, error) {
	found, err := discovery.Get(engine)
	Expect(err).ToNot(HaveOccurred())

	var records []discovery.Record
	err = found.Parse(strings.NewReader(body), func(r discovery.Record) error {
		records = append(records, r)
		return nil
	})
	return records, err
}

var _ = Describe("discovery output parsing", func() {
	// Every engine attributes its output to a host, and every one of them names
	// that host differently. Getting this wrong misfiles an observation against
	// the wrong target, which is worse than dropping it.
	DescribeTable("attributes a record to a host",
		func(engine, body, host string) {
			records, err := collect(engine, body)
			Expect(err).ToNot(HaveOccurred())
			Expect(records).To(HaveLen(1))
			Expect(records[0].Host).To(Equal(host))
			Expect(records[0].Fields).To(HaveKeyWithValue("input", host))
		},
		Entry("dnsx uses the queried host",
			"dnsx", `{"host":"a.example.test","a":["192.0.2.1"]}`, "a.example.test"),
		Entry("httpx prefers input over url",
			"httpx", `{"input":"b.example.test","url":"https://redirected.example.test"}`, "b.example.test"),
		Entry("httpx falls back to url",
			"httpx", `{"url":"https://c.example.test:8443/path"}`, "c.example.test"),
		Entry("tlsx strips the port",
			"tlsx", `{"host":"d.example.test","port":"443","tls_version":"tls13"}`, "d.example.test"),
		Entry("katana takes the host from the crawled endpoint",
			"katana", `{"request":{"method":"GET","endpoint":"https://e.example.test/admin"}}`, "e.example.test"),
	)

	It("naabu reports the open port and a joined endpoint", func() {
		records, err := collect("naabu", `{"host":"f.example.test","ip":"192.0.2.9","port":8443}`)
		Expect(err).ToNot(HaveOccurred())
		Expect(records[0].Host).To(Equal("f.example.test"))
		Expect(records[0].Fields).To(HaveKeyWithValue("port", 8443))
		Expect(records[0].Fields).To(HaveKeyWithValue("endpoint", "f.example.test:8443"))
	})

	It("naabu falls back to the address when a scan had no hostname", func() {
		records, err := collect("naabu", `{"ip":"192.0.2.9","port":443}`)
		Expect(err).ToNot(HaveOccurred())
		Expect(records[0].Host).To(Equal("192.0.2.9"))
	})

	It("naabu rejects a port outside the valid range", func() {
		_, err := collect("naabu", `{"host":"g.example.test","port":70000}`)
		Expect(err).To(MatchError(ContainSubstring("out of range")))
	})

	It("subfinder reads plain hostnames and ignores blank lines", func() {
		records, err := collect("subfinder", "h.example.test\n\ni.example.test\n")
		Expect(err).ToNot(HaveOccurred())
		Expect([]string{records[0].Host, records[1].Host}).
			To(Equal([]string{"h.example.test", "i.example.test"}))
	})

	It("httpx drops the bodies and headers it is not allowed to persist", func() {
		// A redirect chain puts cookies in raw_header; nothing downstream reads
		// any of this, so it must not reach the inventory.
		records, err := collect("httpx", `{"input":"j.example.test","status_code":200,`+
			`"header":{"set-cookie":"session=secret"},"raw_header":"HTTP/1.1 200 OK",`+
			`"request":"GET / HTTP/1.1","response":"<html>","body":"<html>"}`)
		Expect(err).ToNot(HaveOccurred())

		Expect(records[0].Fields).To(HaveKeyWithValue("status_code", BeNumerically("==", 200)))
		for _, key := range []string{"header", "raw_header", "request", "response", "body"} {
			Expect(records[0].Fields).ToNot(HaveKey(key))
		}
	})

	It("tlsx nests certificate data where the normaliser expects it", func() {
		// httpx reports these under `tls`; tlsx reports them at the top level.
		// Reshaping in the engine is what lets one normaliser handle both.
		records, err := collect("tlsx",
			`{"host":"k.example.test","port":"443","tls_version":"tls13","expired":false}`)
		Expect(err).ToNot(HaveOccurred())

		Expect(records[0].Fields).To(HaveKey("tls"))
		Expect(records[0].Fields["tls"]).To(HaveKeyWithValue("tls_version", "tls13"))
		Expect(records[0].Fields["tls"]).ToNot(HaveKey("host"))
	})

	It("katana ignores crawl events that are not endpoints", func() {
		records, err := collect("katana",
			`{"timestamp":"2026-01-01T00:00:00Z"}`+"\n"+
				`{"request":{"method":"GET","endpoint":"https://l.example.test/"}}`)
		Expect(err).ToNot(HaveOccurred())
		Expect(records).To(HaveLen(1))
	})

	It("dnsx keeps only the record types it found", func() {
		records, err := collect("dnsx",
			`{"host":"m.example.test","a":["192.0.2.1"],"cname":["target.example.test"]}`)
		Expect(err).ToNot(HaveOccurred())

		Expect(records[0].Fields).To(HaveKeyWithValue("cname", ConsistOf("target.example.test")))
		Expect(records[0].Fields).ToNot(HaveKey("mx"), "an empty result must not become an empty list")
	})

	DescribeTable("refuses a record it cannot attribute to a host",
		func(engine, body string) {
			_, err := collect(engine, body)
			Expect(err).To(HaveOccurred())
		},
		Entry("dnsx", "dnsx", `{"a":["192.0.2.1"]}`),
		Entry("httpx", "httpx", `{"status_code":200}`),
		Entry("tlsx", "tlsx", `{"port":"443"}`),
		Entry("naabu", "naabu", `{"port":443}`),
	)
})
