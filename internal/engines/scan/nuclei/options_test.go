package nuclei

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("mapping a profile onto nuclei's options", func() {
	It("handles every option the catalog offers", func() {
		// The catalog is what the profile form renders and what the store
		// validates against, so a key present there and absent here is a field
		// the user can set, the server accepts, and the scan ignores. Without
		// this the mismatch is invisible until someone wonders why their
		// severity filter did nothing.
		var unmapped []string
		for _, key := range CatalogKeys() {
			_, mapped := options[key]
			_, runtime := runtimeKeys[key]
			if !mapped && !runtime {
				unmapped = append(unmapped, key)
			}
		}

		Expect(unmapped).To(BeEmpty(),
			"catalog keys with no effect on a scan")
	})

	It("maps nothing the catalog does not offer", func() {
		catalogued := map[string]bool{}
		for _, key := range CatalogKeys() {
			catalogued[key] = true
		}

		var orphaned []string
		for key := range options {
			if !catalogued[key] {
				orphaned = append(orphaned, key)
			}
		}

		Expect(orphaned).To(BeEmpty(),
			"options nothing can set, because the catalog does not declare them")
	})

	It("translates filters, counts and lists onto the fields nuclei reads", func() {
		opts, err := Options(map[string]any{
			"tags":        []any{"k8s", "kubernetes"},
			"severity":    []any{"critical", "high"},
			"type":        []any{"http", "dns"},
			"rate-limit":  50,
			"concurrency": 25,
			"templates":   []any{"dast/"},
			"dast":        true,
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(opts.Tags).To(ConsistOf("k8s", "kubernetes"))
		Expect(opts.Severities.String()).To(Equal("critical, high"))
		Expect(opts.Protocols.String()).To(Equal("http, dns"))
		Expect(opts.RateLimit).To(Equal(50))
		Expect(opts.TemplateThreads).To(Equal(25))
		Expect(opts.Templates).To(ConsistOf("dast/"))
		Expect(opts.DAST).To(BeTrue())
	})

	It("accepts the JSON shapes an edited profile arrives as", func() {
		// A profile saved through the API is decoded JSON: numbers are float64
		// and lists are []any. One saved from a Go literal is neither.
		opts, err := Options(map[string]any{
			"rate-limit": float64(150),
			"header":     []any{"X-Scan: recon"},
			"timeout":    float64(10),
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(opts.RateLimit).To(Equal(150))
		Expect(opts.Timeout).To(Equal(10))
		Expect(opts.CustomHeaders).To(ConsistOf("X-Scan: recon"))
	})

	It("rejects a value of the wrong shape rather than ignoring it", func() {
		_, err := Options(map[string]any{"rate-limit": "fast"})

		Expect(err).To(MatchError(ContainSubstring("rate-limit")))
	})

	It("excludes the dangerous tags whatever the profile says", func() {
		// The command line appended -exclude-tags last so a profile could not
		// re-enable a denial-of-service template. Nothing about that guarantee
		// changed when the flags did.
		opts, err := Options(map[string]any{"exclude-tags": []any{"azure"}})

		Expect(err).ToNot(HaveOccurred())
		Expect(opts.ExcludeTags).To(ContainElements("azure", "dos", "fuzz", "bruteforce", "intrusive"))
	})

	It("applies the excludes even to a profile that sets none", func() {
		opts, err := Options(map[string]any{})

		Expect(err).ToNot(HaveOccurred())
		Expect(opts.ExcludeTags).To(ContainElements("dos", "fuzz", "bruteforce", "intrusive"))
	})

	It("leaves nuclei's own default alone for a false boolean", func() {
		// A false boolean means "do not set the flag", matching how the command
		// line worked: presence was the switch.
		opts, err := Options(map[string]any{"headless": false, "dast": false})

		Expect(err).ToNot(HaveOccurred())
		Expect(opts.Headless).To(BeFalse())
		Expect(opts.DAST).To(BeFalse())
	})

	It("reads max-time as a deadline rather than an option", func() {
		// It is a process soft-kill on the command line and has no field to set.
		opts, err := Options(map[string]any{"max-time": "30m"})

		Expect(err).ToNot(HaveOccurred())
		Expect(opts).ToNot(BeNil())
	})
})
