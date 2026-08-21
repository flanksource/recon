package entities

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	_ "github.com/flanksource/recon/internal/engines/all"
	"github.com/flanksource/recon/internal/store"
)

var _ = Describe("routing a scan by what its engine audits", func() {
	Describe("directScanSelector", func() {
		It("passes a provider-context stable ID straight to the scan runtime", func() {
			target, err := (runTarget{ID: []string{"gcp-prod"}}).resolve()
			Expect(err).ToNot(HaveOccurred())

			selector, direct, err := directScanSelector("prowler", target)

			Expect(err).ToNot(HaveOccurred())
			Expect(direct).To(BeTrue())
			Expect(selector).To(Equal(store.TargetOpts{IDs: []string{"gcp-prod"}}))
		})

		It("sends a cloud account engine down the direct path", func() {
			target, err := (runTarget{Host: []string{"acme-platform-prod"}}).resolve()
			Expect(err).ToNot(HaveOccurred())

			_, direct, err := directScanSelector("inspec", target)

			Expect(err).ToNot(HaveOccurred())
			Expect(direct).To(BeTrue())
		})

		It("leaves a network scanner on the discovery path", func() {
			target, err := (runTarget{Host: []string{"example.test"}}).resolve()
			Expect(err).ToNot(HaveOccurred())

			_, direct, err := directScanSelector("nuclei", target)

			Expect(err).ToNot(HaveOccurred())
			Expect(direct).To(BeFalse())
		})

		It("rejects network inputs for a provider-context scan", func() {
			target, err := (runTarget{Host: []string{"example.test"}}).resolve()
			Expect(err).ToNot(HaveOccurred())

			_, _, err = directScanSelector("prowler", target)

			Expect(err).To(MatchError(ContainSubstring("cannot name a provider context")))
		})

		It("reports an engine that is not registered", func() {
			_, _, err := directScanSelector("nmap", resolvedTarget{})

			Expect(err).To(MatchError(ContainSubstring("unknown scan engine")))
		})
	})

	Describe("accountSelector", func() {
		const project = "acme-platform-prod"

		It("passes an inventory selector through unchanged", func() {
			target, err := (runTarget{Class: []string{"prod"}}).resolve()
			Expect(err).ToNot(HaveOccurred())

			Expect(accountSelector(target)).To(Equal(target.Inventory))
		})

		It("turns an explicit host into a selector naming those accounts", func() {
			// On the endpoint path --host feeds discovery, which reports back
			// what it found. There is no such step here, so the names have to
			// become the selector directly or the run would match every account.
			target, err := (runTarget{Host: []string{project}}).resolve()
			Expect(err).ToNot(HaveOccurred())

			Expect(accountSelector(target)).To(Equal(store.TargetOpts{Hosts: []string{project}}))
		})

		DescribeTable("refuses input that names network addresses",
			func(target runTarget) {
				// Silently ignoring these would fall back to the empty selector
				// and audit the whole inventory instead of the nothing they name.
				resolved, err := target.resolve()
				Expect(err).ToNot(HaveOccurred())

				_, err = accountSelector(resolved)

				Expect(err).To(MatchError(ContainSubstring("cannot name a cloud account")))
			},
			Entry("a domain is enumerated by DNS", runTarget{Domain: []string{"example.test"}}),
			Entry("a CIDR is swept by port scan", runTarget{CIDR: []string{"192.0.2.0/24"}}),
		)
	})

	Describe("defaultProfile", func() {
		It("uses the engine's own default when none was named", func() {
			// "safe" is nuclei's name for its default and means nothing to a
			// compliance engine, so a flag default would be wrong for one of them.
			Expect(defaultProfile("inspec", "")).To(Equal("gcp-cis"))
			Expect(defaultProfile("nuclei", "")).To(Equal("safe"))
		})

		It("keeps a profile the caller named", func() {
			Expect(defaultProfile("nuclei", "full")).To(Equal("full"))
		})

		It("reports an engine that is not registered", func() {
			_, err := defaultProfile("nmap", "")

			Expect(err).To(MatchError(ContainSubstring("unknown scan engine")))
		})
	})
})
