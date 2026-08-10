package entities

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("run targeting", func() {
	It("uses an empty target as the whole inventory", func() {
		target, err := (runTarget{}).resolve()
		Expect(err).ToNot(HaveOccurred())
		Expect(target.explicit()).To(BeFalse())
		Expect(target.Inventory.Empty()).To(BeTrue())
	})

	It("accepts mixed explicit hosts, domains and CIDRs", func() {
		target, err := (runTarget{
			Host:   []string{"api.example.test", "192.0.2.10", "api.example.test"},
			Domain: []string{"example.test"},
			CIDR:   []string{"192.0.2.0/24"},
		}).resolve()
		Expect(err).ToNot(HaveOccurred())
		Expect(target.Hosts).To(Equal([]string{"192.0.2.10", "api.example.test"}))
		Expect(target.Domains).To(Equal([]string{"example.test"}))
		Expect(target.CIDRs).To(Equal([]string{"192.0.2.0/24"}))
		Expect(target.explicit()).To(BeTrue())
	})

	It("rejects inventory selectors mixed with explicit discovery input", func() {
		_, err := (runTarget{
			Selector: "env=prod",
			Host:     []string{"api.example.test"},
		}).resolve()
		Expect(err).To(MatchError(ContainSubstring("cannot combine --selector")))
	})

	It("rejects malformed CIDRs at the command boundary", func() {
		_, err := (runTarget{CIDR: []string{"192.0.2.1"}}).resolve()
		Expect(err).To(MatchError(ContainSubstring("invalid CIDR")))
	})

	It("rejects malformed Kubernetes selectors at the command boundary", func() {
		_, err := (runTarget{Selector: "env in ("}).resolve()
		Expect(err).To(MatchError(ContainSubstring("invalid selector")))
	})

	It("keeps tag filters in inventory-selection mode", func() {
		target, err := (runTarget{Tags: []string{"team=platform"}}).resolve()
		Expect(err).ToNot(HaveOccurred())
		Expect(target.Inventory.Tags).To(Equal([]string{"team=platform"}))
		Expect(target.explicit()).To(BeFalse())
	})

	It("refuses to turn empty explicit discovery into a whole-inventory scan", func() {
		_, err := scanSelectorFromDiscovery(nil)
		Expect(err).To(MatchError("explicit discovery found no targets to scan"))
	})

	It("selects only the hosts returned by explicit discovery", func() {
		selector, err := scanSelectorFromDiscovery([]string{"api.example.test", "api.example.test", "web.example.test"})
		Expect(err).ToNot(HaveOccurred())
		Expect(selector.Hosts).To(Equal([]string{"api.example.test", "web.example.test"}))
	})
})
