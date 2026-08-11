package discovery

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("discovery profile sets", func() {
	It("uses the default profile for every engine when nothing is specified", func() {
		set, err := ParseProfiles(nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(set.Resolve([]string{"naabu", "httpx", "tlsx"})).To(Equal(map[string]string{
			"naabu": DefaultProfile, "httpx": DefaultProfile, "tlsx": DefaultProfile,
		}))
	})

	It("applies a bare name to every engine", func() {
		set, err := ParseProfiles([]string{"deep"})
		Expect(err).ToNot(HaveOccurred())
		Expect(set).To(Equal(ProfileSet{Base: "deep", Overrides: map[string]string{}}))
	})

	It("overrides one engine while the rest keep the base", func() {
		set, err := ParseProfiles([]string{"deep", "naabu=full-ports"})
		Expect(err).ToNot(HaveOccurred())
		Expect(set.Resolve([]string{"subfinder", "naabu", "httpx"})).To(Equal(map[string]string{
			"subfinder": "deep", "naabu": "full-ports", "httpx": "deep",
		}))
	})

	It("overrides several engines without a base", func() {
		set, err := ParseProfiles([]string{"naabu=full-ports", "httpx=slow"})
		Expect(err).ToNot(HaveOccurred())
		Expect(set.Resolve([]string{"naabu", "httpx", "tlsx"})).To(Equal(map[string]string{
			"naabu": "full-ports", "httpx": "slow", "tlsx": DefaultProfile,
		}))
	})

	It("ignores blank references rather than treating them as a profile named empty", func() {
		set, err := ParseProfiles([]string{"", "  ", "deep"})
		Expect(err).ToNot(HaveOccurred())
		Expect(set.Base).To(Equal("deep"))
	})

	It("accepts a base repeated verbatim, because it asks for the same run", func() {
		set, err := ParseProfiles([]string{"deep", "deep"})
		Expect(err).ToNot(HaveOccurred())
		Expect(set.Base).To(Equal("deep"))
	})

	It("rejects two different names that both claim every engine", func() {
		_, err := ParseProfiles([]string{"deep", "quick"})
		Expect(err).To(MatchError(ContainSubstring("both apply to every engine")))
	})

	It("rejects an engine assigned two different profiles", func() {
		_, err := ParseProfiles([]string{"naabu=full-ports", "naabu=quick"})
		Expect(err).To(MatchError(ContainSubstring("naabu is assigned")))
	})

	It("rejects an override for an engine discovery does not have", func() {
		_, err := ParseProfiles([]string{"nuclei=safe"})
		Expect(err).To(MatchError(ContainSubstring("nuclei")))
	})

	It("rejects an override that names no profile", func() {
		_, err := ParseProfiles([]string{"naabu="})
		Expect(err).To(MatchError(ContainSubstring("names no profile")))
	})

	It("renders a canonical reference list so equivalent requests share a run key", func() {
		unordered, err := ParseProfiles([]string{"tlsx=strict", "deep", "naabu=full-ports"})
		Expect(err).ToNot(HaveOccurred())
		Expect(unordered.Refs()).To(Equal([]string{"deep", "naabu=full-ports", "tlsx=strict"}))
	})
})
