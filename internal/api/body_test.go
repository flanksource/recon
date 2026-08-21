package api_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

// Creating a target is the one operation that settles what a target *is*: the
// host and the kind are fixed here and never editable afterwards. Everything
// below is about that boundary — what a create accepts, and what it refuses so
// that a caller finds out rather than getting a target that is quietly the
// wrong shape.
var _ = Describe("creating a target", func() {
	Describe("identity", func() {
		It("takes the host under the name a JSON body uses", func() {
			target, err := api.TargetFrom(map[string]any{
				"host": "a.example.test", "class": "non-prod", "profiles": "safe",
			})

			Expect(err).ToNot(HaveOccurred())
			Expect(target.Host).To(Equal("a.example.test"))
		})

		It("takes it under the name the entity framework uses", func() {
			// The same operation is reachable as a CLI argument and as an HTTP
			// body, and the flag mapping calls the identity `id`. Disagreeing
			// about which is authoritative would make one surface create nothing.
			target, err := api.TargetFrom(map[string]any{
				"id": "a.example.test", "class": "non-prod", "profiles": "safe",
			})

			Expect(err).ToNot(HaveOccurred())
			Expect(target.Host).To(Equal("a.example.test"))
		})

		It("keeps provider arguments absent on a host", func() {
			target, err := api.TargetFrom(map[string]any{
				"host": "a.example.test", "class": "non-prod", "profiles": "safe",
			})

			Expect(err).ToNot(HaveOccurred())
			Expect(target.Arguments).To(BeNil())
		})

		It("refuses a body with no host at all", func() {
			_, err := api.TargetFrom(map[string]any{"class": "non-prod"})

			Expect(err).To(MatchError(ContainSubstring("host is required")))
		})
	})

	Describe("kind", func() {
		It("defaults to host when the body does not say", func() {
			// Absent-means-host is what keeps every document written before
			// cloud accounts existed a valid host document.
			target, err := api.TargetFrom(map[string]any{
				"host": "a.example.test", "class": "non-prod", "profiles": "safe",
			})

			Expect(err).ToNot(HaveOccurred())
			Expect(target.Kind).To(Equal(api.KindHost))
		})

		It("accepts a provider context without an address", func() {
			target, err := api.TargetFrom(map[string]any{
				"id": "gcp-production", "kind": "provider-context", "provider": "gcp",
				"credentialMode": "ambient", "arguments": map[string]any{},
				"class": "non-prod", "profiles": "scan:prowler:gcp-cis-5-0",
			})

			Expect(err).ToNot(HaveOccurred())
			Expect(target.Kind).To(Equal(api.KindProviderContext))
			Expect(target.Host).To(BeEmpty())
		})

		It("refuses a kind nothing knows how to reach", func() {
			// Accepting it would put a row in the inventory that no engine has a
			// transport for, and nothing downstream would ever say so.
			_, err := api.TargetFrom(map[string]any{
				"host": "acme-thing", "kind": "aws-account", "class": "prod", "profiles": "safe",
			})

			Expect(err).To(MatchError(ContainSubstring(`unknown kind "aws-account"`)))
			Expect(err).To(MatchError(ContainSubstring("provider-context")), "the message should name what is valid")
		})

		It("refuses a kind that is not a string", func() {
			_, err := api.TargetFrom(map[string]any{
				"host": "acme-thing", "kind": 7, "class": "prod", "profiles": "safe",
			})

			Expect(err).To(MatchError(ContainSubstring("kind must be a string")))
		})
	})

	Describe("ports", func() {
		It("keeps them on a host, which is the only kind that has any", func() {
			target, err := api.TargetFrom(map[string]any{
				"host": "a.example.test", "class": "non-prod",
				"profiles": "safe", "ports": []any{443},
			})

			Expect(err).ToNot(HaveOccurred())
			Expect(target.Curated.Ports).To(Equal(api.IntList{443}))
		})

		It("refuses them on a provider context", func() {
			_, err := api.TargetFrom(map[string]any{
				"id": "gcp-production", "kind": "provider-context", "provider": "gcp",
				"credentialMode": "ambient", "arguments": map[string]any{},
				"class": "prod", "profiles": "scan:prowler:gcp-cis-5-0", "ports": []any{443},
			})

			Expect(err).To(MatchError(ContainSubstring("a provider-context has no ports")))
			Expect(err).To(MatchError(ContainSubstring("provider API")))
		})
	})

	Describe("what an edit may not touch", func() {
		It("refuses to change the host", func() {
			_, err := api.CuratedFrom(map[string]any{"host": "b.example.test", "class": "prod"})

			Expect(err).To(MatchError(ContainSubstring("host is not editable")))
		})

		It("refuses to change the kind", func() {
			// A curated update replaces the editable fields wholesale, so an
			// omitted kind would turn a cloud account back into a hostname.
			_, err := api.CuratedFrom(map[string]any{"kind": "host", "class": "prod"})

			Expect(err).To(MatchError(ContainSubstring("kind is not editable")))
		})

		DescribeTable("refuses to write a machine-owned section",
			func(section string) {
				_, err := api.CuratedFrom(map[string]any{section: map[string]any{}, "class": "prod"})

				Expect(err).To(MatchError(ContainSubstring(section + " is not editable")))
			},
			Entry("observed", "observed"),
			Entry("network", "network"),
			Entry("http", "http"),
			Entry("tech", "tech"),
			Entry("tls", "tls"),
			Entry("scan", "scan"),
		)

		It("refuses a field that is not a field, rather than ignoring it", func() {
			_, err := api.CuratedFrom(map[string]any{"clazz": "prod"})

			Expect(err).To(MatchError(ContainSubstring("invalid body")))
		})
	})
})

// The kind vocabulary answers two questions that are not each other's inverse,
// which is the whole reason it is a table rather than a predicate.
var _ = Describe("what a kind can have done to it", func() {
	DescribeTable("reachability",
		func(kind api.TargetKind, addressable, providerContext bool) {
			Expect(kind.Addressable()).To(Equal(addressable), "addressable")
			Expect(kind.ProviderContext()).To(Equal(providerContext), "provider context")
		},
		Entry("a host is contacted over the network", api.KindHost, true, false),
		Entry("an absent kind means host", api.TargetKind(""), true, false),
		Entry("a provider context is audited through an API", api.KindProviderContext, false, true),
		Entry("a kind nothing recognises is neither", api.TargetKind("aws-account"), false, false),
	)

	It("resolves the absent-means-host default when rendered", func() {
		// Stored and displayed values go through String, so the default lives in
		// one place rather than at every call site.
		Expect(api.TargetKind("").String()).To(Equal("host"))
		Expect(api.KindProviderContext.String()).To(Equal("provider-context"))
	})
})
