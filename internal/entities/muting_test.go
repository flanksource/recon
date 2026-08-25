package entities

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

var _ = Describe("entity mute rules", func() {
	finding := api.Finding{
		CheckID: "gcp-bucket-public-access",
		Host:    "project-prod",
		Resources: []api.ResourceRef{{
			Provider: "gcp", Scope: "project-prod", UID: "logs-bucket",
		}},
	}

	DescribeTable("builds finding scopes",
		func(scope string, expected api.MuteRule) {
			rule, err := findingMuteRule(finding, "prowler", findingMuteFlags{Name: "mute-public", Scope: scope})
			Expect(err).ToNot(HaveOccurred())
			Expect(rule).To(Equal(expected))
		},
		Entry("check on resource", muteScopeCheckOnResource, api.MuteRule{
			Name: "mute-public", Engines: api.StringList{"prowler"},
			Templates:    api.StringList{"gcp-bucket-public-access"},
			ResourceKeys: api.StringList{"gcp/project-prod/logs-bucket"},
		}),
		Entry("check on host", muteScopeCheckOnHost, api.MuteRule{
			Name: "mute-public", Engines: api.StringList{"prowler"},
			Templates: api.StringList{"gcp-bucket-public-access"}, Resources: api.StringList{"project-prod"},
		}),
		Entry("check anywhere", muteScopeCheckAnywhere, api.MuteRule{
			Name: "mute-public", Engines: api.StringList{"prowler"},
			Templates: api.StringList{"gcp-bucket-public-access"},
		}),
		Entry("anything on resource", muteScopeAnythingOnResource, api.MuteRule{
			Name: "mute-public", Engines: api.StringList{"prowler"},
			ResourceKeys: api.StringList{"gcp/project-prod/logs-bucket"},
		}),
	)

	It("refuses resource scopes when the finding has no canonical resource", func() {
		_, err := findingMuteRule(api.Finding{CheckID: "check"}, "nuclei", findingMuteFlags{
			Name: "missing-resource", Scope: muteScopeCheckOnResource,
		})
		Expect(err).To(MatchError(ContainSubstring("canonical resource")))
	})

	// The shape a persisted prowler finding used to come back in. Reading a
	// finding out of the database rebuilt its references from the stored OCSF
	// record, which names a uid and leaves the account at the event level — so
	// the reference arrived with no provider and no scope, and the key it should
	// have produced could not be formed. Nothing errored on the way; muting a
	// resource simply stopped working for anything already stored.
	//
	// Refusing it here is what makes that loud. The store supplies the whole key
	// now, by joining finding_resources; this pins that a partial one is not
	// quietly turned into a rule that would match nothing.
	It("refuses a reference that names a uid but no provider", func() {
		_, err := findingMuteRule(api.Finding{
			CheckID:   "gcp-bucket-public-access",
			Resources: []api.ResourceRef{{UID: "logs-bucket", Name: "logs"}},
		}, "prowler", findingMuteFlags{Name: "partial-key", Scope: muteScopeCheckOnResource})

		Expect(err).To(MatchError(ContainSubstring("provider is required")))
	})

	It("builds a resource action from the canonical resource identity", func() {
		rule, err := resourceMuteRule(api.Resource{
			Provider: "aws", Scope: "123456789012", UID: "arn:aws:s3:::logs",
		}, resourceMuteFlags{Name: "mute-logs", Comment: "accepted"})
		Expect(err).ToNot(HaveOccurred())
		Expect(rule).To(Equal(api.MuteRule{
			Name: "mute-logs", Comment: "accepted",
			ResourceKeys: api.StringList{"aws/123456789012/arn:aws:s3:::logs"},
		}))
	})
})
