package prowler

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines/scan/prowler/catalog"
)

var _ = Describe("Prowler template projection", func() {
	It("qualifies IDs and preserves provider check metadata", func() {
		checks := []catalog.Check{
			{
				Key: "gcp/shared_check", ID: "shared_check", Provider: "gcp", Title: "GCP check",
				Severity: "high", Service: "iam", SubService: "serviceaccounts",
				ResourceType: "iam.googleapis.com/ServiceAccount", ResourceGroup: "IAM",
				ResourceIDTemplate: "projects/{project}/serviceAccounts/{email}",
				Aliases:            []string{"legacy_gcp_check"}, Categories: []string{"identity-access"},
				CheckTypes: []string{"account-security"}, Risk: "A broad role can expose resources.",
				Remediation: catalog.Remediation{
					Text: "Use a narrow role.", URL: "https://example.test/gcp/check",
					Code: map[string]string{"cli": "gcloud example"},
				},
				DependsOn: []string{"gcp/prerequisite"}, RelatedTo: []string{"gcp/related"},
				Notes: "Requires IAM visibility.", Source: "prowler/providers/gcp/check.metadata.json",
			},
			{
				Key: "github/shared_check", ID: "shared_check", Provider: "github", Title: "GitHub check",
				Severity: "medium", Service: "organization", ResourceType: "GitHubOrganization",
				Risk: "Members can alter repositories.", Remediation: catalog.Remediation{Text: "Restrict members."},
				Source: "prowler/providers/github/check.metadata.json",
			},
		}

		documents := templateDocuments(checks)

		Expect([]string{documents[0].ID, documents[1].ID}).To(Equal([]string{
			"gcp/shared_check", "github/shared_check",
		}))
		Expect(documents[0].Provider).To(Equal("gcp"))
		Expect(documents[0].Risk).To(Equal("A broad role can expose resources."))
		Expect(documents[0].ResourceType).To(Equal("iam.googleapis.com/ServiceAccount"))
		Expect(documents[0].Metadata).To(Equal(map[string]any{
			"aliases":            []string{"legacy_gcp_check"},
			"subService":         "serviceaccounts",
			"resourceGroup":      "IAM",
			"resourceIdTemplate": "projects/{project}/serviceAccounts/{email}",
			"categories":         []string{"identity-access"},
			"checkTypes":         []string{"account-security"},
			"remediation": map[string]any{
				"text": "Use a narrow role.", "url": "https://example.test/gcp/check",
				"code": map[string]string{"cli": "gcloud example"},
			},
			"dependsOn": []string{"gcp/prerequisite"},
			"relatedTo": []string{"gcp/related"},
			"notes":     "Requires IAM visibility.",
		}))
		Expect(documents[1].Provider).To(Equal("github"))
		Expect(documents[1].Risk).To(Equal("Members can alter repositories."))
		Expect(documents[1].ResourceType).To(Equal("GitHubOrganization"))
	})
})
