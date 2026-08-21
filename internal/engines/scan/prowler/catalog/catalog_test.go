package catalog_test

import (
	"encoding/hex"
	"testing/fstest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines/scan/prowler/catalog"
)

var _ = Describe("Prowler catalogue", func() {
	It("loads the generated embedded catalogue", func() {
		loaded, err := catalog.Embedded()
		Expect(err).NotTo(HaveOccurred())
		Expect(loaded.ValidatePinned()).To(Succeed())
		Expect(loaded.Manifest.Digest).NotTo(BeEmpty())
	})

	It("matches the pinned upstream corpus", func() {
		loaded, err := catalog.Load("../../../../../third_party/prowler")
		Expect(err).NotTo(HaveOccurred())
		Expect(loaded.Manifest).To(Equal(catalog.Manifest{
			Version:                catalog.ProwlerVersion,
			SourceCommit:           catalog.PinnedCommit,
			ProviderCount:          23,
			StaticProviderCount:    20,
			DynamicProviderCount:   3,
			CheckCount:             1586,
			ComplianceFileCount:    111,
			ProfileProjectionCount: 141,
			Digest:                 loaded.Manifest.Digest,
		}))
		Expect(loaded.CheckIDs("e2enetworks")).To(HaveLen(27))
		Expect(loaded.ComplianceIDs("e2enetworks")).To(BeEmpty())
		for _, provider := range []string{"iac", "image", "llm"} {
			entry, ok := loaded.Provider(provider)
			Expect(ok).To(BeTrue(), provider)
			Expect(entry.Static).To(BeFalse(), provider)
		}
	})

	It("normalizes provider and shared compliance families", func() {
		loaded, err := catalog.LoadFS(upstreamFixture())
		Expect(err).NotTo(HaveOccurred())

		Expect(loaded.Manifest).To(Equal(catalog.Manifest{
			Version:                catalog.ProwlerVersion,
			SourceCommit:           catalog.PinnedCommit,
			ProviderCount:          6,
			StaticProviderCount:    3,
			DynamicProviderCount:   3,
			CheckCount:             3,
			ComplianceFileCount:    2,
			ProfileProjectionCount: 3,
			Digest:                 loaded.Manifest.Digest,
		}))
		Expect(loaded.ProviderIDs()).To(Equal([]string{"aws", "e2enetworks", "gcp", "iac", "image", "llm"}))

		profile, ok := loaded.Profile("gcp", "cis_5.0_gcp")
		Expect(ok).To(BeTrue())
		Expect(profile.Name).To(Equal("gcp-cis-5-0-gcp"))
		Expect(profile.CheckKeys).To(Equal([]string{"gcp/iam_sa_no_user_managed_keys"}))
		Expect(profile.Controls).To(HaveLen(2))
		Expect(profile.Controls[1].ID).To(Equal("1.2"))
		Expect(profile.Controls[1].AssessmentStatus).To(Equal("Manual"))
		Expect(profile.Controls[1].CheckKeys).To(BeEmpty())
		Expect(profile.ManualControls).To(Equal(1))
		Expect(profile.UnmappedControls).To(Equal(1))
		Expect(profile.Config()).To(Equal(map[string]any{
			"provider":   "gcp",
			"compliance": []any{"cis_5.0_gcp"},
		}))

		shared, ok := loaded.Profile("gcp", "cis_controls_8.1")
		Expect(ok).To(BeTrue())
		Expect(shared.Name).To(Equal("gcp-cis-controls-8-1"))
		Expect(shared.CheckKeys).To(Equal([]string{"gcp/iam_sa_no_user_managed_keys"}))
		Expect(shared.Controls).To(HaveLen(2))
		Expect(shared.UnmappedControls).To(Equal(1))

		aws, ok := loaded.Profile("aws", "cis_controls_8.1")
		Expect(ok).To(BeTrue())
		Expect(aws.CheckKeys).To(Equal([]string{"aws/iam_root_mfa_enabled"}))
		Expect(loaded.ComplianceIDs("e2enetworks")).To(BeEmpty())
		Expect(loaded.CheckIDs("e2enetworks")).To(Equal([]string{"project_firewall_enabled"}))
	})

	It("normalizes check metadata and provider-scoped enum values", func() {
		loaded, err := catalog.LoadFS(upstreamFixture())
		Expect(err).NotTo(HaveOccurred())

		check, ok := loaded.Check("gcp", "iam_sa_no_user_managed_keys")
		Expect(ok).To(BeTrue())
		Expect(check.Key).To(Equal("gcp/iam_sa_no_user_managed_keys"))
		Expect(check.Provider).To(Equal("gcp"))
		Expect(check.Service).To(Equal("iam"))
		Expect(check.Severity).To(Equal("medium"))
		Expect(check.ResourceType).To(Equal("iam.googleapis.com/ServiceAccount"))
		Expect(check.Categories).To(Equal([]string{"identity-access", "secrets"}))
		Expect(check.References).To(Equal([]string{
			"https://cloud.google.com/iam/docs/keys",
			"https://hub.prowler.com/check/iam_sa_no_user_managed_keys",
		}))
		Expect(check.Remediation.Code).To(Equal(map[string]string{
			"cli":       "gcloud iam service-accounts keys delete <KEY_ID>",
			"terraform": "",
		}))
		Expect(loaded.Services("gcp")).To(Equal([]string{"iam"}))
		Expect(loaded.Categories("gcp")).To(Equal([]string{"identity-access", "secrets"}))
		Expect(loaded.ResourceGroups("gcp")).To(Equal([]string{"identity"}))
	})

	It("preserves compliance mappings to missing upstream checks", func() {
		fixture := upstreamFixture()
		fixture["prowler/compliance/gcp/cis_5.0_gcp.json"] = &fstest.MapFile{Data: []byte(providerComplianceJSON("missing_check"))}

		loaded, err := catalog.LoadFS(fixture)
		Expect(err).NotTo(HaveOccurred())
		profile, ok := loaded.Profile("gcp", "cis_5.0_gcp")
		Expect(ok).To(BeTrue())
		Expect(profile.CheckKeys).To(BeEmpty())
		Expect(profile.MissingCheckKeys).To(Equal([]string{"gcp/missing_check"}))
		Expect(profile.UnmappedControls).To(Equal(2))
	})

	It("rejects a third compliance schema family", func() {
		fixture := upstreamFixture()
		fixture["prowler/compliance/gcp/cis_5.0_gcp.json"] = &fstest.MapFile{Data: []byte(`{"title":"unknown"}`)}

		_, err := catalog.LoadFS(fixture)
		Expect(err).To(MatchError(ContainSubstring("unknown compliance schema")))
	})

	It("round trips the compact artifact and detects manifest drift", func() {
		artifact, manifest, err := catalog.GenerateFS(upstreamFixture())
		Expect(err).NotTo(HaveOccurred())
		compressed, err := hex.DecodeString(string(artifact))
		Expect(err).NotTo(HaveOccurred())
		Expect(compressed[:2]).To(Equal([]byte{0x1f, 0x8b}))
		second, _, err := catalog.GenerateFS(upstreamFixture())
		Expect(err).NotTo(HaveOccurred())
		Expect(second).To(Equal(artifact))
		roundTrip, err := catalog.Unmarshal(artifact)
		Expect(err).NotTo(HaveOccurred())
		Expect(roundTrip.Manifest).To(Equal(manifest))
		Expect(roundTrip.Profiles).To(HaveLen(3))
		Expect(roundTrip.Checks).To(HaveLen(3))

		artifact[len(artifact)-2] ^= 1
		_, err = catalog.Unmarshal(artifact)
		Expect(err).To(HaveOccurred())
	})
})

func upstreamFixture() fstest.MapFS {
	fixture := fstest.MapFS{
		"prowler/config/config.py": {Data: []byte(`prowler_version = "5.40.0"`)},
	}
	for _, provider := range []string{"aws", "e2enetworks", "gcp", "iac", "image", "llm"} {
		fixture["prowler/providers/"+provider+"/"+provider+"_provider.py"] = &fstest.MapFile{Data: []byte("class Provider: pass")}
	}
	fixture["prowler/providers/gcp/services/iam/iam_sa_no_user_managed_keys/iam_sa_no_user_managed_keys.metadata.json"] = &fstest.MapFile{Data: []byte(checkJSON("gcp", "iam_sa_no_user_managed_keys", "iam", "identity"))}
	fixture["prowler/providers/aws/services/iam/iam_root_mfa_enabled/iam_root_mfa_enabled.metadata.json"] = &fstest.MapFile{Data: []byte(checkJSON("aws", "iam_root_mfa_enabled", "iam", "identity"))}
	fixture["prowler/providers/e2enetworks/services/project/project_firewall_enabled/project_firewall_enabled.metadata.json"] = &fstest.MapFile{Data: []byte(checkJSON("e2enetworks", "project_firewall_enabled", "project", "network"))}
	fixture["prowler/compliance/gcp/cis_5.0_gcp.json"] = &fstest.MapFile{Data: []byte(providerComplianceJSON("iam_sa_no_user_managed_keys"))}
	fixture["prowler/compliance/cis_controls_8.1.json"] = &fstest.MapFile{Data: []byte(sharedComplianceJSON)}
	return fixture
}

func checkJSON(provider, id, service, resourceGroup string) string {
	return `{
		"Provider":"` + provider + `","CheckID":"` + id + `","CheckTitle":"Protected resource",
		"CheckType":[],"ServiceName":"` + service + `","SubServiceName":"","ResourceIdTemplate":"",
		"Severity":"medium","ResourceType":"iam.googleapis.com/ServiceAccount","ResourceGroup":"` + resourceGroup + `",
		"Description":"Checks the protected resource.","Risk":"Unauthorized access.","RelatedUrl":"",
		"AdditionalURLs":["https://cloud.google.com/iam/docs/keys"],
		"Remediation":{"Code":{"CLI":"gcloud iam service-accounts keys delete <KEY_ID>","Terraform":""},"Recommendation":{"Text":"Remove the key.","Url":"https://hub.prowler.com/check/` + id + `"}},
		"Categories":["secrets","identity-access"],"DependsOn":[],"RelatedTo":[],"Notes":""
	}`
}

func providerComplianceJSON(check string) string {
	return `{
		"Framework":"CIS","Name":"CIS GCP","Version":"5.0","Provider":"GCP","Description":"GCP benchmark",
		"Requirements":[
			{"Id":"1.1","Description":"Automated control","Checks":["` + check + `"],"Attributes":[{"Section":"Identity","AssessmentStatus":"Automated"}]},
			{"Id":"1.2","Description":"Manual control","Checks":[],"Attributes":[{"Section":"Identity","AssessmentStatus":"Manual"}]}
		]
	}`
}

const sharedComplianceJSON = `{
	"framework":"CIS","name":"CIS Controls","version":"8.1","description":"Shared controls",
	"requirements":[
		{"id":"1.1","name":"Protect identities","description":"Protect identities","attributes":{"Section":"Identity"},"checks":{"gcp":["iam_sa_no_user_managed_keys"],"aws":["iam_root_mfa_enabled"]}},
		{"id":"1.2","name":"Document ownership","description":"Document ownership","attributes":{"Section":"Governance"},"checks":{}}
	]
}`
