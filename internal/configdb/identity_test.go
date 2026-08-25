package configdb_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/configdb"
)

func TestConfigDB(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "configdb")
}

var _ = Describe("the config item type a resource would be stored under", func() {
	// Every asset type a real GCP compliance scan of this estate reported, with
	// the type config-db derives from the same string. The table is the point:
	// the transform is only worth having if it is exact for the whole corpus,
	// and a single wrong entry scopes a catalog lookup to rows that cannot match.
	DescribeTable("maps a Cloud Asset Inventory asset type exactly",
		func(assetType, expected string) {
			Expect(configdb.ConfigType("gcp", assetType)).To(Equal(expected))
		},
		Entry(nil, "accessapproval.googleapis.com/AccessApprovalSettings", "GCP::AccessApprovalSettings"),
		Entry(nil, "apikeys.googleapis.com/Key", "GCP::APIKeys::Key"),
		Entry(nil, "bigquery.googleapis.com/Dataset", "GCP::BigQuery::Dataset"),
		Entry(nil, "bigquery.googleapis.com/Table", "GCP::BigQuery::Table"),
		Entry(nil, "cloudkms.googleapis.com/CryptoKey", "GCP::CryptoKey"),
		Entry(nil, "compute.googleapis.com/Firewall", "GCP::Firewall"),
		Entry(nil, "compute.googleapis.com/Instance", "GCP::Instance"),
		Entry(nil, "compute.googleapis.com/Network", "GCP::Network"),
		Entry(nil, "compute.googleapis.com/Subnetwork", "GCP::Subnetwork"),
		Entry(nil, "dns.googleapis.com/ManagedZone", "GCP::ManagedZone"),
		Entry(nil, "iam.googleapis.com/ServiceAccount", "GCP::ServiceAccount"),
		Entry(nil, "iam.googleapis.com/ServiceAccountKey", "GCP::ServiceAccountKey"),
		Entry(nil, "logging.googleapis.com/LogMetric", "GCP::LogMetric"),
		Entry(nil, "serviceusage.googleapis.com/Service", "GCP::ServiceUsage::Service"),
		Entry(nil, "storage.googleapis.com/Bucket", "GCP::Bucket"),
	)

	// Both appear in one run, because Prowler names the project itself whenever a
	// check has nothing more specific to point at. They are different config
	// items and collapsing them would attach an account-level finding to the
	// wrong one.
	It("keeps the two Project asset types apart", func() {
		Expect(configdb.ConfigType("gcp", "compute.googleapis.com/Project")).
			To(Equal("GCP::Project"))
		Expect(configdb.ConfigType("gcp", "cloudresourcemanager.googleapis.com/Project")).
			To(Equal("GCP::ResourceManager::Project"))
	})

	// A resource type recon cannot place gets no type at all. Guessing would
	// scope a lookup to a type no catalog row carries, turning a miss into a
	// confident mismatch — worse than searching untyped.
	DescribeTable("declines what it cannot place",
		func(provider, resourceType string) {
			Expect(configdb.ConfigType(provider, resourceType)).To(BeEmpty())
		},
		Entry("an unknown provider", "vercel", "Project"),
		Entry("an empty type", "gcp", ""),
		Entry("a GCP value that is not an asset type", "gcp", "Firewall"),
		Entry("a GCP asset type with no resource half", "gcp", "compute.googleapis.com/"),
		Entry("an AWS type outside config-db's vocabulary", "aws", "AWS::Invented::Thing"),
		Entry("an Azure value that is not an ARM type", "azure", "VirtualMachine"),
		Entry("a Kubernetes value carrying a group", "kubernetes", "apps/Deployment"),
		Entry("a GitHub kind nobody scrapes", "github", "Gist"),
	)

	DescribeTable("recognises the other providers config-db scrapes",
		func(provider, resourceType, expected string) {
			Expect(configdb.ConfigType(provider, resourceType)).To(Equal(expected))
		},
		// Verbatim, because config-db stores AWS Config's own strings unchanged.
		Entry(nil, "aws", "AWS::EC2::Instance", "AWS::EC2::Instance"),
		// The two the vocabulary exists to carry: neither follows a rule.
		Entry(nil, "aws", "AWS::::Account", "AWS::::Account"),
		Entry(nil, "aws", "AWS::EBS::Volume", "AWS::EBS::Volume"),
		Entry(nil, "azure", "Microsoft.Compute/virtualMachines", "Azure::Microsoft.Compute/virtualMachines"),
		Entry(nil, "kubernetes", "Pod", "Kubernetes::Pod"),
		Entry(nil, "github", "Repository", "GitHub::Repository"),
		Entry(nil, "github", "GitHub::Organization", "GitHub::Organization"),
	)

	// config-db drops the scraper from its own predicate for these, so a lookup
	// that scoped by one would exclude the rows it wants.
	It("knows which types are stored without a scraper", func() {
		Expect(configdb.ScraperLess("GitHub::Organization")).To(BeTrue())
		Expect(configdb.ScraperLess("AWS::Region")).To(BeTrue())
		Expect(configdb.ScraperLess("GCP::Firewall")).To(BeFalse())
	})
})

var _ = Describe("the identities a config item can be found by", func() {
	// config-db lowercases and trims every external id on the way in, so a
	// lookup that skipped this would miss any row whose identity carried a
	// capital — which is most service account emails and every ARN.
	It("normalises the way config-db does", func() {
		Expect(configdb.ExternalIDs("  Scanner-SA@Example-Prod.iam.gserviceaccount.com ")).
			To(Equal([]string{"scanner-sa@example-prod.iam.gserviceaccount.com"}))
	})

	// Both the uid and the name are offered because neither is reliably
	// config-db's primary identity: for a firewall the uid is the numeric
	// resource id config-db keys on, and for a service account the *name* is,
	// while the uid is only an alias.
	It("keeps every candidate, in order, without duplicates", func() {
		Expect(configdb.ExternalIDs(
			"1429543158501771126",
			"tailscale-router",
			"1429543158501771126",
			"",
			"   ",
			"//compute.googleapis.com/projects/x/global/firewalls/tailscale-router",
		)).To(Equal([]string{
			"1429543158501771126",
			"tailscale-router",
			"//compute.googleapis.com/projects/x/global/firewalls/tailscale-router",
		}))
	})

	It("reports nothing when it was given nothing usable", func() {
		Expect(configdb.ExternalIDs("", "  ")).To(BeNil())
	})
})
