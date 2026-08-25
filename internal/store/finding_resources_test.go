package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/mute"
	"github.com/flanksource/recon/internal/ocsf"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

// The subjects a finding is about, after a round trip through the database.
//
// A resource is identified by (provider, scope, uid), and OCSF supplies only
// the last of those on each entry of its `resources` array: at 1.5.0 the
// account lives once at the event level, in cloud.account.uid, rather than on
// every resource. So identity cannot be rebuilt by re-reading the record no
// matter how carefully — it has to come from the table that already holds it.
//
// Until it did, ingest patched provider and scope on afterwards and reading the
// row back did not, so every persisted prowler finding carried references that
// failed ResourceKey.Validate. Nothing errored. A resource-scoped mute rule
// simply stopped matching, and entity resolution simply stopped resolving.
var _ = Describe("the resources a finding names", Ordered, Label("db"), func() {
	var (
		db  *dbtest.DB
		st  *store.Store
		ctx context.Context
	)

	BeforeAll(func() {
		if testing.Short() {
			Skip("needs a database")
		}
		db = dbtest.ForGinkgo(dbtest.Options{
			Name:        "recon_finding_resources",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()
	})

	BeforeEach(func() {
		Expect(db.Gorm().Exec(`DELETE FROM scans`).Error).To(Succeed())
		Expect(db.Gorm().Exec(`DELETE FROM resources`).Error).To(Succeed())
	})

	const account = "flanksource-prod"

	resource := func(uid, name string) api.Resource {
		return api.Resource{
			Provider: "gcp", Scope: account, UID: uid,
			Kind: api.KindCloudResource, Type: "storage.googleapis.com/Bucket",
			Name: name, Service: "storage", Region: "eu",
		}
	}
	ref := func(uid, name string) api.ResourceRef {
		return api.ResourceRef{
			Provider: "gcp", Scope: account, UID: uid,
			Name: name, Type: "storage.googleapis.com/Bucket", Service: "storage", Region: "eu",
		}
	}

	// A prowler check that failed against two buckets in one account — the case
	// where only the first used to survive, and the rest existed nowhere but the
	// raw blob a later step deletes.
	var persisted api.Finding

	BeforeEach(func() {
		at := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
		row, err := st.CreateScan(ctx, models.Scan{
			Name: "prowler-buckets", Engine: "prowler", Profile: "gcp-cis-5-0",
			Phase: string(api.PhaseRunning), StartedAt: at,
		})
		Expect(err).ToNot(HaveOccurred())

		exitCode := 0
		row.Phase = string(api.PhaseDone)
		row.FinishedAt = &at
		row.ExitCode = &exitCode
		Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
			Scan:      row,
			Resources: []api.Resource{resource("bucket-a", "logs"), resource("bucket-b", "backups")},
			Findings: []api.Finding{{
				DetectionFinding: ocsf.DetectionFinding{
					ClassUID:    ocsf.ClassUID,
					CategoryUID: ocsf.CategoryUID,
					ActivityID:  ocsf.ActivityIDCreate,
					TypeUID:     ocsf.TypeUID(ocsf.ActivityIDCreate),
					SeverityID:  ocsf.SeverityIDHigh,
					FindingInfo: &ocsf.FindingInfo{
						UID: "gcp/bucket_public", Title: "Bucket is public",
					},
					Cloud: &ocsf.Cloud{
						Provider: "gcp",
						Account:  &ocsf.Account{UID: account},
					},
				},
				LineNo: 1, CheckID: "gcp/bucket_public", Engine: "prowler",
				Host: account, MatchedAt: "bucket-a",
				Resources: []api.ResourceRef{ref("bucket-a", "logs"), ref("bucket-b", "backups")},
			}},
		})).To(Succeed())

		found, err := st.ListFindings(ctx, store.FindingOpts{Limit: 10})
		Expect(err).ToNot(HaveOccurred())
		Expect(found).To(HaveLen(1))
		persisted = found[0]
	})

	It("gives every reference the full key, not only the uid", func() {
		keys := make([]string, 0, len(persisted.Resources))
		for _, resource := range persisted.Resources {
			key := api.ResourceKey{Provider: resource.Provider, Scope: resource.Scope, UID: resource.UID}
			Expect(key.Validate()).To(Succeed(),
				"reference %q came back without a resolvable key", resource.UID)
			keys = append(keys, key.String())
		}

		Expect(keys).To(Equal([]string{
			"gcp/" + account + "/bucket-a",
			"gcp/" + account + "/bucket-b",
		}))
	})

	// The reason the relation exists rather than a second column. Dropping raw
	// must not lose the resources a check reported beyond the first.
	It("keeps every resource the record named, in the order it named them", func() {
		names := make([]string, 0, len(persisted.Resources))
		for _, resource := range persisted.Resources {
			names = append(names, resource.Name)
		}

		Expect(names).To(Equal([]string{"logs", "backups"}))
	})

	It("resolves the canonical subject to the row recon owns", func() {
		Expect(persisted.Resources[0].ID).ToNot(BeEmpty())
	})

	// The exact path that was broken. matchesResourceKey skips any reference
	// whose key does not validate, so a rule scoped to a resource matched a
	// finding held in memory since ingest and not the same finding read back.
	It("matches a resource-scoped mute rule after the round trip", func() {
		rule := mute.Rule{MuteRule: api.MuteRule{
			Name:         "accept-public-logs",
			ResourceKeys: api.StringList{"gcp/" + account + "/bucket-a"},
		}}

		matched, err := rule.Matches(persisted)

		Expect(err).ToNot(HaveOccurred())
		Expect(matched).To(BeTrue())
	})

	It("matches a rule scoped to a resource the check named second", func() {
		rule := mute.Rule{MuteRule: api.MuteRule{
			Name:         "accept-public-backups",
			ResourceKeys: api.StringList{"gcp/" + account + "/bucket-b"},
		}}

		matched, err := rule.Matches(persisted)

		Expect(err).ToNot(HaveOccurred())
		Expect(matched).To(BeTrue())
	})

	It("still declines a rule naming a resource the check did not report", func() {
		rule := mute.Rule{MuteRule: api.MuteRule{
			Name:         "accept-something-else",
			ResourceKeys: api.StringList{"gcp/" + account + "/bucket-c"},
		}}

		matched, err := rule.Matches(persisted)

		Expect(err).ToNot(HaveOccurred())
		Expect(matched).To(BeFalse())
	})
})
