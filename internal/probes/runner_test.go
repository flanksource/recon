package probes

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

// A sweep is recorded twice on purpose: in probes, which is what the Ping dialog
// follows, and in scans, which is what the runs list shows and what stamps each
// covered host's scan.last_scan. They share one id, so the two records are one
// run rather than two things that happened to be about the same hosts.
var _ = Describe("recording a sweep", Ordered, Label("db"), func() {
	var (
		db     *dbtest.DB
		st     *store.Store
		runner *Runner
		ctx    context.Context

		up   *httptest.Server
		down string
	)

	BeforeAll(func() {
		if testing.Short() {
			Skip("needs a database")
		}
		db = dbtest.ForGinkgo(dbtest.Options{
			Name:        "recon_probes",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		runner = &Runner{Store: st}
		ctx = context.Background()

		up = httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		DeferCleanup(up.Close)

		// A port nothing is listening on, so the sweep has one host that answers
		// and one that does not — which is the case the run has to survive.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		down = listener.Addr().String()
		Expect(listener.Close()).To(Succeed())

		for _, host := range []string{up.Listener.Addr().String(), down} {
			Expect(st.SaveTarget(ctx, api.TargetDocument{
				Schema: api.TargetSchemaRef, Version: api.TargetVersion,
				Host: host, Class: api.ClassNonProd,
				Profiles: []string{"safe"}, Tags: []string{},
			})).To(Succeed(), host)
		}
	})

	It("writes the sweep to both tables under one id and stamps what it covered", func() {
		hosts := []string{"http://" + up.Listener.Addr().String(), "http://" + down}
		run, err := runner.Run(ctx, Options{
			Hosts: hosts, Timeout: 2 * time.Second, Concurrency: 2, Wait: true,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(run.Phase).To(Equal(api.PhaseDone))

		recorded, err := st.GetScan(ctx, run.ID)
		Expect(err).ToNot(HaveOccurred())
		Expect(struct {
			ID, Engine, Profile string
			Phase               api.Phase
			EndpointCount       int
		}{
			recorded.ID, recorded.Engine, recorded.Profile, recorded.Phase, recorded.EndpointCount,
		}).To(Equal(struct {
			ID, Engine, Profile string
			Phase               api.Phase
			EndpointCount       int
		}{run.ID, api.ProbeEngine, api.ProbeProfile, api.PhaseDone, 2}))

		// The whole reason a ping writes a scan row: the inventory's Last scan
		// column was empty for every host until something stamped it, and a
		// liveness check is a check.
		stamped, err := st.GetTarget(ctx, up.Listener.Addr().String())
		Expect(err).ToNot(HaveOccurred())
		Expect(stamped.Scan).ToNot(BeNil())
		Expect(stamped.Scan.LastScan).ToNot(BeEmpty())
		Expect(stamped.Scan.LastFindings).To(BeNil(), "a sweep finds nothing and claims nothing")
	})

	// A host that answered and a host that did not are both results. The run is
	// done, not failed, and the dead one carries a classification the inventory
	// can badge.
	It("classifies a host that did not answer without failing the run", func() {
		run, err := runner.Run(ctx, Options{
			Hosts: []string{"http://" + down}, Timeout: 2 * time.Second, Concurrency: 1, Wait: true,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(run.Phase).To(Equal(api.PhaseDone))
		Expect(run.Results).To(HaveLen(1))
		Expect(run.Results[0].Failure).To(Equal(api.FailureRefused))

		stored, err := st.GetTarget(ctx, down)
		Expect(err).ToNot(HaveOccurred())
		Expect(stored.Observed.Failure).To(Equal(api.FailureRefused))
	})
})
