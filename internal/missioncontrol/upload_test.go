package missioncontrol_test

import (
	"context"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/missioncontrol"
)

func uploaderFor(c *catalog) *missioncontrol.Uploader {
	client := c.client()
	return &missioncontrol.Uploader{
		Client: client, Resolver: missioncontrol.NewResolver(client), Server: c.server.URL, Context: "test",
	}
}

// remembered is the choices a previous sync stored, and what this one stores.
type remembered struct {
	stored map[string]api.ConfigPin
	saved  map[string]api.ConfigPin
	asked  []string
}

func (r *remembered) ConfigPins(_ context.Context, resourceIDs []string) (map[string]api.ConfigPin, error) {
	r.asked = append(r.asked, resourceIDs...)
	found := map[string]api.ConfigPin{}
	for _, id := range resourceIDs {
		if pin, ok := r.stored[id]; ok {
			found[id] = pin
		}
	}
	return found, nil
}

func (r *remembered) SetConfigPins(_ context.Context, pins map[string]api.ConfigPin) error {
	if r.saved == nil {
		r.saved = map[string]api.ConfigPin{}
	}
	for id, pin := range pins {
		r.saved[id] = pin
	}
	return nil
}

// ambiguousCatalog is one project described twice, which is what a second
// scraper over the same estate produces.
func ambiguousCatalog() *catalog {
	return newCatalog(
		under(configItem(accountID, "workload-prod-eu-02", "GCP::Project", "1"), projectID),
		under(configItem(twinID, "workload-prod-eu-02", "GCP::Project", "1"), projectID),
		configItem(projectID, "acme-root", "GCP::Organization"),
	)
}

// projectState is a resource the catalog does not hold, inside the project two
// config items both claim to be.
func projectState(uid string) api.InsightState {
	state := currentState(api.StatusOpen)
	state.Resource = api.Resource{
		ID: "01JRESOURCE" + uid, Provider: "gcp", Scope: "1", UID: uid, Name: uid,
		ExternalIDs: []string{uid},
	}
	state.State.ResourceID = state.Resource.ID
	state.Parent = &api.Resource{
		Provider: "gcp", Scope: "1", UID: "1", ConfigType: "GCP::Project",
		ExternalIDs: []string{"workload-prod-eu-02"},
	}
	return state
}

var _ = Describe("syncing current insight state", func() {
	It("pushes open, resolved and muted states with one stable insight each", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Endpoint", "https://api.example.test"))
		defer catalog.server.Close()
		states := []api.InsightState{
			currentState(api.StatusOpen), currentState(api.StatusResolved), currentState(api.StatusMuted),
		}
		states[0].State.CheckID = "tls-version"
		states[0].Finding.CheckID = "tls-version"
		states[1].State.CheckID = "weak-cipher"
		states[1].Finding.CheckID = "weak-cipher"
		states[2].State.CheckID = "accepted-risk"
		states[2].Finding.CheckID = "accepted-risk"

		result, err := uploaderFor(catalog).Sync(context.Background(), states, nil, 1, missioncontrol.SyncOptions{})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Pushed).To(Equal(3))
		Expect(result.Open).To(Equal(1))
		Expect(result.Resolved).To(Equal(1))
		Expect(result.Silenced).To(Equal(1))
		Expect(result.Direct).To(Equal(3))
		Expect(catalog.pushAgent).To(Equal(missioncontrol.DefaultAgent))
		Expect(catalog.pushes[0]).To(HaveLen(3))
	})

	It("attributes the push to the agent without scoping the catalog search to it", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Endpoint", "https://api.example.test"))
		defer catalog.server.Close()

		result, err := uploaderFor(catalog).Sync(context.Background(),
			[]api.InsightState{currentState(api.StatusOpen)}, nil, 1,
			missioncontrol.SyncOptions{Agent: "recon-prod"})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Pushed).To(Equal(1))
		Expect(catalog.pushAgent).To(Equal("recon-prod"))
		Expect(catalog.searchAgents).ToNot(BeEmpty())
		Expect(catalog.searchAgents).To(HaveEach(BeEmpty()))
	})

	It("previews the exact resolution without sending", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Endpoint", "https://api.example.test"))
		defer catalog.server.Close()

		result, err := uploaderFor(catalog).Sync(context.Background(),
			[]api.InsightState{currentState(api.StatusOpen)}, nil, 1,
			missioncontrol.SyncOptions{DryRun: true})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.DryRun).To(BeTrue())
		Expect(result.Eligible).To(Equal(1))
		Expect(result.Pushed).To(BeZero())
		Expect(catalog.pushes).To(BeEmpty())
	})

	It("excludes pass-only resolved states", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Endpoint", "https://api.example.test"))
		defer catalog.server.Close()
		state := currentState(api.StatusResolved)
		state.State.Occurrences = 0

		result, err := uploaderFor(catalog).Sync(context.Background(), []api.InsightState{state}, nil, 1, missioncontrol.SyncOptions{})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Skipped).To(Equal(1))
		Expect(result.Pushed).To(BeZero())
	})

	It("pushes nothing when unresolved resources are an error", func() {
		catalog := newCatalog()
		defer catalog.server.Close()

		result, err := uploaderFor(catalog).Sync(context.Background(),
			[]api.InsightState{currentState(api.StatusOpen)}, nil, 1,
			missioncontrol.SyncOptions{Unresolved: missioncontrol.UnresolvedError})

		Expect(err).To(MatchError(ContainSubstring("1 of 1 eligible states")))
		Expect(result.Unresolved).To(HaveLen(1))
		Expect(catalog.pushes).To(BeEmpty())
	})

	It("reports how far it has got, so a run of a large estate is not a silent pause", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Endpoint", "https://api.example.test"))
		defer catalog.server.Close()
		var seen []missioncontrol.Progress

		_, err := uploaderFor(catalog).Sync(context.Background(),
			[]api.InsightState{currentState(api.StatusOpen)}, nil, 1,
			missioncontrol.SyncOptions{Progress: func(at missioncontrol.Progress) { seen = append(seen, at) }})

		Expect(err).ToNot(HaveOccurred())
		Expect(seen).To(Equal([]missioncontrol.Progress{
			{Phase: missioncontrol.PhaseResolve, Done: 0, Total: 1, Identity: "https://api.example.test"},
			{Phase: missioncontrol.PhaseResolve, Done: 1, Total: 1},
			{Phase: missioncontrol.PhasePush, Done: 0, Total: 1},
			{Phase: missioncontrol.PhasePush, Done: 1, Total: 1},
		}))
	})
})

var _ = Describe("syncing an identity several config items carry", func() {
	It("counts every state riding on the choice and names the resources", func() {
		catalog := ambiguousCatalog()
		defer catalog.server.Close()

		result, err := uploaderFor(catalog).Sync(context.Background(),
			[]api.InsightState{projectState("web-1"), projectState("web-2")}, nil, 2,
			missioncontrol.SyncOptions{DryRun: true})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Ambiguous).To(HaveLen(1))
		Expect(result.Ambiguous[0].States).To(Equal(2))
		Expect(result.Ambiguous[0].Resources).To(Equal([]string{"web-1", "web-2"}))
		Expect(result.Ambiguous[0].Options).To(HaveLen(3))
		Expect(result.Unresolved).To(HaveLen(2))
		Expect(result.Direct + result.RolledUp).To(BeZero())
	})

	It("remembers the choice against every resource it decided, once the insights land", func() {
		catalog := ambiguousCatalog()
		defer catalog.server.Close()
		pins := &remembered{}
		uploader := uploaderFor(catalog)
		uploader.Pins = pins
		options := missioncontrol.SyncOptions{
			Choices: map[string]uuid.UUID{"workload-prod-eu-02": uuid.MustParse(twinID)},
		}

		result, err := uploader.Sync(context.Background(),
			[]api.InsightState{projectState("web-1"), projectState("web-2")}, nil, 2, options)

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Pushed).To(Equal(2))
		Expect(result.RolledUp).To(Equal(2))
		Expect(result.Ambiguous[0].Chosen).To(Equal(twinID))
		Expect(result.Configs).To(Equal([]api.InsightConfig{{
			ID: twinID, Name: "workload-prod-eu-02", Type: "GCP::Project",
			Insights: 2, RolledUp: true, Pinned: true,
		}}))
		Expect(pins.saved).To(Equal(map[string]api.ConfigPin{
			"01JRESOURCEweb-1": {ConfigID: twinID, RolledUp: true},
			"01JRESOURCEweb-2": {ConfigID: twinID, RolledUp: true},
		}))
	})

	It("remembers nothing from a preview", func() {
		catalog := ambiguousCatalog()
		defer catalog.server.Close()
		pins := &remembered{}
		uploader := uploaderFor(catalog)
		uploader.Pins = pins

		result, err := uploader.Sync(context.Background(),
			[]api.InsightState{projectState("web-1")}, nil, 1, missioncontrol.SyncOptions{
				DryRun:  true,
				Choices: map[string]uuid.UUID{"workload-prod-eu-02": uuid.MustParse(twinID)},
			})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.RolledUp).To(Equal(1))
		Expect(pins.saved).To(BeEmpty())
		Expect(catalog.pushes).To(BeEmpty())
	})

	It("attaches to a remembered choice without asking the catalog again", func() {
		catalog := ambiguousCatalog()
		defer catalog.server.Close()
		uploader := uploaderFor(catalog)
		uploader.Pins = &remembered{stored: map[string]api.ConfigPin{
			"01JRESOURCEweb-1": {ConfigID: twinID, RolledUp: true},
		}}

		result, err := uploader.Sync(context.Background(),
			[]api.InsightState{projectState("web-1")}, nil, 1, missioncontrol.SyncOptions{})

		Expect(err).ToNot(HaveOccurred())
		Expect(catalog.searches).To(BeEmpty())
		Expect(result.Pinned).To(Equal(1))
		Expect(result.RolledUp).To(Equal(1))
		Expect(result.Ambiguous).To(BeEmpty())
		Expect(result.Pushed).To(Equal(1))
	})

	It("resolves from the catalog again when repin is set", func() {
		catalog := ambiguousCatalog()
		defer catalog.server.Close()
		uploader := uploaderFor(catalog)
		uploader.Pins = &remembered{stored: map[string]api.ConfigPin{
			"01JRESOURCEweb-1": {ConfigID: twinID, RolledUp: true},
		}}

		result, err := uploader.Sync(context.Background(),
			[]api.InsightState{projectState("web-1")}, nil, 1, missioncontrol.SyncOptions{Repin: true})

		Expect(err).ToNot(HaveOccurred())
		Expect(catalog.searches).ToNot(BeEmpty())
		Expect(result.Pinned).To(BeZero())
		Expect(result.Ambiguous).To(HaveLen(1))
	})

	DescribeTable("validates the unresolved policy",
		func(value string, expected missioncontrol.UnresolvedPolicy, valid bool) {
			policy, err := missioncontrol.ParseUnresolvedPolicy(value)
			if !valid {
				Expect(err).To(HaveOccurred())
				return
			}
			Expect(err).ToNot(HaveOccurred())
			Expect(policy).To(Equal(expected))
		},
		Entry("default", "", missioncontrol.UnresolvedReport, true),
		Entry("report", "report", missioncontrol.UnresolvedReport, true),
		Entry("error", "error", missioncontrol.UnresolvedError, true),
		Entry("invalid", "fail", missioncontrol.UnresolvedPolicy(""), false),
	)
})
