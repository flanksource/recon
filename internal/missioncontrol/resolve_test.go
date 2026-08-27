package missioncontrol_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	dutymodels "github.com/flanksource/duty/models"
	"github.com/flanksource/duty/query"
	"github.com/flanksource/duty/upstream"
	"github.com/flanksource/incident-commander/sdk"
	"github.com/google/uuid"
	"github.com/lib/pq"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/missioncontrol"
)

type catalog struct {
	server       *httptest.Server
	items        []dutymodels.ConfigItem
	searches     []string
	searchAgents []string
	pushes       [][]dutymodels.ConfigAnalysis
	pushAgent    string
	pushFails    bool
}

func newCatalog(items ...dutymodels.ConfigItem) *catalog {
	c := &catalog{items: items}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/resources/search":
			var request query.SearchResourcesRequest
			Expect(json.NewDecoder(r.Body).Decode(&request)).To(Succeed())
			search := request.Configs[0].Search
			c.searches = append(c.searches, search)
			c.searchAgents = append(c.searchAgents, request.Configs[0].Agent)
			selected := make([]query.SelectedResource, 0, len(c.items))
			for _, item := range c.items {
				selected = append(selected, query.SelectedResource{
					ID: item.ID.String(), Name: lo.FromPtr(item.Name), Type: lo.FromPtr(item.Type),
				})
			}
			writeJSON(w, query.SearchResourcesResponse{Configs: selected})
		case "/db/config_items":
			writeJSON(w, c.byIDs(r.URL.Query().Get("id")))
		case "/upstream/push":
			if c.pushFails {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var batch upstream.PushData
			Expect(json.NewDecoder(r.Body).Decode(&batch)).To(Succeed())
			c.pushAgent = r.URL.Query().Get(upstream.AgentNameQueryParam)
			c.pushes = append(c.pushes, batch.ConfigAnalysis)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	return c
}

func (c *catalog) client() *sdk.Client { return sdk.New(c.server.URL, "token") }

func (c *catalog) byIDs(filter string) []dutymodels.ConfigItem {
	wanted := strings.Split(strings.Trim(strings.TrimPrefix(filter, "in."), "()"), ",")
	var out []dutymodels.ConfigItem
	for _, item := range c.items {
		if lo.Contains(wanted, item.ID.String()) {
			out = append(out, item)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	Expect(json.NewEncoder(w).Encode(body)).To(Succeed())
}

func configItem(id, name, configType string, externalIDs ...string) dutymodels.ConfigItem {
	return dutymodels.ConfigItem{
		ID: uuid.MustParse(id), Name: lo.ToPtr(name), Type: lo.ToPtr(configType),
		ExternalID: pq.StringArray(externalIDs),
	}
}

// under nests an item beneath a root, the way the catalog's materialised path
// records containment: a dot-separated chain of ids from the root down.
func under(item dutymodels.ConfigItem, root string) dutymodels.ConfigItem {
	item.ParentID = lo.ToPtr(uuid.MustParse(root))
	item.Path = root + "." + item.ID.String()
	return item
}

const (
	instanceID = "3f2a1c4e-0000-4000-8000-00000000000a"
	accountID  = "3f2a1c4e-0000-4000-8000-00000000000b"
	clusterID  = "3f2a1c4e-0000-4000-8000-00000000000c"
	twinID     = "3f2a1c4e-0000-4000-8000-00000000000d"
	projectID  = "3f2a1c4e-0000-4000-8000-00000000000e"
)

func resolvedState(resource api.Resource) api.InsightState {
	finding := tlsFinding()
	finding.Resources = []api.ResourceRef{resource.Ref()}
	return api.InsightState{
		Resource: resource, Finding: finding, Scan: nucleiScan(),
		State: api.FindingState{
			ID: "01JSTATE", Engine: "nuclei", CheckID: finding.CheckID,
			Status: api.StatusOpen, Severity: string(finding.Severity),
			FirstSeen: "2026-08-10T12:00:11", LastSeen: "2026-08-10T12:00:11",
		},
	}
}

var _ = Describe("resolving a current resource state", func() {
	It("uses the resource's typed external identity", func() {
		catalog := newCatalog(
			configItem(instanceID, "web-1", "AWS::EC2::Instance", "arn:aws:ec2:eu-west-1:1:instance/i-1"),
			configItem(accountID, "wrong-type", "AWS::Account", "arn:aws:ec2:eu-west-1:1:instance/i-1"),
		)
		defer catalog.server.Close()
		state := resolvedState(api.Resource{
			Provider: "aws", Scope: "1", UID: "i-1", ConfigType: "AWS::EC2::Instance",
			ExternalIDs: []string{"arn:aws:ec2:eu-west-1:1:instance/i-1"},
		})

		resolution, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), missioncontrol.ResolveOptions{State: state})

		Expect(err).ToNot(HaveOccurred())
		Expect(resolution.Unresolved).To(BeNil())
		Expect(resolution.Match.ConfigID.String()).To(Equal(instanceID))
		Expect(resolution.Match.RolledUp).To(BeFalse())
		Expect(catalog.searches[0]).To(ContainSubstring(`type="AWS::EC2::Instance"`))
	})

	It("never treats evidence locations as resource identity", func() {
		catalog := newCatalog(configItem(instanceID, "https://api.example.test/tls", "Endpoint"))
		defer catalog.server.Close()
		state := resolvedState(api.Resource{Provider: "nuclei", Scope: "api.example.test", UID: "input"})
		state.Finding.MatchedAt = "https://api.example.test/tls"

		resolution, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), missioncontrol.ResolveOptions{State: state})

		Expect(err).ToNot(HaveOccurred())
		Expect(resolution.Match).To(BeNil())
		Expect(resolution.Unresolved).ToNot(BeNil())
		Expect(catalog.searches).To(BeEmpty())
	})

	It("rolls up through the emitted account resource before the target", func() {
		catalog := newCatalog(configItem(accountID, "acme-prod", "AWS::::Account", "1"))
		defer catalog.server.Close()
		state := resolvedState(api.Resource{Provider: "aws", Scope: "1", UID: "i-1", ExternalIDs: []string{"i-1"}})
		parent := api.Resource{
			Provider: "aws", Scope: "1", UID: "1", ConfigType: "AWS::::Account", ExternalIDs: []string{"1"},
		}
		state.Parent = &parent

		resolution, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), missioncontrol.ResolveOptions{State: state, Target: api.TargetDocument{ID: "fallback"}})

		Expect(err).ToNot(HaveOccurred())
		Expect(resolution.Unresolved).To(BeNil())
		Expect(resolution.Match.ConfigID.String()).To(Equal(accountID))
		Expect(resolution.Match.RolledUp).To(BeTrue())
	})

	It("uses the target only as the final rollup", func() {
		catalog := newCatalog(configItem(clusterID, "prod-euw1", "Kubernetes::Cluster"))
		defer catalog.server.Close()
		state := resolvedState(api.Resource{Provider: "nuclei", Scope: "api.example.test", UID: "input"})

		resolution, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), missioncontrol.ResolveOptions{
				State: state, Target: api.TargetDocument{ID: "target", Cluster: "prod-euw1"},
			})

		Expect(err).ToNot(HaveOccurred())
		Expect(resolution.Unresolved).To(BeNil())
		Expect(resolution.Match.ConfigID.String()).To(Equal(clusterID))
		Expect(resolution.Match.RolledUp).To(BeTrue())
	})
})

// The catalog fixture answers every search with every item it holds and lets
// the resolver's own confirmation do the filtering, so two items carrying one
// name is all it takes to reproduce the ambiguity a real estate produces when
// two scrapers describe the same project.
var _ = Describe("an identity several config items carry", func() {
	It("attaches nothing and offers the matches beside what contains them", func() {
		catalog := ambiguousCatalog()
		defer catalog.server.Close()

		resolution, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), missioncontrol.ResolveOptions{State: projectState("web-1")})

		Expect(err).ToNot(HaveOccurred())
		Expect(resolution.Match).To(BeNil())
		Expect(resolution.Unresolved.Reason).To(Equal("workload-prod-eu-02 matched 2 config items; choose one"))
		Expect(resolution.Ambiguous).To(HaveLen(1))
		Expect(resolution.Ambiguous[0].Identity).To(Equal("workload-prod-eu-02"))
		Expect(resolution.Ambiguous[0].Scope).To(BeTrue())
		Expect(resolution.Ambiguous[0].Options).To(Equal([]api.InsightChoice{
			{ID: accountID, Name: "workload-prod-eu-02", Type: "GCP::Project"},
			{ID: twinID, Name: "workload-prod-eu-02", Type: "GCP::Project"},
			{ID: projectID, Name: "acme-root", Type: "GCP::Organization", Root: true, Ancestor: true},
		}))
	})

	It("attaches to the config item chosen for that identity", func() {
		catalog := ambiguousCatalog()
		defer catalog.server.Close()
		resolver := missioncontrol.NewResolver(catalog.client())
		resolver.Choices = map[string]uuid.UUID{"workload-prod-eu-02": uuid.MustParse(twinID)}

		resolution, err := resolver.Resolve(context.Background(),
			missioncontrol.ResolveOptions{State: projectState("web-1")})

		Expect(err).ToNot(HaveOccurred())
		Expect(resolution.Unresolved).To(BeNil())
		Expect(resolution.Match.ConfigID.String()).To(Equal(twinID))
		Expect(resolution.Match.Chosen).To(BeTrue())
		Expect(resolution.Match.RolledUp).To(BeTrue())
		// Still reported: the choice is what a real sync then remembers, and the
		// preview has to show what it would remember it against.
		Expect(resolution.Ambiguous).To(HaveLen(1))
	})

	It("rolls a choice of the containing item up, whatever rung it was made on", func() {
		catalog := newCatalog(
			under(configItem(instanceID, "web-1", "GCP::Instance", "i-1"), projectID),
			under(configItem(twinID, "web-1", "GCP::Instance", "i-1"), projectID),
			configItem(projectID, "acme-root", "GCP::Organization"),
		)
		defer catalog.server.Close()
		resolver := missioncontrol.NewResolver(catalog.client())
		resolver.Choices = map[string]uuid.UUID{"i-1": uuid.MustParse(projectID)}

		resolution, err := resolver.Resolve(context.Background(), missioncontrol.ResolveOptions{
			State: resolvedState(api.Resource{
				Provider: "gcp", Scope: "1", UID: "i-1", ExternalIDs: []string{"i-1"},
			}),
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(resolution.Match.ConfigID.String()).To(Equal(projectID))
		Expect(resolution.Match.RolledUp).To(BeTrue())
	})
})

var _ = Describe("a choice a previous sync remembered", func() {
	It("attaches to it without searching the catalog at all", func() {
		catalog := newCatalog(configItem(accountID, "workload-prod-eu-02", "GCP::Project"))
		defer catalog.server.Close()

		resolution, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), missioncontrol.ResolveOptions{
				State: resolvedState(api.Resource{
					Provider: "gcp", Scope: "1", UID: "i-1", ExternalIDs: []string{"i-1"},
				}),
				Pin: &api.ConfigPin{ConfigID: accountID, RolledUp: true},
			})

		Expect(err).ToNot(HaveOccurred())
		Expect(catalog.searches).To(BeEmpty())
		Expect(resolution.Match.ConfigID.String()).To(Equal(accountID))
		Expect(resolution.Match.ConfigName).To(Equal("workload-prod-eu-02"))
		Expect(resolution.Match.Pinned).To(BeTrue())
		Expect(resolution.Match.RolledUp).To(BeTrue())
	})

	It("reports one that has left the catalog rather than pushing against it", func() {
		catalog := newCatalog()
		defer catalog.server.Close()

		resolution, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), missioncontrol.ResolveOptions{
				State: resolvedState(api.Resource{Provider: "gcp", Scope: "1", UID: "i-1"}),
				Pin:   &api.ConfigPin{ConfigID: accountID},
			})

		Expect(err).ToNot(HaveOccurred())
		Expect(resolution.Match).To(BeNil())
		Expect(resolution.Unresolved.Reason).To(ContainSubstring("no longer in the catalog"))
		Expect(resolution.Unresolved.Reason).To(ContainSubstring("--repin"))
	})
})
