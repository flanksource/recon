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
	server    *httptest.Server
	items     []dutymodels.ConfigItem
	searches  []string
	pushes    [][]dutymodels.ConfigAnalysis
	pushAgent string
	pushFails bool
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

const (
	instanceID = "3f2a1c4e-0000-4000-8000-00000000000a"
	accountID  = "3f2a1c4e-0000-4000-8000-00000000000b"
	clusterID  = "3f2a1c4e-0000-4000-8000-00000000000c"
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

		match, unresolved, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), missioncontrol.ResolveOptions{State: state})

		Expect(err).ToNot(HaveOccurred())
		Expect(unresolved).To(BeNil())
		Expect(match.ConfigID.String()).To(Equal(instanceID))
		Expect(match.RolledUp).To(BeFalse())
		Expect(catalog.searches[0]).To(ContainSubstring(`type="AWS::EC2::Instance"`))
	})

	It("never treats evidence locations as resource identity", func() {
		catalog := newCatalog(configItem(instanceID, "https://api.example.test/tls", "Endpoint"))
		defer catalog.server.Close()
		state := resolvedState(api.Resource{Provider: "nuclei", Scope: "api.example.test", UID: "input"})
		state.Finding.MatchedAt = "https://api.example.test/tls"

		match, unresolved, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), missioncontrol.ResolveOptions{State: state})

		Expect(err).ToNot(HaveOccurred())
		Expect(match).To(BeNil())
		Expect(unresolved).ToNot(BeNil())
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

		match, unresolved, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), missioncontrol.ResolveOptions{State: state, Target: api.TargetDocument{ID: "fallback"}})

		Expect(err).ToNot(HaveOccurred())
		Expect(unresolved).To(BeNil())
		Expect(match.ConfigID.String()).To(Equal(accountID))
		Expect(match.RolledUp).To(BeTrue())
	})

	It("uses the target only as the final rollup", func() {
		catalog := newCatalog(configItem(clusterID, "prod-euw1", "Kubernetes::Cluster"))
		defer catalog.server.Close()
		state := resolvedState(api.Resource{Provider: "nuclei", Scope: "api.example.test", UID: "input"})

		match, unresolved, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), missioncontrol.ResolveOptions{
				State: state, Target: api.TargetDocument{ID: "target", Cluster: "prod-euw1"},
			})

		Expect(err).ToNot(HaveOccurred())
		Expect(unresolved).To(BeNil())
		Expect(match.ConfigID.String()).To(Equal(clusterID))
		Expect(match.RolledUp).To(BeTrue())
	})
})
