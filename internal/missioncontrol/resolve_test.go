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

// catalog is a stand-in for Mission Control holding a fixed set of config
// items. It answers the two calls the resolver makes — the narrowing search and
// the exact read — the same way the real server does: the search compares the
// whole external_id array cast to text, which is why only a substring can match
// it there and the exact confirmation has to happen client-side.
type catalog struct {
	server   *httptest.Server
	items    []dutymodels.ConfigItem
	searches []string
	// pushes records each batch that reached /upstream/push, and pushAgent the
	// name it was pushed under.
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
			Expect(request.Configs).To(HaveLen(1))
			search := request.Configs[0].Search
			c.searches = append(c.searches, search)
			writeJSON(w, query.SearchResourcesResponse{Configs: c.search(search)})
		case "/db/config_items":
			writeJSON(w, c.byIDs(r.URL.Query().Get("id")))
		case "/upstream/push":
			if c.pushFails {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"access denied"}`))
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

func (c *catalog) client() *sdk.Client { return sdk.New(c.server.URL, "tok") }

// search mirrors the server's matching: an exact, case-insensitive name
// comparison OR a substring of the external_id array rendered as text.
func (c *catalog) search(expression string) []query.SelectedResource {
	name, external := parseSearch(expression)
	var out []query.SelectedResource
	for _, item := range c.items {
		nameHit := name != "" && strings.EqualFold(lo.FromPtr(item.Name), name)
		externalHit := external != "" && strings.Contains(
			strings.ToLower("{"+strings.Join(item.ExternalID, ",")+"}"), strings.ToLower(external))
		if nameHit || externalHit {
			out = append(out, query.SelectedResource{
				ID: item.ID.String(), Name: lo.FromPtr(item.Name), Type: lo.FromPtr(item.Type),
			})
		}
	}
	return out
}

func (c *catalog) byIDs(filter string) []dutymodels.ConfigItem {
	wanted := strings.Split(strings.Trim(strings.TrimPrefix(filter, "in."), "()"), ",")
	out := []dutymodels.ConfigItem{}
	for _, item := range c.items {
		if lo.Contains(wanted, item.ID.String()) {
			out = append(out, item)
		}
	}
	return out
}

// parseSearch reads back the `name="x" | external_id="*x*"` the resolver emits.
func parseSearch(expression string) (name, external string) {
	for _, clause := range strings.Split(expression, "|") {
		field, value, found := strings.Cut(strings.TrimSpace(clause), "=")
		if !found {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch field {
		case "name":
			name = value
		case "external_id":
			external = strings.Trim(value, "*")
		}
	}
	return name, external
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
	duplicateA = "3f2a1c4e-0000-4000-8000-00000000000d"
	duplicateB = "3f2a1c4e-0000-4000-8000-00000000000e"
)

var _ = Describe("resolving a finding to a config item", func() {
	var host api.TargetDocument

	BeforeEach(func() {
		host = api.TargetDocument{ID: "api.example.test", Kind: api.KindHost, Cluster: "prod-euw1"}
	})

	It("prefers the resource the engine named, over its account", func() {
		catalog := newCatalog(
			configItem(instanceID, "web-1", "AWS::EC2::Instance", "arn:aws:ec2:eu-west-1:1:instance/i-1"),
			configItem(accountID, "acme-prod", "AWS::Account", "1"),
		)
		defer catalog.server.Close()

		match, unresolved, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), nucleiScan(),
			api.Finding{MatchedAt: "arn:aws:ec2:eu-west-1:1:instance/i-1", Host: "acme-prod"},
			api.TargetDocument{ID: "acme-prod", Kind: api.KindProviderContext})

		Expect(err).ToNot(HaveOccurred())
		Expect(unresolved).To(BeNil())
		Expect(match.ConfigID.String()).To(Equal(instanceID))
		Expect(match.ConfigName).To(Equal("web-1"))
		Expect(match.MatchedOn).To(Equal("arn:aws:ec2:eu-west-1:1:instance/i-1"))
		Expect(match.RolledUp).To(BeFalse())
	})

	It("matches on the host's own name when the catalog holds it", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Kubernetes::Ingress"))
		defer catalog.server.Close()

		match, unresolved, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), nucleiScan(), tlsFinding(), host)

		Expect(err).ToNot(HaveOccurred())
		Expect(unresolved).To(BeNil())
		Expect(match.MatchedOn).To(Equal("api.example.test"))
		Expect(match.RolledUp).To(BeFalse())
	})

	// Nothing in the catalog is the host itself, so the finding belongs to the
	// cluster that contains it rather than to nothing at all.
	It("rolls up to the cluster when neither the URL nor the host is known", func() {
		catalog := newCatalog(configItem(clusterID, "prod-euw1", "Kubernetes::Cluster"))
		defer catalog.server.Close()

		match, unresolved, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), nucleiScan(), tlsFinding(), host)

		Expect(err).ToNot(HaveOccurred())
		Expect(unresolved).To(BeNil())
		Expect(match.ConfigID.String()).To(Equal(clusterID))
		Expect(match.MatchedOn).To(Equal("prod-euw1"))
		Expect(match.RolledUp).To(BeTrue())
	})

	It("reports what it tried when nothing claims the finding", func() {
		catalog := newCatalog(configItem(accountID, "somewhere-else", "AWS::Account"))
		defer catalog.server.Close()

		match, unresolved, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), nucleiScan(), tlsFinding(), host)

		Expect(err).ToNot(HaveOccurred())
		Expect(match).To(BeNil())
		Expect(unresolved.Finding).To(Equal("01JSCAN#4"))
		Expect(unresolved.Host).To(Equal("api.example.test"))
		Expect(unresolved.Severity).To(Equal(api.SeverityHigh))
		Expect(unresolved.Tried).To(Equal([]string{
			"https://api.example.test:443", "api.example.test", "prod-euw1",
		}))
		Expect(unresolved.Reason).To(ContainSubstring("no catalog config item"))
	})

	// Two config items answering to the same name is not a coin toss: the rung
	// is skipped, the upload still lands on the enclosing scope, and the report
	// says which ids collided.
	It("rolls up rather than guessing between two configs with the same name", func() {
		catalog := newCatalog(
			configItem(duplicateA, "api.example.test", "Kubernetes::Ingress"),
			configItem(duplicateB, "api.example.test", "AWS::Route53::Record"),
			configItem(clusterID, "prod-euw1", "Kubernetes::Cluster"),
		)
		defer catalog.server.Close()

		match, unresolved, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), nucleiScan(), tlsFinding(), host)

		Expect(err).ToNot(HaveOccurred())
		Expect(unresolved).To(BeNil())
		Expect(match.ConfigID.String()).To(Equal(clusterID))
		Expect(match.RolledUp).To(BeTrue())
		Expect(match.Note).To(ContainSubstring("api.example.test matched 2 config items"))
		Expect(match.Note).To(ContainSubstring(duplicateA))
	})

	// A substring hit is only a candidate. Confirming it client-side is what
	// stops dev.api.example.test from absorbing api.example.test's findings.
	It("does not accept a config whose external id merely contains the value", func() {
		catalog := newCatalog(configItem(instanceID, "dev-ingress", "Kubernetes::Ingress", "dev.api.example.test"))
		defer catalog.server.Close()

		match, unresolved, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), nucleiScan(), tlsFinding(), host)

		Expect(err).ToNot(HaveOccurred())
		Expect(match).To(BeNil())
		Expect(unresolved).ToNot(BeNil())
	})

	It("asks the catalog once per distinct identity", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Kubernetes::Ingress"))
		defer catalog.server.Close()
		resolver := missioncontrol.NewResolver(catalog.client())

		for range 3 {
			_, _, err := resolver.Resolve(context.Background(), nucleiScan(), tlsFinding(), host)
			Expect(err).ToNot(HaveOccurred())
		}

		// The URL misses and the host hits, and both answers are remembered.
		Expect(catalog.searches).To(HaveLen(2))
	})

	// A star is a wildcard and a comma splits the value in two, so either would
	// quietly widen the query into matching something else.
	It("skips an identity the search grammar would reinterpret", func() {
		catalog := newCatalog(configItem(clusterID, "prod-euw1", "Kubernetes::Cluster"))
		defer catalog.server.Close()

		finding := tlsFinding()
		finding.MatchedAt = `https://api.example.test/*`
		finding.Host = "api.example.test,dev.example.test"

		match, unresolved, err := missioncontrol.NewResolver(catalog.client()).Resolve(
			context.Background(), nucleiScan(), finding, host)

		Expect(err).ToNot(HaveOccurred())
		Expect(unresolved).To(BeNil())
		Expect(match.MatchedOn).To(Equal("prod-euw1"))
		Expect(catalog.searches).To(HaveLen(1))
	})
})
