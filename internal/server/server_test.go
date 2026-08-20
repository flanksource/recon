package server_test

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon"
	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/cli"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/server"
	"github.com/flanksource/recon/internal/store"
)

func TestServer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "server")
}

// commandTree builds the CLI once per test binary.
//
// Building it is what registers the entities, and they register into a registry
// that belongs to the process. `reconctl serve` builds the tree once; a suite
// that builds it per spec would list every entity as many times as it built,
// and would be testing an arrangement that never exists in production.
var commandTree = sync.OnceValue(cli.New)

var _ = Describe("the HTTP surface", Ordered, Label("db"), func() {
	var (
		suite *httptest.Server
		st    *store.Store
		spec  map[string]any
	)

	BeforeAll(func() {
		if testing.Short() {
			Skip("needs a database")
		}

		db := dbtest.ForGinkgo(dbtest.Options{
			Name:        "recon_server",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())

		// Building the command tree is what registers the entities, so the
		// server under test is wired exactly as `reconctl serve` wires it.
		root := commandTree()
		// The UI is wired as `serve` wires it: with the SPA claiming "/", an
		// unmatched API path could otherwise fall through to index.html, and a
		// suite that left it out would not see that.
		suite = httptest.NewServer(server.Handler(server.Config{
			Host: "localhost", Root: root, Registry: cli.EntityRegistry(), Store: st,
			UI: recon.UI, UIDir: recon.UIDir,
		}))
		DeferCleanup(suite.Close)

		spec = getJSON[map[string]any](suite.URL + "/api/openapi.json")
	})

	Describe("the generated OpenAPI description", func() {
		It("gives every entity a list and a get", func() {
			paths, _ := spec["paths"].(map[string]any)
			for _, entity := range []string{"target", "scan", "finding", "discover", "probe", "profile", "engine"} {
				Expect(paths).To(HaveKey("/api/v1/"+entity), entity)
				Expect(paths).To(HaveKey("/api/v1/"+entity+"/{id}"), entity)
			}
		})

		It("never gives one method and path to two operations", func() {
			// net/http panics on a duplicate pattern at startup, so a collision
			// here is a server that will not boot. It has happened: an entity
			// whose name contains a CRUD keyword used to infer the wrong method
			// and land on its own collection route.
			seen := map[string]string{}
			paths, _ := spec["paths"].(map[string]any)
			for path, item := range paths {
				methods, _ := item.(map[string]any)
				for method, operation := range methods {
					key := strings.ToUpper(method) + " " + path
					id := operationID(operation)
					Expect(seen).ToNot(HaveKey(key),
						"%s is claimed by both %s and %s", key, seen[key], id)
					seen[key] = id
				}
			}
		})

		It("runs scan and discovery on their collection resources", func() {
			paths, _ := spec["paths"].(map[string]any)
			for _, resource := range []string{"scan", "discover"} {
				methods, _ := paths["/api/v1/"+resource].(map[string]any)
				Expect(methods).To(HaveKey("get"), resource+" history")
				Expect(methods).To(HaveKey("post"), resource+" execution")
			}
			Expect(paths).ToNot(HaveKey("/api/v1/target/scan"))
			Expect(paths).ToNot(HaveKey("/api/v1/target/discover"))
		})

		It("offers a custom run every choice the CLI takes", func() {
			// The dialog builds its request from these, so a choice the action
			// accepts but the spec omits is a control the UI cannot offer.
			declared := func(path string) map[string]bool {
				named := map[string]bool{}
				for _, parameter := range parameters(spec, path, "post") {
					named[parameter] = true
				}
				return named
			}

			scan := declared("/api/v1/scan")
			for _, choice := range []string{
				"engine", "profile", "override",
				"discovery-engine", "discovery-profile", "discovery-override",
			} {
				Expect(scan).To(HaveKey(choice), "scan cannot be customised by %s", choice)
			}

			discover := declared("/api/v1/discover")
			for _, choice := range []string{"engine", "profile", "override"} {
				Expect(discover).To(HaveKey(choice), "discovery cannot be customised by %s", choice)
			}
		})

		It("keeps the commands that administer the process off the API", func() {
			// Publishing a CLI publishes every runnable command in the tree. These
			// three are not resources: `migrate` altered the schema on an
			// unauthenticated POST, `db url` printed the DSN, and `serve` would
			// start a second server inside this one.
			paths, _ := spec["paths"].(map[string]any)
			for _, local := range []string{"/api/v1/migrate", "/api/v1/serve", "/api/v1/db/url"} {
				Expect(paths).ToNot(HaveKey(local), local)
			}

			for _, local := range []string{"/api/v1/migrate", "/api/v1/serve", "/api/v1/db/url"} {
				res, err := http.Post(suite.URL+local, "application/json", strings.NewReader("{}"))
				Expect(err).ToNot(HaveOccurred())
				Expect(res.StatusCode).To(Equal(http.StatusNotFound), local)
				Expect(res.Body.Close()).To(Succeed())
			}
		})

		It("puts an update behind a method that is not GET", func() {
			methods, _ := spec["paths"].(map[string]any)["/api/v1/target"].(map[string]any)
			Expect(methods).To(HaveKey("get"))
			Expect(methods).To(HaveKey("put"))
			Expect(operationID(methods["get"])).To(Equal("target"))
			Expect(operationID(methods["put"])).To(Equal("target_update"))
		})

		It("exposes every selector field as a query parameter", func() {
			// The filter bar is generated from these, so a field the selector
			// understands but the spec omits is a filter the UI cannot offer.
			declared := map[string]bool{}
			for _, parameter := range parameters(spec, "/api/v1/target", "get") {
				declared[parameter] = true
			}

			opts := reflect.TypeOf(store.TargetOpts{})
			for i := range opts.NumField() {
				flag := opts.Field(i).Tag.Get("flag")
				Expect(declared).To(HaveKey(flag),
					"selector field %s is not offered as a query parameter", opts.Field(i).Name)
			}
		})
	})

	Describe("the entity index", func() {
		It("lists every entity with the operations it supports", func() {
			var index []struct {
				Name       string `json:"name"`
				Operations []struct {
					Verb string `json:"verb"`
				} `json:"operations"`
			}
			Expect(json.Unmarshal(get(suite.URL+"/api/entities"), &index)).To(Succeed())

			verbs := map[string][]string{}
			for _, entity := range index {
				for _, operation := range entity.Operations {
					verbs[entity.Name] = append(verbs[entity.Name], operation.Verb)
				}
			}

			Expect(verbs).To(HaveKeyWithValue("target",
				[]string{"list", "get", "create", "update"}))
			Expect(verbs).To(HaveKeyWithValue("profile",
				[]string{"list", "get", "create", "update", "delete"}))
			Expect(verbs).To(HaveKeyWithValue("engine", []string{"list", "get"}))
		})
	})

	Describe("targets", func() {
		BeforeAll(func() {
			Expect(st.SaveTarget(GinkgoT().Context(), api.TargetDocument{
				Schema: api.TargetSchemaRef, Version: api.TargetVersion,
				Host: "one.example.test", Class: api.ClassNonProd,
				Profiles: []string{"safe"}, Tags: []string{"http"},
			})).To(Succeed())
		})

		It("lists them", func() {
			targets := getJSON[[]api.TargetDocument](suite.URL + "/api/v1/target")
			Expect(targets).To(HaveLen(1))
			Expect(targets[0].Host).To(Equal("one.example.test"))
		})

		It("filters them from the query string", func() {
			Expect(getJSON[[]api.TargetDocument](
				suite.URL + "/api/v1/target?class=non-prod")).To(HaveLen(1))
			Expect(getJSON[[]api.TargetDocument](
				suite.URL + "/api/v1/target?class=prod")).To(BeEmpty())
		})

		It("rejects a class that cannot match instead of returning nothing", func() {
			Expect(errorOf(get(suite.URL + "/api/v1/target?class=staging"))).
				To(ContainSubstring(`unknown class "staging"`))
		})

		It("refuses an edit to a machine-owned section", func() {
			// These are discovery's output. Accepting the edit and letting the
			// next sweep overwrite it would be worse than refusing it.
			Expect(errorOf(send(http.MethodPut, suite.URL+"/api/v1/target",
				`{"id":"one.example.test","http":{"status_code":200}}`))).
				To(ContainSubstring("not editable"))
		})

		// Discovery records what it sees but never classifies it, so this is how
		// a host a sweep found joins the inventory. An update refuses a host
		// that is not already there, which left the Discover dialog's "add to
		// inventory" with nothing to call.
		It("classifies a discovered host into the inventory", func() {
			created := send(http.MethodPost, suite.URL+"/api/v1/target",
				`{"host":"found.example.test","class":"non-prod","profiles":["safe"],"tags":["http"]}`)

			var target api.TargetDocument
			Expect(json.Unmarshal(created, &target)).To(Succeed(), string(created))
			Expect(target.Host).To(Equal("found.example.test"))
			Expect(target.Class).To(Equal(api.ClassNonProd))

			Expect(getJSON[api.TargetDocument](
				suite.URL + "/api/v1/target/found.example.test").Tags).To(Equal([]string{"http"}))
		})

		It("refuses to add a host that is already curated", func() {
			// Overwriting would discard whoever classified it first, and the
			// caller asked to add rather than to replace.
			Expect(errorOf(send(http.MethodPost, suite.URL+"/api/v1/target",
				`{"host":"one.example.test","class":"prod","profiles":["safe"],"tags":[]}`))).
				To(ContainSubstring("already in the inventory"))
		})

		It("refuses to rename a target", func() {
			Expect(errorOf(send(http.MethodPut, suite.URL+"/api/v1/target",
				`{"id":"one.example.test","host":"two.example.test"}`))).
				To(ContainSubstring("host is not editable"))
		})
	})

	// A parameter the spec merely names is a text box: the filter bar can send
	// it but cannot say what it accepts, which is how the UI ended up loading
	// the whole inventory and narrowing it in the browser. These assert the two
	// halves that replace that — the spec marks each parameter as a control,
	// and the lookup says what the control offers.
	Describe("filters", func() {
		It("marks every selector parameter as a filter control", func() {
			for name, meta := range parameterRoles(spec, "/api/v1/target", "get") {
				Expect(meta).To(Equal("filter"), "parameter %s carries no control", name)
			}
		})

		It("offers a closed vocabulary from the code", func() {
			// A class cannot be discovered from the data: a class nobody has
			// used yet is still one you can classify a host as.
			Expect(lookup(suite.URL+"/api/v1/target", "")["class"].values()).
				To(Equal([]string{"deactivated", "internal", "non-prod", "prod", "public", "unclassified"}))
		})

		It("offers an open vocabulary from the database", func() {
			// Tags are whatever anyone has typed, so the only honest source is
			// what is in the inventory now.
			Expect(lookup(suite.URL+"/api/v1/target", "")["tags"].values()).
				To(Equal([]string{"http"}))
		})

		It("answers a search with only the filter it asked about", func() {
			// Narrowing server-side is what keeps a vocabulary larger than the
			// lookup's 200-option cap reachable. Re-enumerating the other
			// filters would also cost a query each per keystroke.
			filters := lookup(suite.URL+"/api/v1/target", "&__lookup_filter=hosts&__lookup_q=one")
			Expect(maps.Keys(filters)).To(ConsistOf("hosts"))
			Expect(filters["hosts"].values()).To(Equal([]string{"one.example.test"}))
			Expect(filters["hosts"].Total).To(Equal(1))
		})

		It("gives every listing something to narrow by", func() {
			for _, entity := range []string{"target", "scan", "finding", "discover", "probe", "profile", "engine"} {
				Expect(lookup(suite.URL+"/api/v1/"+entity, "")).ToNot(BeEmpty(), entity)
			}
		})
	})

	Describe("profiles", func() {
		It("round-trips a nested config through create and get", func() {
			// A flag value is a string, so a nested object has to survive being
			// encoded into one and decoded back.
			created := send(http.MethodPost, suite.URL+"/api/v1/profile",
				`{"kind":"scan","engine":"nuclei","name":"api-test",`+
					`"config":{"tags":["headers"],"rate-limit":25}}`)
			Expect(string(created)).To(ContainSubstring("api-test"))

			profile := getJSON[api.Profile](suite.URL + "/api/v1/profile/scan:nuclei:api-test")
			Expect(profile.Config).To(HaveKeyWithValue("rate-limit", BeNumerically("==", 25)))
			Expect(profile.Config).To(HaveKeyWithValue("tags", ConsistOf("headers")))
		})

		It("rejects a config its engine would reject", func() {
			Expect(errorOf(send(http.MethodPost, suite.URL+"/api/v1/profile",
				`{"kind":"scan","engine":"nuclei","name":"bad","config":{"nonsense":1}}`))).
				To(ContainSubstring("unsupported option: nonsense"))
		})

		It("rejects mutually exclusive Nuclei execution modes", func() {
			Expect(errorOf(send(http.MethodPost, suite.URL+"/api/v1/profile",
				`{"kind":"scan","engine":"nuclei","name":"bad-modes","config":{"automatic-scan":true,"dast":true}}`))).
				To(ContainSubstring("automatic-scan cannot be combined with dast"))
		})

		It("rejects an unknown engine", func() {
			Expect(errorOf(send(http.MethodPost, suite.URL+"/api/v1/profile",
				`{"kind":"scan","engine":"nmap","name":"x","config":{}}`))).
				To(ContainSubstring("unknown scan engine: nmap"))
		})
	})

	Describe("engines", func() {
		It("serves the registry, including the option catalog the form needs", func() {
			engines := getJSON[[]api.EngineSpec](suite.URL + "/api/v1/engine")
			Expect(engines).To(HaveLen(7))

			var nuclei api.EngineSpec
			for _, engine := range engines {
				if engine.Name == "nuclei" {
					nuclei = engine
				}
			}
			Expect(nuclei.Kind).To(Equal("scan"))
			Expect(nuclei.Sections).ToNot(BeNil())
			Expect(nuclei.Defaults).To(Equal("safe"))
		})

		It("reports a discovery engine's place in the chain", func() {
			engine := getJSON[api.EngineSpec](suite.URL + "/api/v1/engine/naabu")
			Expect(engine.Accepts).To(Equal("hosts"))
			Expect(engine.Emits).To(Equal("endpoints"))
		})
	})
})

// errorOf reads the error out of the executor's response envelope. Asserting on
// the raw bytes would be asserting on JSON escaping rather than on the message.
func errorOf(body []byte) string {
	var envelope struct {
		Error string `json:"error"`
	}
	Expect(json.Unmarshal(body, &envelope)).To(Succeed(),
		fmt.Sprintf("not an error envelope: %s", truncate(body)))
	Expect(envelope.Error).ToNot(BeEmpty(),
		fmt.Sprintf("expected an error, got %s", truncate(body)))
	return envelope.Error
}

func operationID(operation any) string {
	fields, _ := operation.(map[string]any)
	id, _ := fields["operationId"].(string)
	return id
}

func parameters(spec map[string]any, path, method string) []string {
	paths, _ := spec["paths"].(map[string]any)
	item, _ := paths[path].(map[string]any)
	operation, _ := item[method].(map[string]any)
	declared, _ := operation["parameters"].([]any)

	var names []string
	for _, parameter := range declared {
		fields, _ := parameter.(map[string]any)
		if name, ok := fields["name"].(string); ok {
			names = append(names, name)
		}
	}
	return names
}

// parameterRoles maps each declared query parameter to the control the UI is
// told to render it as.
func parameterRoles(spec map[string]any, path, method string) map[string]string {
	paths, _ := spec["paths"].(map[string]any)
	item, _ := paths[path].(map[string]any)
	operation, _ := item[method].(map[string]any)
	declared, _ := operation["parameters"].([]any)

	roles := map[string]string{}
	for _, parameter := range declared {
		fields, _ := parameter.(map[string]any)
		name, ok := fields["name"].(string)
		if !ok {
			continue
		}
		meta, _ := fields["x-clicky"].(map[string]any)
		role, _ := meta["role"].(string)
		roles[name] = role
	}
	return roles
}

// lookupFilter is one control as the lookup describes it. Options is keyed by
// the value the filter sends, which is what makes values() the option set.
type lookupFilter struct {
	Label   string                     `json:"label"`
	Multi   bool                       `json:"multi"`
	Total   int                        `json:"total"`
	Options map[string]json.RawMessage `json:"options"`
}

func (f lookupFilter) values() []string {
	values := make([]string, 0, len(f.Options))
	for value := range f.Options {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

// lookup asks a listing what its filters offer. search is the extra query
// string that narrows one of them, or "" for every filter's head set.
func lookup(url, search string) map[string]lookupFilter {
	response := getJSON[struct {
		Filters map[string]lookupFilter `json:"filters"`
	}](url + "?__lookup=filters" + search)
	return response.Filters
}

func get(url string) []byte {
	response, err := http.Get(url)
	Expect(err).ToNot(HaveOccurred())
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	Expect(err).ToNot(HaveOccurred())
	return body
}

func send(method, url, body string) []byte {
	request, err := http.NewRequest(method, url, strings.NewReader(body))
	Expect(err).ToNot(HaveOccurred())
	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	Expect(err).ToNot(HaveOccurred())
	defer response.Body.Close()

	read, err := io.ReadAll(response.Body)
	Expect(err).ToNot(HaveOccurred())
	return read
}

func getJSON[T any](url string) T {
	body := get(url)
	var decoded T
	Expect(json.Unmarshal(body, &decoded)).To(Succeed(),
		fmt.Sprintf("%s returned %s", url, truncate(body)))
	return decoded
}

func truncate(body []byte) string {
	if len(body) > 400 {
		return string(body[:400]) + "…"
	}
	return string(body)
}
