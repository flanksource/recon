package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/flanksource/clicky/task"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/cli"
	"github.com/flanksource/recon/internal/server"
)

// Deliberately without a database. net/http panics when two routes claim one
// method and path, so building the handler at all is the assertion — and it is
// the one that catches an entity registered twice, which used to be possible
// for `probe` because it was both a bare command and, later, an entity.
//
// The equivalent checks in server_test.go sit behind a suite that needs
// Postgres, so on a machine that cannot start one they never run. This is what
// stops a startup panic reaching a release unnoticed.
var _ = Describe("the generated route surface", func() {
	It("gives every run-and-history resource one listing and one action", func() {
		handler := server.Handler(server.Config{
			Host: "localhost", Root: commandTree(), Registry: cli.EntityRegistry(),
		})

		spec := httptest.NewRecorder()
		handler.ServeHTTP(spec, httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil))
		Expect(spec.Code).To(Equal(http.StatusOK), spec.Body.String())

		var document struct {
			Paths map[string]map[string]any `json:"paths"`
		}
		Expect(json.Unmarshal(spec.Body.Bytes(), &document)).To(Succeed())

		for _, resource := range []string{"scan", "discover", "probe"} {
			collection := document.Paths["/api/v1/"+resource]
			Expect(collection).To(HaveKey("get"), resource+" history")
			Expect(collection).To(HaveKey("post"), resource+" execution")
			Expect(document.Paths).To(HaveKey("/api/v1/"+resource+"/{id}"), resource)
		}
	})
})

var _ = Describe("the task API", func() {
	It("lists and expands runs from the process task registry", func() {
		run := task.StartManagedRun("task API fixture", task.WithKind("test"))
		DeferCleanup(func() { run.Finish(task.StatusCancelled, nil) })

		root := commandTree()
		handler := server.Handler(server.Config{
			Host: "localhost", Root: root, Registry: cli.EntityRegistry(),
		})

		listing := httptest.NewRecorder()
		handler.ServeHTTP(listing, httptest.NewRequest(http.MethodGet, "/api/v1/tasks", nil))
		Expect(listing.Code).To(Equal(http.StatusOK), listing.Body.String())

		var runs []task.RunMeta
		Expect(json.Unmarshal(listing.Body.Bytes(), &runs)).To(Succeed())
		var listed *task.RunMeta
		for i := range runs {
			if runs[i].ID == run.ID() {
				listed = &runs[i]
				break
			}
		}
		Expect(listed).ToNot(BeNil())
		Expect(struct {
			ID, Name, Kind, Status string
		}{listed.ID, listed.Name, listed.Kind, listed.Status}).To(Equal(struct {
			ID, Name, Kind, Status string
		}{run.ID(), "task API fixture", "test", string(task.StatusRunning)}))

		detail := httptest.NewRecorder()
		handler.ServeHTTP(detail, httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+run.ID(), nil))
		Expect(detail.Code).To(Equal(http.StatusOK), detail.Body.String())

		var snapshots []task.TaskSnapshot
		Expect(json.Unmarshal(detail.Body.Bytes(), &snapshots)).To(Succeed())
		Expect(snapshots).To(HaveLen(2))
		Expect([]string{snapshots[0].Status, snapshots[1].Status}).To(Equal([]string{
			string(task.StatusRunning), string(task.StatusRunning),
		}))
	})
})
