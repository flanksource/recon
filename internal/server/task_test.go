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
