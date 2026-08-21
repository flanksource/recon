package runtimecontext_test

import (
	"context"
	"testing"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/runtimecontext"
	"github.com/flanksource/recon/internal/store"
)

func TestRuntimeContext(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "runtime context")
}

var _ = Describe("the database runtime context", Label("db"), func() {
	It("carries the request cancellation, database, and configured namespace", func() {
		if testing.Short() {
			Skip("needs a database")
		}
		database := dbtest.ForGinkgo(dbtest.Options{Name: "recon_runtime_context"})
		factory := runtimecontext.New(store.New(database.Gorm()), "tenant-a")

		base, cancel := context.WithCancel(context.Background())
		resolved := factory(base)
		Expect(resolved.DB()).ToNot(BeNil())
		Expect(resolved.GetNamespace()).To(Equal("tenant-a"))

		cancel()
		Expect(resolved.Err()).To(MatchError(context.Canceled))
	})
})
