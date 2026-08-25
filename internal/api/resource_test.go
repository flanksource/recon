package api_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

// How a finding names the thing it is about.
//
// Reading references back out of an engine's preserved record used to live
// here. It moved into the adapter that produces them, because it cannot be done
// generically: a reference is keyed by (provider, scope, uid) and OCSF puts the
// account once at the event level rather than on each resource, so only the
// adapter — which can see the whole record — can build a whole key. See
// prowler.resourceRefs, and the finding_resources relation that carries the
// result back out of the database.
var _ = Describe("the resources a finding names", func() {
	// Half of all GCP uids are opaque numbers, so the name is what an operator
	// recognises and the uid is the last resort.
	DescribeTable("what a reference displays as",
		func(ref api.ResourceRef, expected string) {
			Expect(ref.Display()).To(Equal(expected))
		},
		Entry("the name when it has one",
			api.ResourceRef{UID: "1429543158501771126", Name: "tailscale-router"}, "tailscale-router"),
		Entry("the uid when it does not",
			api.ResourceRef{UID: "1429543158501771126"}, "1429543158501771126"),
	)

	It("omits the fields a reference does not carry", func() {
		encoded, err := json.Marshal(api.ResourceRef{UID: "u"})
		Expect(err).ToNot(HaveOccurred())
		Expect(string(encoded)).To(Equal(`{"uid":"u"}`))
	})

	It("keeps the canonical provider scope identity on finding references", func() {
		resource := api.Resource{
			ID: "01JRESOURCE", Provider: "gcp", Scope: "production", UID: "bucket-1",
			Name: "audit-logs", Type: "storage.googleapis.com/Bucket",
		}

		Expect(resource.Ref()).To(Equal(api.ResourceRef{
			ID: "01JRESOURCE", Provider: "gcp", Scope: "production", UID: "bucket-1",
			Name: "audit-logs", Type: "storage.googleapis.com/Bucket",
		}))
	})
})
