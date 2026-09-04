package missioncontrol_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/missioncontrol"
)

var _ = Describe("reading a linked config item", func() {
	It("returns the catalog identity and frontend link", func() {
		catalog := newCatalog(configItem(accountID, "Production GCP", "GCP::Project", "flanksource-prod"))
		defer catalog.server.Close()

		linked, err := missioncontrol.LookupConfig(context.Background(), missioncontrol.ConfigLookupOptions{
			Client: catalog.client(),
			Server: catalog.server.URL + "/api",
			ID:     accountID,
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(linked).To(Equal(&missioncontrol.LinkedConfig{
			ID:     accountID,
			Name:   "Production GCP",
			Type:   "GCP::Project",
			URL:    catalog.server.URL + "/catalog/" + accountID,
			Server: catalog.server.URL + "/api",
		}))
	})

	It("returns a linked item that the catalog has marked deleted", func() {
		item := configItem(accountID, "Retired GCP", "GCP::Project", "flanksource-prod")
		deletedAt := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
		item.DeletedAt = &deletedAt
		catalog := newCatalog(item)
		defer catalog.server.Close()

		linked, err := missioncontrol.LookupConfig(context.Background(), missioncontrol.ConfigLookupOptions{
			Client: catalog.client(), Server: catalog.server.URL, ID: accountID,
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(linked.Name).To(Equal("Retired GCP"))
	})
})
