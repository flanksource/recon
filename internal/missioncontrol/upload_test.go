package missioncontrol_test

import (
	"context"

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
