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
		Client:   client,
		Resolver: missioncontrol.NewResolver(client),
		Server:   c.server.URL,
		Context:  "test",
	}
}

func finding(lineNo int, name string, severity api.Severity) api.Finding {
	return api.Finding{
		ScanID: "01JSCAN", LineNo: lineNo, TargetID: "api.example.test",
		TemplateID: name, Name: name, Severity: severity,
		Host: "api.example.test", MatchedAt: "https://api.example.test/" + name,
	}
}

var hostTargets = map[string]api.TargetDocument{
	"api.example.test": {ID: "api.example.test", Kind: api.KindHost, Cluster: "prod-euw1"},
}

var _ = Describe("uploading a scan", func() {
	It("pushes one insight per resolved finding, under the agent's name", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Kubernetes::Ingress"))
		defer catalog.server.Close()

		result, err := uploaderFor(catalog).Upload(context.Background(), nucleiScan(),
			[]api.Finding{
				finding(1, "tls-version", api.SeverityHigh),
				finding(2, "weak-cipher", api.SeverityMedium),
			},
			hostTargets, missioncontrol.UploadOptions{})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Pushed).To(Equal(2))
		Expect(result.Resolved).To(Equal(2))
		Expect(result.RolledUp).To(BeZero())
		Expect(result.Unresolved).To(BeEmpty())
		Expect(catalog.pushAgent).To(Equal(missioncontrol.DefaultAgent))
		Expect(catalog.pushes).To(HaveLen(1))
		Expect(catalog.pushes[0]).To(HaveLen(2))
		Expect(result.Configs).To(HaveLen(1))
		Expect(result.Configs[0].Insights).To(Equal(2))
		Expect(result.Configs[0].Type).To(Equal("Kubernetes::Ingress"))
	})

	// The point of a dry run is to see the coverage before writing to a shared
	// system, so it must do the same resolution and report the same numbers.
	It("resolves but sends nothing on a dry run", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Kubernetes::Ingress"))
		defer catalog.server.Close()

		result, err := uploaderFor(catalog).Upload(context.Background(), nucleiScan(),
			[]api.Finding{finding(1, "tls-version", api.SeverityHigh)},
			hostTargets, missioncontrol.UploadOptions{DryRun: true})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.DryRun).To(BeTrue())
		Expect(result.Resolved).To(Equal(1))
		Expect(result.Pushed).To(BeZero())
		Expect(catalog.pushes).To(BeEmpty())
	})

	It("separates what landed on the resource from what rolled up", func() {
		catalog := newCatalog(
			configItem(instanceID, "api.example.test", "Kubernetes::Ingress"),
			configItem(clusterID, "prod-euw1", "Kubernetes::Cluster"),
		)
		defer catalog.server.Close()

		elsewhere := finding(2, "open-redirect", api.SeverityLow)
		elsewhere.Host = "unknown.example.test"
		elsewhere.MatchedAt = "https://unknown.example.test/redirect"

		result, err := uploaderFor(catalog).Upload(context.Background(), nucleiScan(),
			[]api.Finding{finding(1, "tls-version", api.SeverityHigh), elsewhere},
			hostTargets, missioncontrol.UploadOptions{})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Resolved).To(Equal(1))
		Expect(result.RolledUp).To(Equal(1))
		Expect(result.Pushed).To(Equal(2))
		Expect(result.Configs).To(HaveLen(2))
	})

	It("keeps only findings at or above the severity floor", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Kubernetes::Ingress"))
		defer catalog.server.Close()

		result, err := uploaderFor(catalog).Upload(context.Background(), nucleiScan(),
			[]api.Finding{
				finding(1, "critical-thing", api.SeverityCritical),
				finding(2, "high-thing", api.SeverityHigh),
				finding(3, "low-thing", api.SeverityLow),
				finding(4, "info-thing", api.SeverityInfo),
			},
			hostTargets, missioncontrol.UploadOptions{MinSeverity: api.SeverityHigh})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Total).To(Equal(4))
		Expect(result.Findings).To(Equal(2))
		Expect(result.Pushed).To(Equal(2))
	})

	// `unknown` means the engine used a vocabulary recon does not recognise, not
	// that the finding is unimportant, so a floor of `info` must not hide it.
	It("keeps unknown-severity findings at the info floor", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Kubernetes::Ingress"))
		defer catalog.server.Close()

		result, err := uploaderFor(catalog).Upload(context.Background(), nucleiScan(),
			[]api.Finding{finding(1, "unclassified", api.SeverityUnknown)},
			hostTargets, missioncontrol.UploadOptions{MinSeverity: api.SeverityInfo})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Findings).To(Equal(1))
		Expect(result.Pushed).To(Equal(1))
	})

	It("lists unresolved findings and still pushes the rest", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Kubernetes::Ingress"))
		defer catalog.server.Close()

		orphan := finding(2, "open-redirect", api.SeverityLow)
		orphan.Host = "unknown.example.test"
		orphan.MatchedAt = "https://unknown.example.test/redirect"
		orphan.TargetID = "unknown.example.test"

		result, err := uploaderFor(catalog).Upload(context.Background(), nucleiScan(),
			[]api.Finding{finding(1, "tls-version", api.SeverityHigh), orphan},
			hostTargets, missioncontrol.UploadOptions{})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Pushed).To(Equal(1))
		Expect(result.Unresolved).To(HaveLen(1))
		Expect(result.Unresolved[0].Finding).To(Equal("01JSCAN#2"))
	})

	It("pushes nothing when unresolved findings are an error", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Kubernetes::Ingress"))
		defer catalog.server.Close()

		orphan := finding(2, "open-redirect", api.SeverityLow)
		orphan.Host = "unknown.example.test"
		orphan.MatchedAt = "https://unknown.example.test/redirect"
		orphan.TargetID = "unknown.example.test"

		result, err := uploaderFor(catalog).Upload(context.Background(), nucleiScan(),
			[]api.Finding{finding(1, "tls-version", api.SeverityHigh), orphan},
			hostTargets, missioncontrol.UploadOptions{Unresolved: missioncontrol.UnresolvedError})

		Expect(err).To(MatchError(ContainSubstring("1 of 2 findings could not be resolved")))
		Expect(result.Unresolved).To(HaveLen(1))
		Expect(catalog.pushes).To(BeEmpty())
	})

	It("surfaces a rejected push rather than reporting a clean upload", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Kubernetes::Ingress"))
		catalog.pushFails = true
		defer catalog.server.Close()

		result, err := uploaderFor(catalog).Upload(context.Background(), nucleiScan(),
			[]api.Finding{finding(1, "tls-version", api.SeverityHigh)},
			hostTargets, missioncontrol.UploadOptions{})

		Expect(err).To(MatchError(ContainSubstring("agent-push")))
		Expect(result.Pushed).To(BeZero())
	})

	It("sends nothing when every finding was filtered out", func() {
		catalog := newCatalog(configItem(instanceID, "api.example.test", "Kubernetes::Ingress"))
		defer catalog.server.Close()

		result, err := uploaderFor(catalog).Upload(context.Background(), nucleiScan(),
			[]api.Finding{finding(1, "info-thing", api.SeverityInfo)},
			hostTargets, missioncontrol.UploadOptions{MinSeverity: api.SeverityHigh})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Findings).To(BeZero())
		Expect(catalog.pushes).To(BeEmpty())
	})

	DescribeTable("the unresolved policy is validated rather than defaulted",
		func(value string, expected missioncontrol.UnresolvedPolicy, valid bool) {
			policy, err := missioncontrol.ParseUnresolvedPolicy(value)
			if !valid {
				Expect(err).To(MatchError(ContainSubstring("unknown --unresolved policy")))
				return
			}
			Expect(err).ToNot(HaveOccurred())
			Expect(policy).To(Equal(expected))
		},
		Entry("empty means report", "", missioncontrol.UnresolvedReport, true),
		Entry("report", "report", missioncontrol.UnresolvedReport, true),
		Entry("error", "error", missioncontrol.UnresolvedError, true),
		Entry("anything else is refused", "fail", missioncontrol.UnresolvedPolicy(""), false),
	)
})
