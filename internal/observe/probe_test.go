package observe_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/observe"
)

var _ = Describe("folding a liveness probe into a target", func() {
	const now = "2026-08-11T09:00:00Z"

	// A host as discovery leaves it: technology, certificate and ports that only
	// the heavier engines can see.
	discovered := func() api.TargetDocument {
		title, webserver := "API", "nginx"
		subjectCN := "api.example.test"
		return api.TargetDocument{
			Host: "api.example.test",
			Observed: &api.Observed{
				FirstObserved: "2026-01-01T00:00:00Z",
				LastSeen:      "2026-08-01T00:00:00Z",
				LastAttempt:   "2026-08-01T00:00:00Z",
			},
			Network: &api.Network{IP: "192.0.2.1", OpenPorts: []int{443, 8443}},
			HTTP: &api.HTTP{
				URL: "https://api.example.test", Scheme: "https", Port: 443,
				StatusCode: 200, Title: &title, Webserver: &webserver,
				KnownPaths: []string{"/", "/login"},
			},
			Tech: &api.Tech{Names: []string{"Go"}},
			TLS:  &api.TLS{SubjectCN: &subjectCN},
		}
	}

	live := observe.Probe{
		Host: "api.example.test", URL: "https://api.example.test", Scheme: "https",
		Port: 443, IP: "192.0.2.9", StatusCode: 204, ResponseTime: 125 * time.Millisecond,
	}

	It("records what the probe saw", func() {
		updated, err := observe.ApplyProbe(discovered(), live, now)
		Expect(err).ToNot(HaveOccurred())

		Expect(updated.Observed.LastSeen).To(Equal(now))
		Expect(updated.Observed.LastAttempt).To(Equal(now))
		Expect(updated.HTTP.StatusCode).To(Equal(204))
		Expect(*updated.HTTP.ResponseTime).To(Equal("125ms"))
		Expect(*updated.HTTP.Failed).To(BeFalse())
		Expect(updated.Network.IP).To(Equal("192.0.2.9"))
	})

	// The whole reason this is not observe.Apply: a ping knows none of these, and
	// replacing the machine-owned sections wholesale would erase them on every
	// status refresh.
	It("leaves technology, TLS, ports and paths as the engines that found them left them", func() {
		updated, err := observe.ApplyProbe(discovered(), live, now)
		Expect(err).ToNot(HaveOccurred())

		Expect(updated.Tech).To(Equal(discovered().Tech))
		Expect(updated.TLS).To(Equal(discovered().TLS))
		Expect(updated.Network.OpenPorts).To(Equal([]int{443, 8443}))
		Expect(updated.HTTP.KnownPaths).To(Equal([]string{"/", "/login"}))
		Expect(*updated.HTTP.Title).To(Equal("API"))
		Expect(*updated.HTTP.Webserver).To(Equal("nginx"))
	})

	It("keeps the first sighting rather than restamping it", func() {
		updated, err := observe.ApplyProbe(discovered(), live, now)
		Expect(err).ToNot(HaveOccurred())
		Expect(updated.Observed.FirstObserved).To(Equal("2026-01-01T00:00:00Z"))
	})

	It("dates the first sighting of a host nothing had reached before", func() {
		fresh := api.TargetDocument{Host: "api.example.test"}
		updated, err := observe.ApplyProbe(fresh, live, now)
		Expect(err).ToNot(HaveOccurred())
		Expect(updated.Observed.FirstObserved).To(Equal(now))
	})

	Describe("a probe that failed", func() {
		failed := observe.Probe{
			Host: "api.example.test", Failed: true, Error: "connection refused",
			Failure: api.FailureRefused,
		}

		// The status code below stays at its last good value, so this is the only
		// thing on the row that says the host is not answering right now.
		It("classifies the failure so the inventory can badge and filter it", func() {
			updated, err := observe.ApplyProbe(discovered(), failed, now)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated.Observed.Failure).To(Equal(api.FailureRefused))
		})

		It("records the attempt and the error without moving last seen", func() {
			updated, err := observe.ApplyProbe(discovered(), failed, now)
			Expect(err).ToNot(HaveOccurred())

			Expect(updated.Observed.LastAttempt).To(Equal(now))
			Expect(updated.Observed.LastSeen).To(Equal("2026-08-01T00:00:00Z"))
			Expect(updated.Observed.Error).To(Equal("connection refused"))
			Expect(*updated.HTTP.Failed).To(BeTrue())
		})

		It("keeps the last successful snapshot, which is still the best thing known", func() {
			updated, err := observe.ApplyProbe(discovered(), failed, now)
			Expect(err).ToNot(HaveOccurred())

			Expect(updated.HTTP.StatusCode).To(Equal(200))
			Expect(updated.Tech).To(Equal(discovered().Tech))
			Expect(updated.Network.OpenPorts).To(Equal([]int{443, 8443}))
		})

		// An unexplained failure still has to be one: leaving the kind empty would
		// send the row back to rendering its last good status code, which is the
		// state this whole classification exists to end.
		It("names a failure the prober did not explain", func() {
			updated, err := observe.ApplyProbe(discovered(),
				observe.Probe{Host: "api.example.test", Failed: true}, now)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated.Observed.Error).To(Equal(observe.FailedProbeError))
			Expect(updated.Observed.Failure).To(Equal(api.FailureOther))
		})
	})

	It("clears an error left by an earlier failure once the host answers", func() {
		target := discovered()
		target.Observed.Error = "connection refused"
		target.Observed.Failure = api.FailureRefused

		updated, err := observe.ApplyProbe(target, live, now)
		Expect(err).ToNot(HaveOccurred())
		Expect(updated.Observed.Error).To(BeEmpty())
		Expect(updated.Observed.Failure).To(Equal(api.FailureNone))
	})

	It("refuses an observation of a different host", func() {
		_, err := observe.ApplyProbe(discovered(),
			observe.Probe{Host: "other.example.test"}, now)
		Expect(err).To(MatchError(ContainSubstring("does not match")))
	})

	It("refuses an undated observation", func() {
		_, err := observe.ApplyProbe(discovered(), live, "")
		Expect(err).To(MatchError(ContainSubstring("timestamp is required")))
	})
})
