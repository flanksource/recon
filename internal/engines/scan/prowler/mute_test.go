package prowler

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/mute"
)

var _ = Describe("pushing mute rules into Prowler", func() {
	push := func(config map[string]any, rules ...api.MuteRule) (map[string]any, mute.Plan) {
		GinkgoHelper()
		prepared := make([]mute.Rule, 0, len(rules))
		for _, rule := range rules {
			prepared = append(prepared, mute.Rule{MuteRule: rule})
		}
		result, err := Engine{}.Pushdown(scan.PushdownRequest{Config: config, Rules: prepared})
		Expect(err).ToNot(HaveOccurred())
		return config, result.Plan
	}

	// A finding's template id is the provider-qualified key while
	// --excluded-checks names the check alone.
	It("strips the provider a finding's template id carries", func() {
		config, plan := push(map[string]any{"provider": "gcp"},
			api.MuteRule{Name: "accepted", Templates: api.StringList{"gcp/bucket_public"}})

		Expect(config["excluded-checks"]).To(ConsistOf("bucket_public"))
		Expect(plan.PushedDown).To(HaveKeyWithValue("accepted", "excluded-checks"))
	})

	It("adds to what the profile already excluded", func() {
		config, _ := push(map[string]any{"provider": "gcp", "excluded-checks": []any{"apikeys_key_exists"}},
			api.MuteRule{Name: "accepted", Templates: api.StringList{"gcp/bucket_public"}})

		Expect(config["excluded-checks"]).To(ConsistOf("apikeys_key_exists", "bucket_public"))
	})

	// Prowler excludes by name, so a rule that matches with a pattern cannot be
	// handed over even though the rule itself is a single-dimension one.
	It("leaves a glob to be applied to the results", func() {
		config, plan := push(map[string]any{"provider": "gcp"},
			api.MuteRule{Name: "wildcard", Templates: api.StringList{"gcp/bucket_*"}})

		Expect(plan.PushedDown).To(BeEmpty())
		Expect(config).ToNot(HaveKey("excluded-checks"))
	})

	// A template id without this run's provider matches no finding this run
	// produces, so excluding a check of that name would suppress something the
	// rule never covered.
	It("leaves a check belonging to another provider alone", func() {
		_, plan := push(map[string]any{"provider": "gcp"},
			api.MuteRule{Name: "aws-rule", Templates: api.StringList{"aws/s3_public"}})
		Expect(plan.PushedDown).To(BeEmpty())

		_, plan = push(map[string]any{"provider": "gcp"},
			api.MuteRule{Name: "unqualified", Templates: api.StringList{"bucket_public"}})
		Expect(plan.PushedDown).To(BeEmpty())
	})

	// Half a rule is worse than none: the excluded checks would leave nothing
	// behind while the rest of the rule still matched.
	It("leaves the whole rule alone when one of its checks cannot be expressed", func() {
		config, plan := push(map[string]any{"provider": "gcp"},
			api.MuteRule{Name: "mixed", Templates: api.StringList{"gcp/bucket_public", "gcp/apikeys_*"}})

		Expect(plan.PushedDown).To(BeEmpty())
		Expect(config).ToNot(HaveKey("excluded-checks"))
	})

	It("leaves severity and tag rules to be applied to the results", func() {
		_, plan := push(map[string]any{"provider": "gcp"},
			api.MuteRule{Name: "quiet", Severity: api.StringList{"informational"}},
			api.MuteRule{Name: "noisy", Tags: api.StringList{"storage"}})

		Expect(plan.PushedDown).To(BeEmpty())
	})

	It("pushes nothing when the configuration names no provider", func() {
		_, plan := push(map[string]any{},
			api.MuteRule{Name: "accepted", Templates: api.StringList{"gcp/bucket_public"}})
		Expect(plan.PushedDown).To(BeEmpty())
	})
})
