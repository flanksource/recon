package nuclei

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/mute"
)

func pushdown(config map[string]any, rules ...api.MuteRule) (map[string]any, mute.Plan) {
	GinkgoHelper()
	prepared := make([]mute.Rule, 0, len(rules))
	for _, rule := range rules {
		prepared = append(prepared, mute.Rule{MuteRule: rule})
	}
	result, err := Engine{}.Pushdown(scan.PushdownRequest{Config: config, Rules: prepared})
	Expect(err).ToNot(HaveOccurred())
	return config, result.Plan
}

var _ = Describe("pushing mute rules into nuclei", func() {
	It("turns a check rule into an id exclusion", func() {
		config, plan := pushdown(map[string]any{},
			api.MuteRule{Name: "accepted", Templates: api.StringList{"open-redirect"}})

		Expect(config["exclude-id"]).To(ConsistOf("open-redirect"))
		Expect(plan.PushedDown).To(HaveKeyWithValue("accepted", "exclude-id"))
	})

	It("turns a tag rule into a tag exclusion and a severity rule into a severity exclusion", func() {
		config, plan := pushdown(map[string]any{},
			api.MuteRule{Name: "noisy", Tags: api.StringList{"db-vendor"}},
			api.MuteRule{Name: "quiet", Severity: api.StringList{"info"}})

		Expect(config["exclude-tags"]).To(ConsistOf("db-vendor"))
		Expect(config["exclude-severity"]).To(ConsistOf("info"))
		Expect(plan.PushedDown).To(HaveLen(2))
	})

	// Replacing the key would silently switch the profile's own exclusion back
	// on, which is the opposite of what adding a mute should do.
	It("adds to what the profile already excluded", func() {
		config, _ := pushdown(map[string]any{"exclude-tags": []any{"dos"}},
			api.MuteRule{Name: "noisy", Tags: api.StringList{"db-vendor"}})

		Expect(config["exclude-tags"]).To(ConsistOf("dos", "db-vendor"))
	})

	It("does not repeat a value the profile already excluded", func() {
		config, _ := pushdown(map[string]any{"exclude-id": []any{"open-redirect"}},
			api.MuteRule{Name: "accepted", Templates: api.StringList{"open-redirect"}})

		Expect(config["exclude-id"]).To(ConsistOf("open-redirect"))
	})

	It("leaves a rule it cannot express alone", func() {
		config, plan := pushdown(map[string]any{},
			api.MuteRule{Name: "narrow", Templates: api.StringList{"a"}, Severity: api.StringList{"info"}},
			api.MuteRule{Name: "expr", Expr: `finding.host == "x"`})

		Expect(plan.PushedDown).To(BeEmpty())
		Expect(config).To(BeEmpty())
	})

	// Command is documentation of what ran, and its own comment insists it stay
	// faithful to Options. Both read the configuration the pushdown edited, so
	// this asserts that invariant directly rather than trusting the convention.
	Describe("the three readers of the configuration", func() {
		It("all reflect a pushed-down exclusion", func() {
			config, _ := pushdown(map[string]any{},
				api.MuteRule{Name: "accepted", Templates: api.StringList{"open-redirect"}},
				api.MuteRule{Name: "noisy", Tags: api.StringList{"db-vendor"}})

			options, err := Options(config)
			Expect(err).ToNot(HaveOccurred())
			Expect(options.ExcludeIds).To(ContainElement("open-redirect"))
			Expect(options.ExcludeTags).To(ContainElement("db-vendor"))

			command := strings.Join(Engine{}.Command(engines.Run{Config: config}), " ")
			Expect(command).To(ContainSubstring("open-redirect"))
			Expect(command).To(ContainSubstring("db-vendor"))

			preview, err := Engine{}.Preview(config)
			Expect(err).ToNot(HaveOccurred())
			Expect(preview.Total).To(BeNumerically(">", 0))
		})
	})
})
