package engines_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines"
)

var _ = Describe("layering run-only overrides", func() {
	It("adds and replaces keys the patch names", func() {
		merged := engines.LayerOverrides(
			map[string]any{"provider": "github", "compliance": []any{"cis_1.0_github"}},
			map[string]any{"verbose": true, "compliance": []any{"cis_2.0_github"}},
		)

		Expect(merged).To(Equal(map[string]any{
			"provider": "github", "compliance": []any{"cis_2.0_github"}, "verbose": true,
		}))
	})

	// Choosing one member of a mutually exclusive group means unsetting the
	// others. Without a way to say so the profile's member survives the merge
	// and the run fails on a combination the request never asked for.
	It("removes a key the patch nulls rather than storing the null", func() {
		merged := engines.LayerOverrides(
			map[string]any{"provider": "github", "compliance": []any{"cis_1.0_github"}},
			map[string]any{"services": []any{"repository"}, "compliance": nil},
		)

		Expect(merged).To(Equal(map[string]any{
			"provider": "github", "services": []any{"repository"},
		}))
		Expect(merged).ToNot(HaveKey("compliance"))
	})

	It("leaves the profile untouched when the patch is empty", func() {
		config := map[string]any{"provider": "github"}

		Expect(engines.LayerOverrides(config, nil)).To(Equal(config))
		Expect(engines.LayerOverrides(config, map[string]any{})).To(Equal(config))
	})

	It("ignores a null for a key the profile never set", func() {
		merged := engines.LayerOverrides(
			map[string]any{"provider": "github"},
			map[string]any{"checks": nil},
		)

		Expect(merged).To(Equal(map[string]any{"provider": "github"}))
	})
})
