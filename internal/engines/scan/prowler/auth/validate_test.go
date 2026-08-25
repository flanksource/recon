package auth

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("configured credential validation", func() {
	It("matches one complete environment method", func() {
		method, err := Match("cloudflare", map[string]any{}, credentials("CLOUDFLARE_API_TOKEN"))
		Expect(err).NotTo(HaveOccurred())
		Expect(method.ID).To(Equal("api-token"))
	})

	It("rejects mixed, incomplete, and arbitrary environment methods", func() {
		_, err := Match("cloudflare", map[string]any{}, credentials("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY"))
		Expect(err).To(MatchError(ContainSubstring("does not match exactly one authentication method")))

		_, err = Match("m365", map[string]any{"tenant-id": "tenant-x"}, credentials("AZURE_CLIENT_ID"))
		Expect(err).To(MatchError(ContainSubstring("does not match exactly one authentication method")))

		_, err = Match("github", map[string]any{}, credentials("UNAPPROVED_TOKEN"))
		Expect(err).To(MatchError(ContainSubstring("does not match exactly one authentication method")))
	})

	It("requires method settings and rejects conflicting auth selectors", func() {
		_, err := Match("cloudflare", map[string]any{}, credentials("CLOUDFLARE_API_KEY"))
		Expect(err).To(MatchError(ContainSubstring(`requires setting "api-email"`)))

		_, err = Match("azure", map[string]any{"az-cli-auth": true}, map[string]any{
			"connections": map[string]any{"azure": map[string]any{"connection": "connection://prod-azure"}},
		})
		Expect(err).To(MatchError(ContainSubstring(`conflicts with authentication argument "az-cli-auth"`)))
	})

	It("matches a typed native connection shape", func() {
		method, err := Match("aws", map[string]any{}, map[string]any{
			"connections": map[string]any{"aws": map[string]any{"connection": "connection://prod-aws"}},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(method.Connection).To(Equal(&Connection{Key: "aws", Type: "aws"}))
	})

	It("projects automatic arguments and environment-only settings", func() {
		method, err := Match("github", map[string]any{"github-app-id": "1234", "organizations": []any{"acme"}}, credentials("GITHUB_APP_KEY"))
		Expect(err).NotTo(HaveOccurred())

		arguments, err := ProjectArguments("github", map[string]any{
			"github-app-id": "1234", "organizations": []any{"acme"},
		}, &method)
		Expect(err).NotTo(HaveOccurred())
		Expect(arguments).To(Equal(map[string]any{"organizations": []any{"acme"}}))

		settings, err := EnvironmentSettings("github", map[string]any{"github-app-id": "1234"})
		Expect(err).NotTo(HaveOccurred())
		Expect(settings).To(Equal(map[string]string{"GITHUB_APP_ID": "1234"}))
	})
})

func credentials(names ...string) map[string]any {
	values := make([]any, 0, len(names))
	for _, name := range names {
		values = append(values, map[string]any{"name": name, "value": "secret"})
	}
	return map[string]any{"envVars": values}
}
