package all_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	depsmanager "github.com/flanksource/deps/pkg/manager"
	"github.com/flanksource/deps/pkg/manager/github"
	"github.com/flanksource/deps/pkg/platform"
	depstemplate "github.com/flanksource/deps/pkg/template"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The install definitions are only exercised on a machine that does not already
// have the tool on PATH, which in practice means they can be wrong for months
// before anyone finds out — as they were: every asset pattern named the tag
// (v1.7.0) where the assets are named for the version (1.7.0), and only katana
// was missing locally to reveal it.
//
// This resolves each package the way deps does and asks GitHub whether the asset
// exists, without downloading it. Skipped under -short, so the offline suite
// stays offline.
var _ = Describe("engine install definitions", Label("network"), func() {
	BeforeEach(func() {
		if testing.Short() {
			Skip("network-gated")
		}
	})

	client := &http.Client{
		Timeout: 30 * time.Second,
		// A release asset redirects to a signed CDN URL. Following it would
		// start the download; the redirect itself is proof enough that the
		// asset exists.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	exists := func(url string) (int, error) {
		request, err := http.NewRequest(http.MethodHead, url, nil)
		if err != nil {
			return 0, err
		}
		response, err := client.Do(request)
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		return response.StatusCode, nil
	}

	// platforms are the ones a release must cover. Windows is declared but not
	// asserted: nothing here runs on it.
	platforms := []platform.Platform{
		{OS: "darwin", Arch: "amd64"},
		{OS: "darwin", Arch: "arm64"},
		{OS: "linux", Arch: "amd64"},
		{OS: "linux", Arch: "arm64"},
	}

	for _, engine := range allSpecs() {
		spec := engine // one entry per engine, so a failure names the engine

		// An in-process engine is linked into this binary: there is no release
		// to publish assets, and its version is whatever recon compiled against.
		if spec.InProcess {
			continue
		}

		It(fmt.Sprintf("%s publishes every asset its package names", spec.Name), func(ctx SpecContext) {
			owner, repo, found := splitRepo(spec.Install.Repo)
			Expect(found).To(BeTrue(), "repo must be owner/name")

			tag, err := github.ResolveLatestTagViaRedirect(ctx, owner, repo)
			Expect(err).ToNot(HaveOccurred())

			data := map[string]string{
				"tag":     tag,
				"version": depstemplate.NormalizeVersion(tag),
			}

			assets := []string{}
			for _, plat := range platforms {
				pattern, err := depsmanager.ResolveAssetPattern(spec.Install.AssetPatterns, plat)
				Expect(err).ToNot(HaveOccurred(), "no asset pattern for %s", plat)

				data["os"], data["arch"] = plat.OS, plat.Arch
				asset, err := depstemplate.TemplateString(pattern, data)
				Expect(err).ToNot(HaveOccurred())
				assets = append(assets, asset)
			}

			checksums, err := depstemplate.TemplateString(spec.Install.ChecksumFile, data)
			Expect(err).ToNot(HaveOccurred())
			assets = append(assets, checksums)

			for _, asset := range assets {
				url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s",
					spec.Install.Repo, tag, asset)
				status, err := exists(url)
				Expect(err).ToNot(HaveOccurred())
				Expect(status).To(BeElementOf(http.StatusOK, http.StatusFound),
					"%s does not publish %s at %s", spec.Name, asset, tag)
			}
		})
	}
})

func splitRepo(repo string) (owner, name string, ok bool) {
	for i := 0; i < len(repo); i++ {
		if repo[i] == '/' {
			return repo[:i], repo[i+1:], i > 0 && i < len(repo)-1
		}
	}
	return "", "", false
}
