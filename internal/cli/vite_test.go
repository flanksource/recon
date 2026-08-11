package cli

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("locating the web app for --dev", func() {
	// --dev serves the working tree, so the app has to be found from wherever
	// the command was run rather than from a path baked into the binary.
	chdir := func(dir string) {
		previous, err := os.Getwd()
		Expect(err).ToNot(HaveOccurred())
		Expect(os.Chdir(dir)).To(Succeed())
		DeferCleanup(func() { Expect(os.Chdir(previous)).To(Succeed()) })
	}

	withApp := func() string {
		root := GinkgoT().TempDir()
		Expect(os.MkdirAll(filepath.Join(root, "app"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(root, "app", "package.json"), []byte("{}"), 0o644)).To(Succeed())
		// Symlinks in the temp path (/var -> /private/var on macOS) would make the
		// returned path differ textually from the one built here.
		resolved, err := filepath.EvalSymlinks(root)
		Expect(err).ToNot(HaveOccurred())
		return resolved
	}

	It("finds the app beside the working directory", func() {
		root := withApp()
		chdir(root)

		Expect(appDir()).To(Equal(filepath.Join(root, "app")))
	})

	It("walks up from a subdirectory, so it works from anywhere in the checkout", func() {
		root := withApp()
		nested := filepath.Join(root, "internal", "cli")
		Expect(os.MkdirAll(nested, 0o755)).To(Succeed())
		chdir(nested)

		Expect(appDir()).To(Equal(filepath.Join(root, "app")))
	})

	It("says what is missing rather than starting vite against nothing", func() {
		chdir(GinkgoT().TempDir())

		_, err := appDir()
		Expect(err).To(MatchError(ContainSubstring("no app/package.json was found")))
	})
})

var _ = Describe("choosing a port for the dev server", func() {
	It("returns a port nothing is listening on", func() {
		port, err := freePort()
		Expect(err).ToNot(HaveOccurred())
		Expect(port).To(BeNumerically(">", 0))

		// Nothing holds it: the whole point is that Vite can bind it next.
		again, err := freePort()
		Expect(err).ToNot(HaveOccurred())
		Expect(again).To(BeNumerically(">", 0))
	})
})
