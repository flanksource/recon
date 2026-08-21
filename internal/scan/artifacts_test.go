package scan_test

import (
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/scan"
)

// The artifact directory is the durable half of a run: findings live in
// Postgres, but the engine's own output file is what every other tool in this
// ecosystem reads, and it used to be deleted the moment the scan ended.
var _ = Describe("scan artifacts", func() {
	var (
		root    string
		started time.Time
	)

	BeforeEach(func() {
		root = GinkgoT().TempDir()
		started = time.Date(2026, 8, 12, 9, 30, 0, 0, time.UTC)
	})

	It("partitions by engine and date so a directory listing stays readable", func() {
		artifacts, err := scan.NewArtifacts(root, "nuclei", started, "nuclei-safe-20260812-093000")
		Expect(err).ToNot(HaveOccurred())

		Expect(artifacts.Dir).To(Equal(filepath.Join(
			root, "results", "nuclei", "2026-08-12", "nuclei-safe-20260812-093000")))
		Expect(artifacts.Dir).To(BeADirectory())
	})

	It("lists nested files with portable names and ignores directories", func() {
		artifacts, err := scan.NewArtifacts(root, "nuclei", started, "run")
		Expect(err).ToNot(HaveOccurred())

		Expect(artifacts.WriteFile(scan.FindingsFile, []byte(`{"a":1}`+"\n"))).To(Succeed())
		Expect(artifacts.WriteJSON(scan.ConfigFile, map[string]any{"rate-limit": 50})).To(Succeed())
		Expect(os.Mkdir(artifacts.Path("nested"), 0o755)).To(Succeed())
		Expect(os.WriteFile(artifacts.Path("nested/report.json"), []byte("{}\n"), 0o644)).To(Succeed())

		files, err := scan.ListArtifacts(artifacts.Dir)
		Expect(err).ToNot(HaveOccurred())

		names := make([]string, 0, len(files))
		for _, file := range files {
			names = append(names, file.Name)
			Expect(file.Size).To(BeNumerically(">", 0), file.Name)
			Expect(file.Modified).ToNot(BeEmpty(), file.Name)
		}
		Expect(names).To(Equal([]string{scan.ConfigFile, scan.FindingsFile, "nested/report.json"}))
	})

	// The directory comes from the database and the name from a URL. Matching
	// the name against the listing rather than joining it onto the directory is
	// what keeps the download route from serving anything the process can read.
	DescribeTable("refuses a name that is not a file the run wrote",
		func(name string) {
			artifacts, err := scan.NewArtifacts(root, "nuclei", started, "run")
			Expect(err).ToNot(HaveOccurred())
			Expect(artifacts.WriteFile(scan.FindingsFile, []byte("{}\n"))).To(Succeed())

			_, err = scan.ResolveArtifact(artifacts.Dir, name)
			Expect(err).To(MatchError(ContainSubstring("no such scan artifact")))
		},
		Entry("parent traversal", ".."),
		Entry("a path out of the directory", "../../../etc/passwd"),
		Entry("a path that cleans into another file", "nested/../findings.jsonl"),
		Entry("a windows-style path", `..\config.json`),
		Entry("nothing at all", ""),
		Entry("a file the run did not write", "secrets.env"),
	)

	It("resolves a file the run did write", func() {
		artifacts, err := scan.NewArtifacts(root, "nuclei", started, "run")
		Expect(err).ToNot(HaveOccurred())
		Expect(artifacts.WriteFile(scan.LogFile, []byte("[INF] done\n"))).To(Succeed())

		path, err := scan.ResolveArtifact(artifacts.Dir, scan.LogFile)
		Expect(err).ToNot(HaveOccurred())
		Expect(os.ReadFile(path)).To(BeEquivalentTo("[INF] done\n"))
	})

	It("resolves a nested file the run did write", func() {
		artifacts, err := scan.NewArtifacts(root, "prowler", started, "run")
		Expect(err).ToNot(HaveOccurred())
		Expect(os.MkdirAll(artifacts.Path("contexts/0001/output"), 0o755)).To(Succeed())
		name := "contexts/0001/output/report.ocsf.json"
		Expect(os.WriteFile(artifacts.Path(name), []byte("[]\n"), 0o644)).To(Succeed())

		resolved, err := scan.ResolveArtifact(artifacts.Dir, name)
		Expect(err).ToNot(HaveOccurred())
		Expect(os.ReadFile(resolved)).To(BeEquivalentTo("[]\n"))
	})

	It("does not list or resolve symbolic links", func() {
		artifacts, err := scan.NewArtifacts(root, "prowler", started, "run")
		Expect(err).ToNot(HaveOccurred())
		outside := filepath.Join(root, "credential.json")
		Expect(os.WriteFile(outside, []byte("secret\n"), 0o600)).To(Succeed())
		Expect(os.Symlink(outside, artifacts.Path("credential.json"))).To(Succeed())

		files, err := scan.ListArtifacts(artifacts.Dir)
		Expect(err).ToNot(HaveOccurred())
		Expect(files).To(BeEmpty())
		_, err = scan.ResolveArtifact(artifacts.Dir, "credential.json")
		Expect(err).To(MatchError(ContainSubstring("no such scan artifact")))
	})

	It("reports a directory that is no longer there rather than an empty listing", func() {
		artifacts, err := scan.NewArtifacts(root, "nuclei", started, "run")
		Expect(err).ToNot(HaveOccurred())
		artifacts.Remove()

		_, err = scan.ListArtifacts(artifacts.Dir)
		Expect(err).To(MatchError(ContainSubstring("read scan artifacts")))
	})
})
