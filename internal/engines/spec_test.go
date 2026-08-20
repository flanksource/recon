package engines_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/deps/pkg/types"

	"github.com/flanksource/recon/internal/engines"
)

// spawned is a minimally valid spec for an engine with a binary — the shape
// every assertion below varies one field of.
func spawned() engines.Spec {
	return engines.Spec{
		Name:   "example",
		Binary: "example",
		Install: types.Package{
			Name: "example", Manager: "github_release", VersionCommand: "--version",
		},
		Defaults: engines.DefaultProfile{Name: "default"},
	}
}

var _ = Describe("an engine spec", func() {
	Describe("Subject", func() {
		It("defaults to the endpoint list", func() {
			// The zero value has to be what a network scanner wants, or every
			// existing engine would need a field it has no opinion about.
			Expect(spawned().Subject).To(Equal(engines.SubjectEndpoints))
			Expect(spawned().Validate()).To(Succeed())
		})

		It("accepts an engine whose subject is cloud accounts", func() {
			spec := spawned()
			spec.Subject = engines.SubjectAccounts

			Expect(spec.Validate()).To(Succeed())
		})

		It("rejects a subject the runtime cannot resolve", func() {
			// The runtime switches on this to decide what the selector resolves
			// to. An unrecognised value would fall through to the endpoint
			// branch and scan addresses for an engine that wanted accounts.
			spec := spawned()
			spec.Subject = "clusters"

			Expect(spec.Validate()).To(MatchError(ContainSubstring("unknown subject")))
		})
	})

	Describe("the binary contract", func() {
		It("holds for a spawned engine", func() {
			spec := spawned()
			spec.Install.VersionCommand = ""

			// Without a version command `doctor` cannot tell an outdated binary
			// from a current one, and a run cannot record what it used.
			Expect(spec.Validate()).To(MatchError(ContainSubstring("version_command is required")))
		})

		It("does not apply to a linked-in engine", func() {
			// There is nothing to provision, so the fields describing how to
			// provision it describe nothing.
			Expect(engines.Spec{
				Name:      "linked",
				InProcess: true,
				Defaults:  engines.DefaultProfile{Name: "default"},
			}.Validate()).To(Succeed())
		})
	})
})
