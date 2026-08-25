package ocsf_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/ocsf"
)

func TestOCSF(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ocsf")
}

// The generated constants reach a database CHECK constraint and every engine
// adapter, so a wrong integer here is expensive and silent. These pin the
// published scales rather than trusting the generator to have read them right.
var _ = Describe("the generated OCSF scales", func() {
	It("pins the severity scale, captions included", func() {
		scale := map[int]string{}
		for _, value := range []ocsf.SeverityID{
			ocsf.SeverityIDUnknown, ocsf.SeverityIDInformational, ocsf.SeverityIDLow,
			ocsf.SeverityIDMedium, ocsf.SeverityIDHigh, ocsf.SeverityIDCritical,
			ocsf.SeverityIDFatal, ocsf.SeverityIDOther,
		} {
			scale[int(value)] = value.String()
		}

		Expect(scale).To(Equal(map[int]string{
			0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium",
			4: "High", 5: "Critical", 6: "Fatal", 99: "Other",
		}))
	})

	// OCSF defines status_id twice. The attribute dictionary defines it as the
	// outcome of an activity — 1 is Success — and the finding classes override it
	// as a triage state, where 1 is New. Both are integers, both compile, and
	// reading the dictionary's copy would label every finding wrongly while
	// looking entirely reasonable.
	It("pins the finding status scale, not the activity outcome", func() {
		scale := map[int]string{}
		for _, value := range []ocsf.StatusID{
			ocsf.StatusIDUnknown, ocsf.StatusIDNew, ocsf.StatusIDInProgress,
			ocsf.StatusIDSuppressed, ocsf.StatusIDResolved, ocsf.StatusIDArchived,
			ocsf.StatusIDOther,
		} {
			scale[int(value)] = value.String()
		}

		Expect(scale).To(Equal(map[int]string{
			0: "Unknown", 1: "New", 2: "In Progress", 3: "Suppressed",
			4: "Resolved", 5: "Archived", 99: "Other",
		}))
		Expect(ocsf.StatusID(1).String()).ToNot(Equal("Success"))
	})

	It("names the class the way OCSF composes it", func() {
		Expect([]int{ocsf.ClassUID, ocsf.CategoryUID}).To(Equal([]int{2004, 2}))
		Expect(ocsf.ClassUID).To(Equal(ocsf.CategoryUID*1000 + 4))
		Expect(ocsf.TypeUID(ocsf.ActivityIDCreate)).To(BeEquivalentTo(200401))
	})

	It("was generated from the pinned release", func() {
		Expect(ocsf.Version).To(Equal("1.5.0"))
	})
})

// minimal is a record carrying exactly what OCSF requires of a detection
// finding that declares no profile — the shape a nuclei or filesystem scan
// produces, which has no cloud account to name.
func minimal() ocsf.DetectionFinding {
	return ocsf.DetectionFinding{
		ClassUID:    ocsf.ClassUID,
		CategoryUID: ocsf.CategoryUID,
		TypeUID:     ocsf.TypeUID(ocsf.ActivityIDCreate),
		ActivityID:  ocsf.ActivityIDCreate,
		SeverityID:  ocsf.SeverityIDHigh,
		Time:        1_764_547_200_000,
		Metadata:    &ocsf.Metadata{Version: ocsf.Version, Product: &ocsf.Product{Name: "recon"}},
		FindingInfo: &ocsf.FindingInfo{Title: "Missing security headers", UID: "http-missing-security-headers"},
	}
}

var _ = Describe("validating a record against OCSF", func() {
	It("accepts a record that declares no profile and names no cloud", func() {
		Expect(ocsf.Validate(minimal())).To(Succeed())
	})

	It("reports each missing requirement rather than only the first", func() {
		err := ocsf.Validate(ocsf.DetectionFinding{})

		Expect(err).To(HaveOccurred())
		for _, attribute := range []string{
			"category_uid", "class_uid", "finding_info", "metadata", "time", "type_uid",
		} {
			Expect(err.Error()).To(ContainSubstring(attribute))
		}
	})

	// An enum's zero is a value, not the absence of one. severity_id 0 is
	// Unknown, which is what an engine reporting a severity recon does not
	// recognise honestly maps to, and reading it as "unspecified" would reject
	// the one mapping telling the truth about not knowing.
	It("accepts an enum at its zero value, which is a defined member", func() {
		unknown := minimal()
		unknown.SeverityID = ocsf.SeverityIDUnknown
		unknown.ActivityID = ocsf.ActivityIDUnknown

		Expect(ocsf.Validate(unknown)).To(Succeed())
		Expect(ocsf.Validate(ocsf.DetectionFinding{}).Error()).
			ToNot(ContainSubstring("severity_id"))
	})

	// The reason Validate reads profiles off the record instead of taking them as
	// an argument. `cloud` is optional until a record says it audits a cloud
	// account, and then it is required — so the same struct is valid or invalid
	// depending only on what its own metadata claims.
	Context("when a record declares the cloud profile", func() {
		declaring := func() ocsf.DetectionFinding {
			finding := minimal()
			finding.Metadata.Profiles = []string{"cloud"}
			return finding
		}

		It("requires the cloud identity the profile promises", func() {
			err := ocsf.Validate(declaring())

			Expect(err).To(MatchError(ContainSubstring("cloud is required under the cloud profile")))
		})

		It("accepts the same record once the identity is there", func() {
			finding := declaring()
			finding.Cloud = &ocsf.Cloud{
				Provider: "gcp",
				Account:  &ocsf.Account{UID: "example-project", Name: "Example"},
			}

			Expect(ocsf.Validate(finding)).To(Succeed())
		})
	})

	// OCSF's at_least_one on the evidence object. An entry carrying only a name
	// describes nothing, and it is the shape a collapsed inspec control falls
	// into if its assertions are written to `name` instead of `data`.
	It("rejects an evidence entry that identifies no artifact", func() {
		finding := minimal()
		finding.Evidences = []ocsf.Evidences{{Name: "File /etc/shadow should exist"}}

		err := ocsf.Validate(finding)

		Expect(err).To(MatchError(ContainSubstring("evidences[0] needs at least one of")))
		Expect(err).To(MatchError(ContainSubstring("data")))
	})

	It("accepts the same evidence once it carries the assertion as data", func() {
		finding := minimal()
		finding.Evidences = []ocsf.Evidences{{
			Name: "File /etc/shadow should exist",
			Data: []byte(`{"code_desc":"File /etc/shadow should exist","status":"failed"}`),
		}}

		Expect(ocsf.Validate(finding)).To(Succeed())
	})

	// A resource with neither name nor uid identifies nothing, which is how a
	// finding ends up attached to a subject nobody can look up.
	It("rejects a resource that cannot be identified, naming which one", func() {
		finding := minimal()
		finding.Resources = []ocsf.ResourceDetails{
			{UID: "projects/example/roles/editor"},
			{Type: "IAMPolicy"},
		}

		err := ocsf.Validate(finding)

		Expect(err).To(MatchError(ContainSubstring("resources[1] needs at least one of name, uid")))
		Expect(err.Error()).ToNot(ContainSubstring("resources[0]"))
	})

	It("rejects a vulnerability that claims both a CVE and a CWE", func() {
		finding := minimal()
		finding.Vulnerabilities = []ocsf.Vulnerability{{
			Title: "CVE-2026-0001",
			CVE:   &ocsf.CVE{UID: "CVE-2026-0001"},
			CWE:   &ocsf.CWE{UID: "CWE-79"},
		}}

		Expect(ocsf.Validate(finding)).To(MatchError(
			ContainSubstring("which allows only one")))
	})
})
