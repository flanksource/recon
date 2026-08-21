package prowler

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestProwler(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "prowler")
}
