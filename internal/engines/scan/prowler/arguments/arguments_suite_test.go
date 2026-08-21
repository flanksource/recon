package arguments_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestArguments(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Prowler Arguments Suite")
}
