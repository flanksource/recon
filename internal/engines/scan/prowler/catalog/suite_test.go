package catalog_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCatalog(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Prowler Catalog Suite")
}
