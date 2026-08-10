package entities

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestEntities(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "entities")
}
