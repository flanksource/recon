package nuclei

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the Nuclei catalogue", func() {
	It("describes the item and selection vocabulary for catalogue clients", func() {
		corpus := (Engine{}).Corpus()
		Expect(corpus.ItemLabel).To(Equal("template"))
		Expect(corpus.ProfileLabel).To(Equal("profile"))
	})
})
