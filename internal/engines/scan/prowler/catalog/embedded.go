package catalog

import (
	_ "embed"
	"sync"
)

//go:embed catalog.generated.json.xz
var embeddedArtifact []byte

var loadEmbedded = newEmbeddedLoader(embeddedArtifact)

func newEmbeddedLoader(data []byte) func() (*Catalog, error) {
	return sync.OnceValues(func() (*Catalog, error) {
		loaded, err := Unmarshal(data)
		if err != nil {
			return nil, err
		}
		if err := loaded.ValidatePinned(); err != nil {
			return nil, err
		}
		return loaded, nil
	})
}

func Embedded() (*Catalog, error) { return loadEmbedded() }
