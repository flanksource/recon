package catalog

import _ "embed"

//go:embed catalog.generated.gz.hex
var embeddedArtifact []byte

func Embedded() (*Catalog, error) {
	loaded, err := Unmarshal(embeddedArtifact)
	if err != nil {
		return nil, err
	}
	if err := loaded.ValidatePinned(); err != nil {
		return nil, err
	}
	return loaded, nil
}
