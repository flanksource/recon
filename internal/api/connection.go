package api

// ConnectionReference is the non-secret connection shape exposed to provider
// credential pickers.
type ConnectionReference struct {
	ID        string `json:"id"`
	Reference string `json:"reference"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Type      string `json:"type"`
}

func (c ConnectionReference) GetID() string   { return c.ID }
func (c ConnectionReference) GetName() string { return c.Reference }
