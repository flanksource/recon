package api

// OpenFindingsReport describes current resource/check states, not a synthetic
// scan. Each state carries only its own resource and the evidence it references.
type OpenFindingsReport struct {
	States      []FindingState `json:"states"`
	GeneratedAt string         `json:"generatedAt"`
}
