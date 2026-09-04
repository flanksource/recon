package api

import "encoding/json"

// FindingGroup is the current posture for one engine check across resources.
type FindingGroup struct {
	Engine   string         `json:"engine"`
	CheckID  string         `json:"checkId"`
	Name     string         `json:"name"`
	Severity Severity       `json:"severity"`
	Affected int            `json:"affected"`
	Statuses map[string]int `json:"statuses"`
	LastSeen string         `json:"lastSeen"`
}

func (g FindingGroup) GetID() string   { return g.Engine + "/" + g.CheckID }
func (g FindingGroup) GetName() string { return g.Name }

type FindingGroupPage struct {
	Data []FindingGroup `json:"data"`
	Page PageInfo       `json:"page"`
}

type FindingStatePage struct {
	Data []FindingState `json:"data"`
	Page PageInfo       `json:"page"`
}

// InsightSync reports the preview or push of current resource/check states.
type InsightSync struct {
	Context string `json:"context,omitempty"`
	Server  string `json:"server,omitempty"`
	Agent   string `json:"agent"`
	DryRun  bool   `json:"dryRun,omitempty"`

	MatchedResources int `json:"matchedResources"`
	MatchedStates    int `json:"matchedStates"`
	Eligible         int `json:"eligible"`
	Skipped          int `json:"skipped"`
	Open             int `json:"open"`
	Resolved         int `json:"resolved"`
	Silenced         int `json:"silenced"`
	Direct           int `json:"direct"`
	RolledUp         int `json:"rolledUp"`
	// Pinned counts states attached through a manual link.
	Pinned int `json:"pinned"`
	Pushed int `json:"pushed"`

	Configs    []InsightConfig     `json:"configs"`
	Unresolved []InsightUnresolved `json:"unresolved"`
	// Ambiguous are the identities more than one config item carried. They are
	// reported whether or not a lower rung then resolved the state, because the
	// finer identity is the one a person would want the insight attached to.
	Ambiguous []InsightAmbiguity `json:"ambiguous"`
}

type InsightConfig struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Insights int    `json:"insights"`
	RolledUp bool   `json:"rolledUp,omitempty"`
	// Pinned marks a config item chosen by hand rather than found by the ladder.
	Pinned bool `json:"pinned,omitempty"`
}

type InsightUnresolved struct {
	Finding  string   `json:"finding"`
	Host     string   `json:"host,omitempty"`
	Severity Severity `json:"severity,omitempty"`
	Tried    []string `json:"tried"`
	Reason   string   `json:"reason"`
}

// InsightAmbiguity is one identity that named more than one config item.
//
// Ambiguity is not a miss: the identity is right and the catalog holds several
// things carrying it, so the only honest resolutions are to pick one or to
// attach to what contains them. Reporting it structurally rather than as prose
// is what lets either be offered.
type InsightAmbiguity struct {
	Identity string `json:"identity"`
	Type     string `json:"type,omitempty"`
	// Scope marks an identity that names the account, project or cluster rather
	// than the thing the findings are about.
	Scope bool `json:"scope,omitempty"`
	// States is every current state that reached this identity; Resources is a
	// bounded sample of the resources they belong to, for a reader.
	States    int      `json:"states"`
	Resources []string `json:"resources,omitempty"`
	// Chosen is the option this run resolved the identity to, empty when nobody
	// has chosen yet.
	Chosen  string          `json:"chosen,omitempty"`
	Options []InsightChoice `json:"options"`
}

// InsightChoice is one config item an ambiguous identity could be attached to.
type InsightChoice struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	// Root marks a config item nothing else contains — the top of its tree.
	Root bool `json:"root,omitempty"`
	// Ancestor marks an option offered because it contains one of the matched
	// items rather than because it carried the identity itself.
	Ancestor bool `json:"ancestor,omitempty"`
	Deleted  bool `json:"deleted,omitempty"`
}

type ConfigMatchMethod string

const (
	ConfigMatchAutomatic ConfigMatchMethod = "automatic"
	ConfigMatchManual    ConfigMatchMethod = "manual"
)

// ConfigPin is the durable catalog link used for a resource's insights. Method
// records how it was selected; RolledUp says whether the item is the resource
// itself or merely contains it.
type ConfigPin struct {
	ConfigID string            `json:"configId"`
	Method   ConfigMatchMethod `json:"method"`
	RolledUp bool              `json:"rolledUp,omitempty"`
	Server   string            `json:"server,omitempty"`
}

func (u InsightSync) MarshalJSON() ([]byte, error) {
	type alias InsightSync
	out := alias(u)
	if out.Configs == nil {
		out.Configs = []InsightConfig{}
	}
	if out.Unresolved == nil {
		out.Unresolved = []InsightUnresolved{}
	}
	if out.Ambiguous == nil {
		out.Ambiguous = []InsightAmbiguity{}
	}
	return json.Marshal(out)
}

// InsightState is all data required to resolve and publish one current state.
type InsightState struct {
	State    FindingState
	Resource Resource
	Parent   *Resource
	Finding  Finding
	Scan     Scan
}
