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
	Pushed           int `json:"pushed"`

	Configs    []InsightConfig     `json:"configs"`
	Unresolved []InsightUnresolved `json:"unresolved"`
	Notes      []string            `json:"notes,omitempty"`
}

type InsightConfig struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Insights int    `json:"insights"`
	RolledUp bool   `json:"rolledUp,omitempty"`
}

type InsightUnresolved struct {
	Finding  string   `json:"finding"`
	Host     string   `json:"host,omitempty"`
	Severity Severity `json:"severity,omitempty"`
	Tried    []string `json:"tried"`
	Reason   string   `json:"reason"`
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
