package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/labels"
)

var (
	targetIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)
	providerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
)

// TargetSelector selects targets without accessing persistence. The same
// struct is the CLI's flags, the REST query string, the UI's filter bar and —
// once resolved to endpoints — what a scan runs against. A scan records the
// selector it ran with, so "what did this actually hit" has an answer.
//
// Every list-valued field means "any of", matching how the filter chips read.
type TargetSelector struct {
	Selector string   `json:"selector,omitempty" flag:"selector" help:"Kubernetes label selector over target tags"`
	IDs      []string `json:"ids,omitempty" flag:"id" help:"Only these stable target IDs"`
	Kind     []string `json:"kind,omitempty" flag:"kind" help:"Only these target kinds (host, provider-context)"`
	Provider []string `json:"provider,omitempty" flag:"provider" help:"Only provider contexts for these providers"`
	Class    []string `json:"class,omitempty" flag:"class" help:"Only these classes (public, prod, non-prod, internal, unclassified, deactivated)"`
	Tags     []string `json:"tags,omitempty" flag:"tags" help:"Only targets carrying any of these tags; prefix ! to exclude"`
	Profiles []string `json:"profiles,omitempty" flag:"profiles" help:"Only targets assigned any of these scan profiles"`
	Hosts    []string `json:"hosts,omitempty" flag:"hosts" help:"Only these exact hosts"`
	Ports    []int    `json:"ports,omitempty" flag:"ports" help:"Only targets with any of these ports, curated or discovered"`
	Status   []int    `json:"status,omitempty" flag:"status" help:"Only targets whose last HTTP status was one of these"`

	LastSeen string   `json:"lastSeen,omitempty" flag:"last-seen" help:"Only targets seen since this time (RFC3339 or a duration such as 168h)"`
	Live     bool     `json:"live,omitempty" flag:"live" help:"Only targets that answered over HTTP the last time they were probed"`
	Failure  []string `json:"failure,omitempty" flag:"failure" help:"Only targets whose last probe failed this way (dns, refused, unreachable, timeout, tls, http, other)"`
}

// Empty reports whether the selector constrains anything. A scan against an
// empty selector targets the whole inventory, which is worth saying out loud
// before it runs.
func (o TargetSelector) Empty() bool {
	return o.Selector == "" && len(o.IDs) == 0 && len(o.Kind) == 0 && len(o.Provider) == 0 && len(o.Class) == 0 && len(o.Tags) == 0 &&
		len(o.Profiles) == 0 && len(o.Hosts) == 0 && len(o.Ports) == 0 && len(o.Status) == 0 &&
		o.LastSeen == "" && !o.Live && len(o.Failure) == 0
}

// Describe renders the selector as the phrase used in confirmation prompts and
// stored on the scan row.
func (o TargetSelector) Describe() string {
	if o.Empty() {
		return "every target"
	}
	var parts []string
	add := func(label string, values []string) {
		if len(values) > 0 {
			parts = append(parts, label+" "+strings.Join(values, ","))
		}
	}
	add("ids", o.IDs)
	add("kind", o.Kind)
	add("provider", o.Provider)
	add("class", o.Class)
	if o.Selector != "" {
		parts = append(parts, "selector "+o.Selector)
	}
	add("tags", o.Tags)
	add("profiles", o.Profiles)
	add("hosts", o.Hosts)
	if len(o.Ports) > 0 {
		parts = append(parts, fmt.Sprintf("ports %v", o.Ports))
	}
	if len(o.Status) > 0 {
		parts = append(parts, fmt.Sprintf("status %v", o.Status))
	}
	if o.LastSeen != "" {
		parts = append(parts, "seen since "+o.LastSeen)
	}
	if o.Live {
		parts = append(parts, "live")
	}
	add("failure", o.Failure)
	return strings.Join(parts, ", ")
}

// Validate rejects a selector that cannot mean anything, rather than silently
// returning nothing and letting the caller conclude the inventory is empty.
func (o TargetSelector) Validate() error {
	if _, err := labels.Parse(o.Selector); err != nil {
		return fmt.Errorf("invalid selector %q: %w", o.Selector, err)
	}
	for _, id := range o.IDs {
		if _, err := netip.ParseAddr(id); !targetIDPattern.MatchString(id) && err != nil {
			return fmt.Errorf("invalid target id %q", id)
		}
	}
	for _, provider := range o.Provider {
		if !providerPattern.MatchString(provider) {
			return fmt.Errorf("invalid provider %q", provider)
		}
	}
	kinds := map[string]bool{}
	for _, kind := range TargetKinds() {
		kinds[string(kind)] = true
	}
	for _, kind := range o.Kind {
		if !kinds[kind] {
			return fmt.Errorf("unknown kind %q: expected one of %s",
				kind, strings.Join(kindNames(), ", "))
		}
	}
	valid := map[string]bool{}
	for _, class := range Classes() {
		valid[string(class)] = true
	}
	for _, class := range o.Class {
		if !valid[class] {
			return fmt.Errorf("unknown class %q: expected one of %s",
				class, strings.Join(classNames(), ", "))
		}
	}
	for _, port := range o.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("port %d out of range", port)
		}
	}
	failures := map[string]bool{}
	for _, failure := range Failures() {
		failures[string(failure)] = true
	}
	for _, failure := range o.Failure {
		if !failures[failure] {
			return fmt.Errorf("unknown failure %q: expected one of %s",
				failure, strings.Join(failureNames(), ", "))
		}
	}
	if o.LastSeen != "" {
		if _, err := ParseSince(o.LastSeen); err != nil {
			return err
		}
	}
	return nil
}

func kindNames() []string {
	names := make([]string, 0, len(TargetKinds()))
	for _, kind := range TargetKinds() {
		names = append(names, string(kind))
	}
	return names
}

func classNames() []string {
	names := make([]string, 0, len(Classes()))
	for _, class := range Classes() {
		names = append(names, string(class))
	}
	return names
}

func failureNames() []string {
	names := make([]string, 0, len(Failures()))
	for _, failure := range Failures() {
		names = append(names, string(failure))
	}
	return names
}

// ParseSince accepts either an absolute RFC3339 timestamp or a duration back
// from now, because "--last-seen 168h" is what anyone actually wants to type.
func ParseSince(value string) (time.Time, error) {
	if duration, err := time.ParseDuration(value); err == nil {
		if duration > 0 {
			duration = -duration
		}
		return time.Now().Add(duration), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"last-seen %q is neither a duration (168h) nor an RFC3339 time", value)
	}
	return parsed, nil
}

// MatchesTags applies Selector to one target's tag set. Bare tags become label
// keys with an empty value; key=value tags become ordinary Kubernetes labels.
func (o TargetSelector) MatchesTags(tags []string) (bool, error) {
	selector, err := labels.Parse(o.Selector)
	if err != nil {
		return false, fmt.Errorf("invalid selector %q: %w", o.Selector, err)
	}
	if o.Selector == "" {
		return true, nil
	}
	set := labels.Set{}
	for _, tag := range tags {
		key, value, found := strings.Cut(tag, "=")
		if !found {
			key, value = tag, ""
		}
		if key == "" {
			return false, fmt.Errorf("invalid empty tag key in %q", tag)
		}
		if existing, exists := set[key]; exists && existing != value {
			return false, fmt.Errorf("conflicting values for tag %q", key)
		}
		set[key] = value
	}
	return selector.Matches(set), nil
}

// Map renders the selector for storage on a scan row. Going through JSON rather
// than reflection keeps it identical to what the API accepts, so a stored
// selector can be replayed.
func (o TargetSelector) Map() (map[string]any, error) {
	encoded, err := json.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("encode target selector: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, fmt.Errorf("project target selector: %w", err)
	}
	return out, nil
}

// ParseTargetSelector decodes and validates JSON-shaped target filters without database access.
func ParseTargetSelector(stored map[string]any) (TargetSelector, error) {
	encoded, err := json.Marshal(stored)
	if err != nil {
		return TargetSelector{}, fmt.Errorf("encode stored target selector: %w", err)
	}
	var opts TargetSelector
	// Strict, because the failure it prevents is silent and inverted: an
	// unrecognised key is dropped, the selector decodes empty, and an empty
	// selector is every target. A mute rule scoped to one host would quietly
	// cover the whole inventory. The near-miss is the realistic case — the flag
	// is `--id` and the stored field is `ids`.
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&opts); err != nil {
		return TargetSelector{}, fmt.Errorf("decode stored target selector: %w", err)
	}
	if err := opts.Validate(); err != nil {
		return TargetSelector{}, fmt.Errorf("validate stored target selector: %w", err)
	}
	return opts, nil
}
