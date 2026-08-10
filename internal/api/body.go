package api

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// The entity framework hands a request body through as a decoded map. These
// turn one into the typed value the store takes, and — importantly — reject the
// fields that are not the caller's to set, rather than accepting and ignoring
// them. Silently dropping `host` from an edit would look like a successful
// rename.

// TargetFrom decodes the body of a create: the host, which is the target's
// identity and so is settable only here, plus the curated fields.
//
// The host arrives as `host` from a JSON body and as `id` from the entity
// framework's flag mapping; both name the same thing and disagreeing about
// which is authoritative would make one of the two surfaces silently create
// nothing.
func TargetFrom(body map[string]any) (string, Curated, error) {
	host, _ := body["host"].(string)
	if host == "" {
		host, _ = body["id"].(string)
	}
	if host == "" {
		return "", Curated{}, fmt.Errorf("host is required: it is the target's identity")
	}

	rest := make(map[string]any, len(body))
	for key, value := range body {
		if key == "host" || key == "id" {
			continue
		}
		rest[key] = value
	}

	curated, err := CuratedFrom(rest)
	if err != nil {
		return "", Curated{}, err
	}
	return host, curated, nil
}

// CuratedFrom decodes an edit to a target's curated fields.
func CuratedFrom(body map[string]any) (Curated, error) {
	if _, present := body["host"]; present {
		return Curated{}, fmt.Errorf("host is not editable: it is the target's identity")
	}
	for _, machine := range []string{"observed", "network", "http", "tech", "tls", "scan"} {
		if _, present := body[machine]; present {
			return Curated{}, fmt.Errorf(
				"%s is not editable: it is discovery's output and an edit would not survive the next sweep",
				machine)
		}
	}

	var curated Curated
	if err := decode(body, &curated); err != nil {
		return Curated{}, err
	}
	if curated.Profiles == nil {
		curated.Profiles = StringList{}
	}
	if curated.Tags == nil {
		curated.Tags = StringList{}
	}
	return curated, nil
}

// ProfileFrom decodes a profile from a request body.
//
// config arrives either as an object — a JSON body posted directly — or as a
// JSON string, which is what a flag carries and therefore what both the CLI
// (`--config '{"rate-limit":25}'`) and the HTTP executor produce.
func ProfileFrom(body map[string]any) (Profile, error) {
	if encoded, ok := body["config"].(string); ok {
		decoded, err := decodeConfig(encoded)
		if err != nil {
			return Profile{}, err
		}
		// Copy rather than mutate: the caller's body is not ours to rewrite.
		replaced := make(map[string]any, len(body))
		for key, value := range body {
			replaced[key] = value
		}
		replaced["config"] = decoded
		body = replaced
	}

	var profile Profile
	if err := decode(body, &profile); err != nil {
		return Profile{}, err
	}
	if profile.Config == nil {
		profile.Config = map[string]any{}
	}
	return profile, nil
}

func decodeConfig(encoded string) (map[string]any, error) {
	if strings.TrimSpace(encoded) == "" {
		return map[string]any{}, nil
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(encoded), &config); err != nil {
		return nil, fmt.Errorf(
			"config must be a JSON object such as {\"rate-limit\":25}: %w", err)
	}
	return config, nil
}

// decode round-trips through JSON so the struct tags are the single description
// of the wire shape, and rejects unknown fields so a typo is an error rather
// than a silently ignored setting.
func decode(body map[string]any, into any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode body: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("invalid body: %w", err)
	}
	return nil
}

// SplitFindingID parses the scan#line address a finding is known by.
func SplitFindingID(id string) (scan string, line int, err error) {
	scan, number, found := strings.Cut(id, "#")
	if !found {
		return "", 0, fmt.Errorf("finding %q is not addressed as scan#line", id)
	}
	line, err = strconv.Atoi(number)
	if err != nil {
		return "", 0, fmt.Errorf("finding %q has a non-numeric line", id)
	}
	return scan, line, nil
}
