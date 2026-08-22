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

// NewTarget is the body of a create: the fields fixed when a target comes into
// existence, and the curated fields that are not.
type NewTarget struct {
	// ID is the stable inventory identity. Host is populated only for an
	// addressable target; provider contexts carry their scope in Arguments.
	ID   string
	Host string

	// Kind is how a scan reaches it. Settable only here, for the same reason
	// Host is: changing it would repoint every future run at something else.
	Kind TargetKind

	Provider       string
	CredentialMode CredentialMode
	Arguments      map[string]any
	Credentials    *ProviderCredentials
	CredentialsSet bool

	Curated Curated
}

// TargetUpdate is one atomic edit. Stable identity remains immutable, while a
// provider context's credential source and non-secret provider arguments may
// change alongside its curated classification and assigned profiles.
type TargetUpdate struct {
	Curated Curated

	// Pointers distinguish an omitted field from explicitly replacing arguments
	// with an empty object or changing the credential mode.
	CredentialMode *CredentialMode
	Arguments      *map[string]any
	Credentials    *ProviderCredentials
	CredentialsSet bool
}

// TargetFrom decodes the body of a create: the identity fields, which are
// settable only here, plus the curated fields.
//
// The host arrives as `host` from a JSON body and as `id` from the entity
// framework's flag mapping; both name the same thing and disagreeing about
// which is authoritative would make one of the two surfaces silently create
// nothing.
func TargetFrom(body map[string]any) (NewTarget, error) {
	host, _ := body["host"].(string)
	id, _ := body["id"].(string)

	kind := KindHost
	if value, present := body["kind"]; present {
		text, ok := value.(string)
		if !ok {
			return NewTarget{}, fmt.Errorf("kind must be a string")
		}
		kind = TargetKind(text)
		if !validKind(kind) {
			return NewTarget{}, fmt.Errorf("unknown kind %q: expected one of %s", text, joinKinds())
		}
	}

	provider, _ := body["provider"].(string)
	credentialMode, _ := body["credentialMode"].(string)
	arguments := map[string]any{}
	if value, present := body["arguments"]; present {
		decoded, err := objectFrom(value, "arguments")
		if err != nil {
			return NewTarget{}, err
		}
		arguments = decoded
	}
	var credentials *ProviderCredentials
	value, credentialsSet := body["credentials"]
	if credentialsSet {
		decoded, err := credentialsFrom(value)
		if err != nil {
			return NewTarget{}, err
		}
		credentials = decoded
	}

	switch kind {
	case KindHost:
		if host == "" {
			host = id
		}
		if host == "" {
			return NewTarget{}, fmt.Errorf("host is required for a host target")
		}
		if id == "" {
			id = host
		}
		if provider != "" || credentialMode != "" || len(arguments) > 0 || credentials != nil {
			return NewTarget{}, fmt.Errorf("a host cannot have provider context")
		}
		arguments = nil
	case KindProviderContext:
		if id == "" {
			return NewTarget{}, fmt.Errorf("id is required for a provider-context target")
		}
		if host != "" {
			return NewTarget{}, fmt.Errorf("a provider-context cannot have a host")
		}
		if provider == "" {
			return NewTarget{}, fmt.Errorf("provider is required for a provider-context target")
		}
		if !CredentialMode(credentialMode).Valid() {
			return NewTarget{}, fmt.Errorf("credentialMode is required and must be ambient or configured")
		}
	}

	rest := make(map[string]any, len(body))
	for key, value := range body {
		if key == "host" || key == "id" || key == "kind" || key == "provider" ||
			key == "credentialMode" || key == "arguments" || key == "credentials" {
			continue
		}
		rest[key] = value
	}

	curated, err := CuratedFrom(rest)
	if err != nil {
		return NewTarget{}, err
	}
	if !kind.Addressable() && len(curated.Ports) > 0 {
		return NewTarget{}, fmt.Errorf(
			"a %s has no ports: it is audited through a provider API rather than contacted over the network", kind)
	}
	return NewTarget{
		ID: id, Host: host, Kind: kind, Provider: provider,
		CredentialMode: CredentialMode(credentialMode), Arguments: arguments,
		Credentials: credentials, CredentialsSet: credentialsSet,
		Curated: curated,
	}, nil
}

// TargetUpdateFrom decodes the update body. Provider and kind are stable
// identity; credentialMode and arguments are mutable provider configuration.
func TargetUpdateFrom(body map[string]any) (TargetUpdate, error) {
	for _, identity := range []string{"id", "host", "kind", "provider"} {
		if _, present := body[identity]; present {
			return TargetUpdate{}, fmt.Errorf("%s is not editable: it defines the target's identity", identity)
		}
	}

	var mode *CredentialMode
	if value, present := body["credentialMode"]; present {
		text, ok := value.(string)
		if !ok || !CredentialMode(text).Valid() {
			return TargetUpdate{}, fmt.Errorf("credentialMode must be ambient or configured")
		}
		parsed := CredentialMode(text)
		mode = &parsed
	}

	var arguments *map[string]any
	if value, present := body["arguments"]; present {
		parsed, err := objectFrom(value, "arguments")
		if err != nil {
			return TargetUpdate{}, err
		}
		arguments = &parsed
	}
	var credentials *ProviderCredentials
	credentialsSet := false
	if value, present := body["credentials"]; present {
		credentialsSet = true
		parsed, err := credentialsFrom(value)
		if err != nil {
			return TargetUpdate{}, err
		}
		credentials = parsed
	}

	rest := make(map[string]any, len(body))
	for key, value := range body {
		if key != "credentialMode" && key != "arguments" && key != "credentials" {
			rest[key] = value
		}
	}
	curated, err := CuratedFrom(rest)
	if err != nil {
		return TargetUpdate{}, err
	}
	return TargetUpdate{
		Curated: curated, CredentialMode: mode, Arguments: arguments,
		Credentials: credentials, CredentialsSet: credentialsSet,
	}, nil
}

func credentialsFrom(value any) (*ProviderCredentials, error) {
	if value == nil {
		return nil, nil
	}
	if text, ok := value.(string); ok && strings.TrimSpace(text) == "null" {
		return nil, nil
	}
	object, err := objectFrom(value, "credentials")
	if err != nil {
		return nil, err
	}
	if values, ok := object["envVars"].([]any); ok {
		for _, value := range values {
			item, ok := value.(map[string]any)
			if !ok {
				continue
			}
			if _, present := item["configured"]; present {
				return nil, fmt.Errorf("credential configured is read-only")
			}
		}
	}
	var credentials ProviderCredentials
	if err := decode(object, &credentials); err != nil {
		return nil, err
	}
	if err := credentials.ValidateWrite(); err != nil {
		return nil, err
	}
	return &credentials, nil
}

// objectFrom decodes a nested object field.
//
// It arrives either as an object — a JSON body posted directly, or a document
// read off disk — or as a JSON string, because the HTTP executor flattens every
// top-level body value to a string before a handler sees it. Accepting only the
// object form made provider-context arguments unsettable over HTTP: both the
// create and the update refused every request the UI could send. ProfileFrom's
// config has taken both forms for the same reason since it was written.
func objectFrom(value any, field string) (map[string]any, error) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return map[string]any{}, nil
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(typed), &decoded); err != nil {
			return nil, fmt.Errorf("%s must be a JSON object: %w", field, err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("%s must be an object", field)
	}
}

func validKind(kind TargetKind) bool {
	for _, known := range TargetKinds() {
		if kind == known {
			return true
		}
	}
	return false
}

func joinKinds() string {
	names := make([]string, 0, len(TargetKinds()))
	for _, kind := range TargetKinds() {
		names = append(names, string(kind))
	}
	return strings.Join(names, ", ")
}

// CuratedFrom decodes an edit to a target's curated fields.
func CuratedFrom(body map[string]any) (Curated, error) {
	if _, present := body["host"]; present {
		return Curated{}, fmt.Errorf("host is not editable: it is the target's identity")
	}
	// Kind decides how a scan reaches a target, so changing it would silently
	// repoint every future run — and a "full curated-field replacement" update
	// that omitted it would turn a cloud account back into a hostname.
	if _, present := body["kind"]; present {
		return Curated{}, fmt.Errorf("kind is not editable: it is fixed when the target is created")
	}
	for _, identity := range []string{"id", "provider", "credentialMode", "arguments", "credentials"} {
		if _, present := body[identity]; present {
			return Curated{}, fmt.Errorf("%s is not editable: it defines the target's provider context", identity)
		}
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

// MuteRuleFrom decodes a mute rule from a request body.
//
// targets arrives either as an object — a JSON body posted directly — or as a
// JSON string, which is what a flag carries and therefore what both the CLI
// (`targets '{"class":["non-prod"]}'`) and the HTTP executor produce. Same
// arrangement as a profile's config, for the same reason.
func MuteRuleFrom(body map[string]any) (MuteRule, error) {
	if value, present := body["targets"]; present {
		decoded, err := objectFrom(value, "targets")
		if err != nil {
			return MuteRule{}, err
		}
		// Copy rather than mutate: the caller's body is not ours to rewrite.
		replaced := make(map[string]any, len(body))
		for key, existing := range body {
			replaced[key] = existing
		}
		replaced["targets"] = decoded
		body = replaced
	}

	var rule MuteRule
	if err := decode(body, &rule); err != nil {
		return MuteRule{}, err
	}
	return rule, nil
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
