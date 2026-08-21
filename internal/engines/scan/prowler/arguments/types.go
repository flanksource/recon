package arguments

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

type Owner string

const (
	OwnerProfile    Owner = "profile"
	OwnerContext    Owner = "context"
	OwnerCredential Owner = "credential"
	OwnerRunner     Owner = "runner"
	OwnerForbidden  Owner = "forbidden"
)

type Action string

const (
	ActionStore     Action = "store"
	ActionStoreTrue Action = "store_true"
	ActionAppend    Action = "append"
)

type NArgs string

const (
	NArgsNone       NArgs = "0"
	NArgsOne        NArgs = "1"
	NArgsOptional   NArgs = "?"
	NArgsOneOrMore  NArgs = "+"
	NArgsZeroOrMore NArgs = "*"
)

type ValueType string

const (
	TypeString  ValueType = "string"
	TypeInteger ValueType = "integer"
	TypeNumber  ValueType = "number"
	TypeBoolean ValueType = "boolean"
)

type Policy struct {
	Owner              Owner  `json:"owner"`
	Sensitive          bool   `json:"sensitive,omitempty"`
	Redact             bool   `json:"redact,omitempty"`
	CredentialSelector bool   `json:"credentialSelector,omitempty"`
	Reason             string `json:"reason,omitempty"`
}

type Argument struct {
	Key         string    `json:"key"`
	Destination string    `json:"destination"`
	Flags       []string  `json:"flags"`
	Canonical   string    `json:"canonical"`
	Order       int       `json:"order"`
	Group       string    `json:"group,omitempty"`
	Action      Action    `json:"action"`
	NArgs       NArgs     `json:"nargs"`
	Type        ValueType `json:"type"`
	Choices     []string  `json:"choices,omitempty"`
	Default     any       `json:"default,omitempty"`
	Required    bool      `json:"required,omitempty"`
	Help        string    `json:"help,omitempty"`
	Metavar     string    `json:"metavar,omitempty"`
	Policy      Policy    `json:"policy"`
}

type MutualExclusion struct {
	Name     string   `json:"name"`
	Keys     []string `json:"keys"`
	Required bool     `json:"required,omitempty"`
}

type Provider struct {
	Name             string            `json:"name"`
	Arguments        []Argument        `json:"arguments"`
	MutualExclusions []MutualExclusion `json:"mutualExclusions,omitempty"`
}

type Catalogue struct {
	Common                 []Argument          `json:"common"`
	CommonMutualExclusions []MutualExclusion   `json:"commonMutualExclusions,omitempty"`
	Providers              []Provider          `json:"providers"`
	SensitiveFlags         map[string][]string `json:"sensitiveFlags"`
}

type Inputs struct {
	Profile    map[string]any
	Context    map[string]any
	Credential map[string]any
	Runner     map[string]any
}

var BuiltInProviders = []string{
	"alibabacloud", "aws", "azure", "cloudflare", "e2enetworks", "gcp", "github",
	"googleworkspace", "huaweicloud", "iac", "image", "kubernetes", "linode", "llm",
	"m365", "mongodbatlas", "nhn", "okta", "openstack", "oraclecloud", "scaleway",
	"stackit", "vercel",
}

var ProviderAliases = map[string]string{
	"microsoft365": "m365",
	"oci":          "oraclecloud",
}

func LoadJSON(data []byte) (*Catalogue, error) {
	var catalogue Catalogue
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalogue); err != nil {
		return nil, fmt.Errorf("decode Prowler argument catalogue: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("decode Prowler argument catalogue: trailing JSON value")
	}
	if err := catalogue.ApplyPolicies(); err != nil {
		return nil, err
	}
	if err := catalogue.Validate(); err != nil {
		return nil, err
	}
	if err := catalogue.ValidateBuiltInCoverage(); err != nil {
		return nil, err
	}
	if err := catalogue.ValidateSensitivity(); err != nil {
		return nil, err
	}
	return &catalogue, nil
}

func IsBuiltInProvider(provider string) bool {
	_, err := NormalizeProvider(provider)
	return err == nil
}

func NormalizeProvider(provider string) (string, error) {
	if canonical, ok := ProviderAliases[provider]; ok {
		return canonical, nil
	}
	if slices.Contains(BuiltInProviders, provider) {
		return provider, nil
	}
	return "", fmt.Errorf("unsupported Prowler provider %q", provider)
}

func (c Catalogue) ValidateBuiltInCoverage() error {
	found := make(map[string]bool, len(c.Providers))
	for _, provider := range c.Providers {
		found[provider.Name] = true
	}
	missing := make([]string, 0)
	for _, provider := range BuiltInProviders {
		if !found[provider] {
			missing = append(missing, provider)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing built-in providers: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (c Catalogue) Validate() error {
	if err := validateArguments("common", c.Common); err != nil {
		return err
	}
	if err := validateMutexes("common", c.Common, c.CommonMutualExclusions); err != nil {
		return err
	}
	seen := make(map[string]bool, len(c.Providers))
	for _, provider := range c.Providers {
		if !slices.Contains(BuiltInProviders, provider.Name) {
			return fmt.Errorf("unsupported Prowler provider %q", provider.Name)
		}
		if seen[provider.Name] {
			return fmt.Errorf("duplicate Prowler provider %q", provider.Name)
		}
		seen[provider.Name] = true
		if err := validateArguments(provider.Name, provider.Arguments); err != nil {
			return err
		}
		combined := append(slices.Clone(c.Common), provider.Arguments...)
		if err := validateUniqueKeys(provider.Name, combined); err != nil {
			return err
		}
		if err := validateUniqueFlags(provider.Name, combined); err != nil {
			return err
		}
		if err := validateUniqueDestinations(provider.Name, combined); err != nil {
			return err
		}
		if err := validateMutexes(provider.Name, combined, provider.MutualExclusions); err != nil {
			return err
		}
	}
	return nil
}

func validateArguments(scope string, args []Argument) error {
	orders := make(map[int]bool, len(args))
	flags := make(map[string]bool)
	for _, arg := range args {
		if err := validateArgument(scope, arg); err != nil {
			return err
		}
		if orders[arg.Order] {
			return fmt.Errorf("%s has duplicate argument order %d", scope, arg.Order)
		}
		orders[arg.Order] = true
		for _, flag := range arg.Flags {
			if flags[flag] {
				return fmt.Errorf("%s has duplicate flag %q", scope, flag)
			}
			flags[flag] = true
		}
	}
	if err := validateUniqueKeys(scope, args); err != nil {
		return err
	}
	return validateUniqueDestinations(scope, args)
}

func validateArgument(scope string, arg Argument) error {
	if arg.Key == "" || arg.Destination == "" || arg.Canonical == "" {
		return fmt.Errorf("%s argument has an empty key, destination, or canonical flag", scope)
	}
	if arg.Order < 0 {
		return fmt.Errorf("%s argument %q has negative order", scope, arg.Key)
	}
	if !slices.Contains(arg.Flags, arg.Canonical) {
		return fmt.Errorf("%s argument %q canonical flag %q is not an alias", scope, arg.Key, arg.Canonical)
	}
	for _, flag := range arg.Flags {
		if !strings.HasPrefix(flag, "-") || strings.Contains(flag, "=") {
			return fmt.Errorf("%s argument %q has malformed flag %q", scope, arg.Key, flag)
		}
	}
	if err := validateShape(arg); err != nil {
		return fmt.Errorf("%s argument %q: %w", scope, arg.Key, err)
	}
	return validatePolicy(scope, arg)
}

func validateShape(arg Argument) error {
	if !slices.Contains([]Action{ActionStore, ActionStoreTrue, ActionAppend}, arg.Action) {
		return fmt.Errorf("unsupported action %q", arg.Action)
	}
	if !slices.Contains([]ValueType{TypeString, TypeInteger, TypeNumber, TypeBoolean}, arg.Type) {
		return fmt.Errorf("unsupported type %q", arg.Type)
	}
	if !slices.Contains([]NArgs{NArgsNone, NArgsOne, NArgsOptional, NArgsOneOrMore, NArgsZeroOrMore}, arg.NArgs) {
		return fmt.Errorf("unsupported nargs %q", arg.NArgs)
	}
	if arg.Action == ActionStoreTrue && (arg.NArgs != NArgsNone || arg.Type != TypeBoolean) {
		return fmt.Errorf("store_true requires boolean type and nargs 0")
	}
	if arg.Action != ActionStoreTrue && arg.NArgs == NArgsNone {
		return fmt.Errorf("action %q does not support nargs 0", arg.Action)
	}
	return nil
}

func validatePolicy(scope string, arg Argument) error {
	owners := []Owner{OwnerProfile, OwnerContext, OwnerCredential, OwnerRunner, OwnerForbidden}
	if !slices.Contains(owners, arg.Policy.Owner) {
		return fmt.Errorf("%s argument %q has invalid or missing policy owner", scope, arg.Key)
	}
	if arg.Policy.Sensitive && !arg.Policy.Redact {
		return fmt.Errorf("%s argument %q is sensitive but not redacted", scope, arg.Key)
	}
	if arg.Policy.Owner == OwnerCredential && (!arg.Policy.Sensitive || !arg.Policy.Redact) {
		return fmt.Errorf("%s credential argument %q must be sensitive and redacted", scope, arg.Key)
	}
	if arg.Policy.CredentialSelector && arg.Policy.Owner != OwnerContext {
		return fmt.Errorf("%s credential selector %q must be context-owned", scope, arg.Key)
	}
	if arg.Policy.Owner == OwnerForbidden && arg.Policy.Reason == "" {
		return fmt.Errorf("%s forbidden argument %q has no reason", scope, arg.Key)
	}
	return nil
}

func validateUniqueKeys(scope string, args []Argument) error {
	keys := make(map[string]bool, len(args))
	for _, arg := range args {
		if keys[arg.Key] {
			return fmt.Errorf("%s has duplicate argument key %q", scope, arg.Key)
		}
		keys[arg.Key] = true
	}
	return nil
}

func validateUniqueFlags(scope string, args []Argument) error {
	flags := make(map[string]bool)
	for _, arg := range args {
		for _, flag := range arg.Flags {
			if flags[flag] {
				return fmt.Errorf("%s has duplicate flag %q", scope, flag)
			}
			flags[flag] = true
		}
	}
	return nil
}

func validateUniqueDestinations(scope string, args []Argument) error {
	destinations := make(map[string]bool, len(args))
	for _, arg := range args {
		if destinations[arg.Destination] {
			return fmt.Errorf("%s has duplicate destination %q; aliases must be merged", scope, arg.Destination)
		}
		destinations[arg.Destination] = true
	}
	return nil
}

func validateMutexes(scope string, args []Argument, mutexes []MutualExclusion) error {
	keys := make(map[string]bool, len(args))
	for _, arg := range args {
		keys[arg.Key] = true
	}
	for _, mutex := range mutexes {
		if mutex.Name == "" || len(mutex.Keys) < 2 {
			return fmt.Errorf("%s has malformed mutual exclusion group", scope)
		}
		seen := map[string]bool{}
		for _, key := range mutex.Keys {
			if !keys[key] {
				return fmt.Errorf("%s mutual exclusion %q references unknown key %q", scope, mutex.Name, key)
			}
			if seen[key] {
				return fmt.Errorf("%s mutual exclusion %q repeats key %q", scope, mutex.Name, key)
			}
			seen[key] = true
		}
	}
	return nil
}
