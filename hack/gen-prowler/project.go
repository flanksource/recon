package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
	"github.com/flanksource/recon/internal/engines/scan/prowler/catalog"
	"github.com/flanksource/recon/internal/engines/scan/prowler/schema"
)

var providerTitles = map[string]string{
	"alibabacloud":    "Alibaba Cloud",
	"aws":             "AWS",
	"azure":           "Azure",
	"cloudflare":      "Cloudflare",
	"e2enetworks":     "E2E Networks",
	"gcp":             "GCP",
	"github":          "GitHub",
	"googleworkspace": "Google Workspace",
	"huaweicloud":     "Huawei Cloud",
	"iac":             "Infrastructure as Code",
	"image":           "Container Image",
	"kubernetes":      "Kubernetes",
	"linode":          "Linode",
	"llm":             "LLM",
	"m365":            "Microsoft 365",
	"mongodbatlas":    "MongoDB Atlas",
	"nhn":             "NHN",
	"okta":            "Okta",
	"openstack":       "OpenStack",
	"oraclecloud":     "OCI",
	"scaleway":        "Scaleway",
	"stackit":         "STACKIT",
	"vercel":          "Vercel",
}

type projectedProperty struct {
	key      string
	group    string
	property schema.JSONSchema
	required bool
	scope    string
}

type sourcedArgument struct {
	argument arguments.Argument
	scope    string
}

type providerProjectionOptions struct {
	Provider      arguments.Provider
	Common        []arguments.Argument
	CommonMutexes []arguments.MutualExclusion
	Checks        *catalog.Catalog
}

type argumentProjectionOptions struct {
	Argument       arguments.Argument
	Choices        []string
	Order          int
	IncludeDefault bool
}

type objectSchemaOptions struct {
	Title   string
	Fields  []projectedProperty
	Mutexes []arguments.MutualExclusion
}

func projectProvider(options providerProjectionOptions) (schema.ProviderSchema, error) {
	provider := options.Provider
	title, ok := providerTitles[provider.Name]
	if !ok {
		return schema.ProviderSchema{}, fmt.Errorf("unknown Prowler provider title %q", provider.Name)
	}
	if !slices.Contains(options.Checks.ProviderIDs(), provider.Name) {
		return schema.ProviderSchema{}, fmt.Errorf("argument provider %s is absent from the Prowler catalogue", provider.Name)
	}
	credential, err := projectCredentialSchema(provider.Name, title)
	if err != nil {
		return schema.ProviderSchema{}, err
	}

	all := make([]sourcedArgument, 0, len(provider.Arguments)+len(options.Common))
	for _, argument := range provider.Arguments {
		all = append(all, sourcedArgument{argument: argument, scope: provider.Name})
	}
	for _, argument := range options.Common {
		all = append(all, sourcedArgument{argument: argument, scope: "common"})
	}
	cli := make([]projectedProperty, 0, len(all))
	profile := []projectedProperty{{
		key: "provider", group: "Provider", scope: "generated", required: true,
		property: schema.JSONSchema{Type: "string", Title: "Provider", Const: provider.Name, ReadOnly: true},
	}}
	context := make([]projectedProperty, 0, len(provider.Arguments))

	seen := map[string]bool{}
	for _, sourced := range all {
		argument := sourced.argument
		if seen[argument.Key] {
			return schema.ProviderSchema{}, fmt.Errorf("provider %s has duplicate projected argument %q", provider.Name, argument.Key)
		}
		seen[argument.Key] = true
		values := providerChoices(provider.Name, argument, options.Checks)
		full, err := projectArgument(argumentProjectionOptions{Argument: argument, Choices: values, Order: len(cli), IncludeDefault: true})
		if err != nil {
			return schema.ProviderSchema{}, err
		}
		cli = append(cli, projectedProperty{argument.Key, argument.Group, full, argument.Required, sourced.scope})

		persisted, err := projectArgument(argumentProjectionOptions{Argument: argument, Choices: values})
		if err != nil {
			return schema.ProviderSchema{}, err
		}
		switch argument.Policy.Owner {
		case arguments.OwnerProfile:
			persisted.ProwlerOrder = integerPointer(len(profile))
			profile = append(profile, projectedProperty{argument.Key, argument.Group, persisted, argument.Required, sourced.scope})
		case arguments.OwnerContext:
			persisted.ProwlerOrder = integerPointer(len(context))
			context = append(context, projectedProperty{argument.Key, argument.Group, persisted, argument.Required, sourced.scope})
		case arguments.OwnerCredential, arguments.OwnerRunner, arguments.OwnerForbidden:
		default:
			return schema.ProviderSchema{}, fmt.Errorf("provider %s argument %s has unknown owner %q", provider.Name, argument.Key, argument.Policy.Owner)
		}
	}

	return schema.ProviderSchema{
		Provider:      provider.Name,
		Title:         title,
		Version:       schema.ProwlerVersion,
		SourceCommit:  schema.PinnedCommit,
		ComponentName: "Prowler" + componentName(title),
		CLI: buildObjectSchema(objectSchemaOptions{
			Title:  title + " Prowler CLI arguments",
			Fields: cli,
			Mutexes: append(
				append([]arguments.MutualExclusion(nil), provider.MutualExclusions...),
				options.CommonMutexes...,
			),
		}),
		Profile: buildObjectSchema(objectSchemaOptions{
			Title: title + " Prowler profile options", Fields: profile, Mutexes: options.CommonMutexes,
		}),
		Context: buildObjectSchema(objectSchemaOptions{
			Title: title + " Prowler context options", Fields: context, Mutexes: provider.MutualExclusions,
		}),
		Credential: credential,
	}, nil
}

func projectArgument(options argumentProjectionOptions) (schema.JSONSchema, error) {
	argument := options.Argument
	if argument.Policy.Owner == "" {
		return schema.JSONSchema{}, fmt.Errorf("argument %s has no ownership policy", argument.Key)
	}
	property := schema.JSONSchema{
		Type:               string(argument.Type),
		Title:              fieldTitle(argument.Key),
		Description:        argument.Help,
		Owner:              string(argument.Policy.Owner),
		Destination:        argument.Destination,
		Flags:              append([]string(nil), argument.Flags...),
		Action:             string(argument.Action),
		NArgs:              string(argument.NArgs),
		Group:              argument.Group,
		ProwlerOrder:       integerPointer(options.Order),
		CredentialSelector: argument.Policy.CredentialSelector,
	}
	if argument.Action == arguments.ActionAppend || argument.NArgs == arguments.NArgsOneOrMore || argument.NArgs == arguments.NArgsZeroOrMore {
		item := schema.JSONSchema{Type: string(argument.Type)}
		item.Enum = stringChoices(options.Choices)
		property.Type = "array"
		property.Items = &item
		if argument.NArgs == arguments.NArgsOneOrMore {
			property.MinItems = integerPointer(1)
		}
	} else {
		property.Enum = stringChoices(options.Choices)
	}
	if options.IncludeDefault && argument.Default != nil && argument.Policy.Owner != arguments.OwnerCredential && !argument.Policy.Sensitive {
		property.Default = argument.Default
	}
	if argument.Policy.Owner == arguments.OwnerCredential || argument.Policy.Sensitive {
		property.WriteOnly = true
		property.Format = "password"
		property.Sensitive = true
		property.SecretReference = true
		property.Default = nil
	}
	return property, nil
}

func providerChoices(provider string, argument arguments.Argument, checks *catalog.Catalog) []string {
	values := append([]string(nil), argument.Choices...)
	switch argument.Destination {
	case "check", "excluded_check":
		values = checks.CheckIDs(provider)
	case "service", "excluded_service":
		values = checks.Services(provider)
	case "compliance", "list_compliance_requirements":
		values = checks.ComplianceIDs(provider)
	case "category":
		values = checks.Categories(provider)
	case "resource_group":
		values = checks.ResourceGroups(provider)
	case "output_formats":
		values = supportedOutputFormats(provider, values)
	}
	return values
}

func supportedOutputFormats(provider string, values []string) []string {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		if value == "json-asff" && provider != "aws" || value == "sarif" && provider != "iac" {
			continue
		}
		filtered = append(filtered, value)
	}
	return filtered
}

func buildObjectSchema(options objectSchemaOptions) schema.JSONSchema {
	properties := make(map[string]schema.JSONSchema, len(options.Fields))
	required := []string{}
	order := make([]string, 0, len(options.Fields))
	sections := []schema.Section{}
	sectionIDs := map[string]bool{}
	for _, field := range options.Fields {
		sectionID := sectionID(field.scope, field.group)
		field.property.Section = sectionID
		properties[field.key] = field.property
		order = append(order, field.key)
		if field.required {
			required = append(required, field.key)
		}
		if !sectionIDs[sectionID] {
			sectionIDs[sectionID] = true
			sections = append(sections, schema.Section{ID: sectionID, Title: field.group, SourceURL: argumentSourceURL(field.scope)})
		}
	}
	document := schema.ObjectSchema(options.Title, properties)
	document.Required = required
	document.Order = order
	document.Sections = sections
	document.MutualExclusions = projectedMutexes(options.Mutexes, properties)
	return document
}

func projectedMutexes(groups []arguments.MutualExclusion, properties map[string]schema.JSONSchema) []schema.MutualExclusion {
	result := []schema.MutualExclusion{}
	for _, group := range groups {
		keys := []string{}
		for _, key := range group.Keys {
			if _, ok := properties[key]; ok {
				keys = append(keys, key)
			}
		}
		if len(keys) > 1 {
			result = append(result, schema.MutualExclusion{Name: group.Name, Keys: keys, Required: group.Required && len(keys) == len(group.Keys)})
		}
	}
	return result
}

func stringChoices(values []string) []any {
	if len(values) == 0 {
		return nil
	}
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func fieldTitle(key string) string {
	words := strings.Split(key, "-")
	for index, word := range words {
		switch strings.ToLower(word) {
		case "aws", "gcp", "id", "ids", "llm", "mfa", "oci", "url":
			words[index] = strings.ToUpper(word)
		default:
			runes := []rune(word)
			if len(runes) > 0 {
				runes[0] = unicode.ToUpper(runes[0])
			}
			words[index] = string(runes)
		}
	}
	return strings.Join(words, " ")
}

func componentName(title string) string {
	var result strings.Builder
	for _, char := range title {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			result.WriteRune(char)
		}
	}
	return result.String()
}

func sectionID(scope, group string) string {
	value := strings.ToLower(scope + "-" + group)
	var result strings.Builder
	dash := false
	for _, char := range value {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			result.WriteRune(char)
			dash = false
		} else if !dash && result.Len() > 0 {
			result.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(result.String(), "-")
}

func argumentSourceURL(scope string) string {
	base := "https://github.com/prowler-cloud/prowler/blob/" + schema.PinnedCommit + "/prowler/"
	if scope == "common" || scope == "generated" {
		return base + "lib/cli/parser.py"
	}
	return base + "providers/" + scope + "/lib/arguments/arguments.py"
}

func integerPointer(value int) *int { return &value }

func sortedProviderArguments(catalogue *arguments.Catalogue) []arguments.Provider {
	providers := append([]arguments.Provider(nil), catalogue.Providers...)
	sort.Slice(providers, func(i, j int) bool { return providers[i].Name < providers[j].Name })
	return providers
}
