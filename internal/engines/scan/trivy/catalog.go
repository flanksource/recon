package trivy

import (
	"fmt"

	"github.com/flanksource/recon/internal/engines"
)

// Provider ids. They name what is scanned rather than the trivy subcommand,
// because a provider id is the vocabulary an operator picks from when adding a
// target and it has to be unique across every scan engine — prowler already
// owns "image" and "kubernetes", and two engines claiming one provider is a
// target nothing can resolve an engine for.
const (
	ProviderImage      = "container-image"
	ProviderRepository = "git-repository"
	ProviderFilesystem = "filesystem"
)

// provider is one trivy scan target kind: the subcommand it runs, the context
// field naming the thing scanned, and whatever options only apply to it.
//
// A table rather than three near-identical engines: trivy's report is the same
// document whichever of these produced it, and the difference between them is
// one subcommand plus a handful of flags.
type provider struct {
	ID          string
	Title       string
	Description string

	// Command is the trivy subcommand, and Subject the context key holding the
	// positional argument it takes.
	Command string
	Subject string

	// Profile are the options only this provider accepts, appended to the
	// options every provider shares.
	Profile engines.Sections

	// Context is the provider-owned scope: what to scan, and how to address it.
	// The subject field is declared here like any other, and made required.
	Context engines.Sections
}

// providers is the complete vocabulary, in the order the picker lists them.
var providers = []provider{
	{
		ID:      ProviderImage,
		Title:   "Container image",
		Command: "image",
		Subject: "image",
		Description: "Vulnerabilities, secrets and misconfiguration in a container image, " +
			"read from a registry or the local daemon.",
		Profile: engines.Sections{{
			ID:          "image",
			Title:       "Image",
			Description: "How the image is obtained and which of its variants is read.",
			SourceURL:   "https://trivy.dev/latest/docs/target/container_image/",
			Properties: []engines.Field{
				engines.EnumList("image-src", "Image sources",
					"Where to look for the image, in priority order. Empty uses trivy's own order.",
					"docker", "containerd", "podman", "remote"),
				engines.Str("platform", "Platform",
					"Which variant of a multi-platform image to read, as os/arch."),
				engines.EnumList("image-config-scanners", "Image config scanners",
					"Additionally scan the image's own configuration — its history and metadata — "+
						"rather than only its filesystem.",
					"misconfig", "secret"),
				engines.Bool("removed-pkgs", "Removed packages",
					"Report vulnerabilities in packages deleted by a later layer. Alpine only."),
			},
		}},
		Context: engines.Sections{{
			ID:          "image-scope",
			Title:       "Image",
			Description: "The image this target names.",
			SourceURL:   "https://trivy.dev/latest/docs/target/container_image/",
			Properties: []engines.Field{
				engines.Str("image", "Image reference",
					"The image to scan, as name:tag or name@digest. Pin a digest — a tag scanned "+
						"twice can be two different images."),
			},
		}},
	},
	{
		ID:      ProviderRepository,
		Title:   "Git repository",
		Command: "repository",
		Subject: "repository",
		Description: "Vulnerabilities, secrets and misconfiguration in a git repository, " +
			"cloned from its URL.",
		Context: engines.Sections{{
			ID:          "repository-scope",
			Title:       "Repository",
			Description: "The repository this target names, and which revision of it is read.",
			SourceURL:   "https://trivy.dev/latest/docs/target/repository/",
			Properties: []engines.Field{
				engines.Str("repository", "Repository",
					"The repository to scan, as a clone URL."),
				engines.Str("branch", "Branch",
					"Scan this branch. Its head moves, so a re-run is not comparable to this one."),
				engines.Str("commit", "Commit",
					"Scan this commit. The only reference that makes a run reproducible."),
				engines.Str("tag", "Tag", "Scan this tag."),
			},
		}},
	},
	{
		ID:      ProviderFilesystem,
		Title:   "Filesystem path",
		Command: "filesystem",
		Subject: "path",
		Description: "Vulnerabilities, secrets and misconfiguration in a directory on the " +
			"machine running recon.",
		Context: engines.Sections{{
			ID:          "filesystem-scope",
			Title:       "Path",
			Description: "The directory this target names.",
			SourceURL:   "https://trivy.dev/latest/docs/target/filesystem/",
			Properties: []engines.Field{
				engines.Str("path", "Path",
					"Absolute path to the directory to scan. Relative paths are refused: a scan "+
						"runs from its own artifact directory, so one would resolve against nothing."),
			},
		}},
	},
}

// find resolves a provider id.
func find(id string) (provider, error) {
	for _, candidate := range providers {
		if candidate.ID == id {
			return candidate, nil
		}
	}
	return provider{}, fmt.Errorf("unknown trivy provider %q", id)
}

// shared are the options every provider accepts. They are trivy's own scan,
// report and database flags, which do not vary by what is being scanned.
var shared = engines.Sections{
	{
		ID:          "scan",
		Title:       "Scan",
		Description: "What to look for and how much of the target to read.",
		SourceURL:   "https://trivy.dev/latest/docs/configuration/",
		Properties: []engines.Field{
			engines.EnumList("scanners", "Scanners",
				"Which classes of issue to detect. Required rather than defaulted: what a scan "+
					"looked for is the first thing anyone reading its findings needs to know.",
				"vuln", "misconfig", "secret", "license"),
			engines.EnumList("severity", "Severities",
				"Report only these severities. Empty reports all of them.",
				"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"),
			engines.EnumList("pkg-types", "Package types",
				"Which package inventories to read: the operating system's, the application's, or both.",
				"os", "library"),
			engines.Enum("detection-priority", "Detection priority",
				"precise minimises false positives; comprehensive finds more at the cost of some.",
				"precise", "comprehensive"),
			engines.Bool("offline-scan", "Offline scan",
				"Do not call out to package registries to identify dependencies. Faster and quieter, "+
					"at the cost of some detail."),
			engines.StrList("skip-dirs", "Skip directories",
				"Directories or globs not to read."),
			engines.StrList("skip-files", "Skip files",
				"Files or globs not to read."),
		},
	},
	{
		ID:          "vulnerabilities",
		Title:       "Vulnerabilities",
		Description: "Which vulnerability findings are worth reporting. Needs the vuln scanner.",
		SourceURL:   "https://trivy.dev/latest/docs/scanner/vulnerability/",
		Properties: []engines.Field{
			engines.Bool("ignore-unfixed", "Only fixed",
				"Report only vulnerabilities that have a fix available — the ones someone can act on today."),
			engines.EnumList("ignore-status", "Ignore statuses",
				"Drop vulnerabilities in these fix states.",
				"unknown", "not_affected", "affected", "fixed", "under_investigation",
				"will_not_fix", "fix_deferred", "end_of_life"),
		},
	},
	{
		ID:          "misconfiguration",
		Title:       "Misconfiguration",
		Description: "How configuration is checked. Needs the misconfig scanner.",
		SourceURL:   "https://trivy.dev/latest/docs/scanner/misconfiguration/",
		Properties: []engines.Field{
			engines.EnumList("misconfig-scanners", "Config formats",
				"Which configuration formats to check. Empty checks every format trivy knows.",
				"azure-arm", "cloudformation", "dockerfile", "helm", "kubernetes",
				"terraform", "terraformplan-json", "terraformplan-snapshot", "ansible"),
			engines.Bool("include-non-failures", "Include passes",
				"Record the checks that passed as well as the ones that failed. They are counted "+
					"either way; this puts them in the retained report."),
		},
	},
	{
		ID:          "licenses",
		Title:       "Licenses",
		Description: "How licences are detected. Needs the license scanner.",
		SourceURL:   "https://trivy.dev/latest/docs/scanner/license/",
		Properties: []engines.Field{
			engines.Bool("license-full", "Full detection",
				"Read source headers and licence files rather than only package metadata. Slower."),
			engines.StrList("ignored-licenses", "Ignored licences",
				"Licences not to report."),
		},
	},
	{
		ID:          "database",
		Title:       "Databases",
		Description: "The vulnerability and check databases a run resolves against.",
		SourceURL:   "https://trivy.dev/latest/docs/configuration/db/",
		Properties: []engines.Field{
			engines.Bool("skip-db-update", "Skip vulnerability DB update",
				"Use the cached vulnerability database. A scan against a stale database misses "+
					"everything published since it was fetched."),
			engines.Bool("skip-java-db-update", "Skip Java DB update",
				"Use the cached Java index database."),
			engines.Bool("skip-check-update", "Skip checks update",
				"Use the cached misconfiguration checks bundle."),
			engines.StrList("db-repository", "Vulnerability DB repositories",
				"OCI repositories to fetch the vulnerability database from, in priority order."),
			engines.Str("checks-bundle-repository", "Checks repository",
				"OCI repository to fetch the misconfiguration checks bundle from."),
		},
	},
	{
		ID:          "execution",
		Title:       "Execution",
		Description: "How the run is bounded.",
		SourceURL:   "https://trivy.dev/latest/docs/configuration/",
		Properties: []engines.Field{
			engines.Str("timeout", "Timeout",
				"How long one target may take, as a Go duration such as 10m. Trivy's own default is 5m, "+
					"which a large image can exceed."),
			engines.Int("parallel", "Parallelism",
				"How many files to analyse at once. 0 matches the machine.", 0),
		},
	},
}

// optionCatalog builds one schema variant per provider.
func optionCatalog() (engines.OptionCatalog, error) {
	variants := make([]engines.OptionVariant, 0, len(providers))
	for _, entry := range providers {
		sections := make(engines.Sections, 0, len(entry.Profile)+len(shared))
		sections = append(sections, entry.Profile...)
		sections = append(sections, shared...)

		profile := engines.SchemaFromSections(sections)
		if err := addDiscriminator(profile, entry); err != nil {
			return engines.OptionCatalog{}, err
		}
		if err := requireList(profile, "scanners"); err != nil {
			return engines.OptionCatalog{}, err
		}
		if err := denullifyItems(profile); err != nil {
			return engines.OptionCatalog{}, err
		}
		profile["title"] = entry.Title + " trivy options"

		context := engines.SchemaFromSections(entry.Context)
		context["title"] = entry.Title + " scope"
		if err := requireText(context, entry.Subject); err != nil {
			return engines.OptionCatalog{}, err
		}
		if err := denullifyItems(context); err != nil {
			return engines.OptionCatalog{}, err
		}
		if entry.ID == ProviderFilesystem {
			if err := absolutePath(context, entry.Subject); err != nil {
				return engines.OptionCatalog{}, err
			}
		}

		variants = append(variants, engines.OptionVariant{
			ID: entry.ID, Title: entry.Title, Schema: profile, ContextSchema: &context,
		})
	}
	return engines.OptionCatalog{Discriminator: "provider", Variants: variants}, nil
}

// addDiscriminator writes the provider field the catalog selects a variant by.
//
// Built here rather than declared as a Field because it is not an option: it is
// pinned to one value, read-only, and required, none of which the form
// vocabulary expresses.
func addDiscriminator(schema engines.JSONSchema, entry provider) error {
	properties, ok := schema["properties"].(engines.JSONSchema)
	if !ok {
		return fmt.Errorf("trivy provider %s: schema has no properties", entry.ID)
	}
	properties["provider"] = engines.JSONSchema{
		"type": "string", "title": "Provider", "description": entry.Description,
		"const": entry.ID, "readOnly": true, "x-section": "provider",
	}

	order, ok := schema["x-order"].([]string)
	if !ok {
		return fmt.Errorf("trivy provider %s: schema has no field order", entry.ID)
	}
	schema["x-order"] = append([]string{"provider"}, order...)

	layout, ok := schema["x-sections"].([]engines.OptionSection)
	if !ok {
		return fmt.Errorf("trivy provider %s: schema has no sections", entry.ID)
	}
	schema["x-sections"] = append([]engines.OptionSection{{
		ID: "provider", Title: "Provider", Description: entry.Description,
	}}, layout...)

	return require(schema, "provider")
}

// denullifyItems removes the null option from every list's element type.
//
// The form vocabulary makes each option nullable so a field can be cleared, and
// for a scalar that is right. For an element of a list it is not: there is no
// unset element, and leaving it in puts "<nil>" in the list of scanners a
// rejection message says are allowed.
func denullifyItems(schema engines.JSONSchema) error {
	properties, ok := schema["properties"].(engines.JSONSchema)
	if !ok {
		return fmt.Errorf("trivy schema has no properties")
	}
	for key, value := range properties {
		property, ok := value.(engines.JSONSchema)
		if !ok {
			return fmt.Errorf("trivy option %q is not a schema", key)
		}
		items, ok := property["items"].(engines.JSONSchema)
		if !ok {
			continue
		}
		if types, ok := items["type"].([]string); ok && len(types) > 0 {
			items["type"] = types[0]
		}
		if values, ok := items["enum"].([]any); ok && len(values) > 0 && values[len(values)-1] == nil {
			items["enum"] = values[:len(values)-1]
		}
	}
	return nil
}

// require marks a declared property mandatory.
func require(schema engines.JSONSchema, key string) error {
	properties, ok := schema["properties"].(engines.JSONSchema)
	if !ok {
		return fmt.Errorf("trivy schema has no properties")
	}
	if _, declared := properties[key]; !declared {
		return fmt.Errorf("trivy schema cannot require undeclared option %q", key)
	}
	existing, _ := schema["required"].([]string)
	schema["required"] = append(existing, key)
	return nil
}

// requireText makes a field mandatory and refuses the empty and null values the
// form vocabulary otherwise permits. A required key set to null passes `required`
// and then names nothing, which is exactly the target that would be scanned as ""
// — so the constraint has to say non-empty string, not merely present.
func requireText(schema engines.JSONSchema, key string) error {
	properties, ok := schema["properties"].(engines.JSONSchema)
	if !ok {
		return fmt.Errorf("trivy schema has no properties")
	}
	property, ok := properties[key].(engines.JSONSchema)
	if !ok {
		return fmt.Errorf("trivy schema has no option %q", key)
	}
	property["type"] = "string"
	property["minLength"] = 1
	return require(schema, key)
}

// requireList makes a list field mandatory and non-empty, for the same reason
// requireText refuses "": a required list set to null or [] is a scan that
// declares it looked for nothing.
func requireList(schema engines.JSONSchema, key string) error {
	properties, ok := schema["properties"].(engines.JSONSchema)
	if !ok {
		return fmt.Errorf("trivy schema has no properties")
	}
	property, ok := properties[key].(engines.JSONSchema)
	if !ok {
		return fmt.Errorf("trivy schema has no option %q", key)
	}
	property["type"] = "array"
	property["minItems"] = 1
	return require(schema, key)
}

// absolutePath constrains a path field to one that resolves the same wherever
// it is read from.
func absolutePath(schema engines.JSONSchema, key string) error {
	properties, ok := schema["properties"].(engines.JSONSchema)
	if !ok {
		return fmt.Errorf("trivy schema has no properties")
	}
	property, ok := properties[key].(engines.JSONSchema)
	if !ok {
		return fmt.Errorf("trivy schema has no option %q", key)
	}
	property["pattern"] = `^/`
	return nil
}
