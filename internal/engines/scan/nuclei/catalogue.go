package nuclei

import (
	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines/scan"
)

// Compile-time proof that nuclei can describe its own catalogue. Most engines
// cannot, which is why this is a separate optional interface.
var _ scan.Catalogue = Engine{}

// Templates lists every installed template.
func (Engine) Templates() ([]api.Template, error) {
	index, err := SharedIndex()
	if err != nil {
		return nil, err
	}
	return documents(index.Templates), nil
}

// Corpus describes the installed templates.
//
// Nuclei is linked into this binary, so its binary cannot be missing; the corpus
// is the artifact that can be. A failure is reported rather than returned so an
// engine listing says "templates are not installed" instead of showing an engine
// that looks ready and scans nothing.
func (Engine) Corpus() api.EngineTemplates {
	corpus := api.EngineTemplates{Version: TemplateVersion(), Path: TemplatesDir()}
	index, err := SharedIndex()
	if err != nil {
		corpus.Problem = err.Error()
		return corpus
	}
	corpus.Count = len(index.Templates)
	return corpus
}

// Preview reports what a configuration would run.
func (Engine) Preview(config map[string]any) (api.TemplatePreview, error) {
	index, err := SharedIndex()
	if err != nil {
		return api.TemplatePreview{}, err
	}

	// Validated first so a preview cannot quietly describe a configuration the
	// engine would reject: an answer for a scan that could never start is worse
	// than the error explaining why.
	if err := (Engine{}).Spec().ValidateConfig(config); err != nil {
		return api.TemplatePreview{}, err
	}

	preview := index.Match(config)
	return api.TemplatePreview{
		Engine:      "nuclei",
		Total:       preview.Total,
		BySeverity:  preview.BySeverity,
		ByType:      preview.ByType,
		ByTag:       tagCounts(preview.ByTag),
		MaxRequests: preview.MaxRequests,
		Templates:   documents(preview.Templates),
		Truncated:   preview.Truncated,
		Caveats:     preview.Unsupported,
	}, nil
}

// Select returns every template a configuration selects, for listing rather
// than summarising.
func (Engine) Select(config map[string]any) ([]api.Template, error) {
	index, err := SharedIndex()
	if err != nil {
		return nil, err
	}
	return documents(index.Select(config)), nil
}

func documents(templates []Template) []api.Template {
	out := make([]api.Template, 0, len(templates))
	for _, template := range templates {
		out = append(out, document(template))
	}
	return out
}

func document(template Template) api.Template {
	return api.Template{
		ID:          template.ID,
		Name:        template.Name,
		Engine:      "nuclei",
		Severity:    template.Severity,
		Type:        template.ProtocolType,
		Tags:        orEmpty(template.Tags),
		Authors:     orEmpty(template.Authors),
		Path:        relativePath(template.FilePath),
		Description: template.Description,
		Remediation: template.Remediation,
		Reference:   template.Reference,
		CVEID:       template.CVEID,
		CVSSScore:   template.CVSSScore,
		MaxRequests: template.MaxRequests,
		Requires:    requirements(template.Requires),
	}
}

// relativePath trims the templates directory, which is a detail of this machine
// rather than of the template. What identifies a template across installs is
// its path within the release.
func relativePath(path string) string {
	root := TemplatesDir() + "/"
	if len(path) > len(root) && path[:len(root)] == root {
		return path[len(root):]
	}
	return path
}

// requirements names the capabilities a profile must enable, in the vocabulary
// of the options that enable them — so the answer to "why is this not running"
// is the name of the switch to turn on.
func requirements(caps Capabilities) []string {
	var needs []string
	if caps.Headless {
		needs = append(needs, "headless")
	}
	if caps.Code {
		needs = append(needs, "code")
	}
	if caps.File {
		needs = append(needs, "file")
	}
	if caps.SelfContained {
		needs = append(needs, "enable-self-contained")
	}
	if caps.Fuzzing {
		needs = append(needs, "dast")
	}
	return needs
}

func tagCounts(tags []TagCount) []api.TemplateTag {
	out := make([]api.TemplateTag, 0, len(tags))
	for _, tag := range tags {
		out = append(out, api.TemplateTag{Tag: tag.Tag, Count: tag.Count})
	}
	return out
}
