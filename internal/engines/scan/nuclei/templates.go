package nuclei

import (
	"fmt"
	"os"

	nucleiconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
)

// TemplatesEnv overrides where templates are read from. It exists because a
// checkout pinned for reproducibility is a real thing to want, and because tests
// need a corpus that does not move underneath them.
const TemplatesEnv = "NUCLEI_TEMPLATES_DIR"

// TemplatesDir is where nuclei loads templates from.
//
// Resolution is nuclei's own — its config directory records the location — with
// an environment override on top. Nothing here invents a path: a wrong guess
// would silently scan with a different set of templates than the preview showed.
func TemplatesDir() string {
	if override := os.Getenv(TemplatesEnv); override != "" {
		nucleiconfig.DefaultConfig.SetTemplatesDir(override)
	}
	return nucleiconfig.DefaultConfig.GetTemplateDir()
}

// TemplateVersion is the installed template release, empty when none is.
func TemplateVersion() string {
	return nucleiconfig.DefaultConfig.TemplateVersion
}

// InstallTemplates downloads the template corpus if it is absent.
//
// This is what provisioning means for a linked-in engine: the binary cannot be
// missing, but without templates every scan matches nothing — which reads as a
// clean run rather than a broken install. It is a no-op once they exist, so
// startup does not depend on the network.
func InstallTemplates() error {
	dir := TemplatesDir()
	manager := &installer.TemplateManager{}
	if err := manager.FreshInstallIfNotExists(); err != nil {
		return fmt.Errorf("install nuclei templates at %s: %w", dir, err)
	}
	return nil
}

// UpdateTemplates fetches the latest template release.
func UpdateTemplates() error {
	manager := &installer.TemplateManager{}
	if err := manager.UpdateIfOutdated(); err != nil {
		return fmt.Errorf("update nuclei templates at %s: %w", TemplatesDir(), err)
	}
	return nil
}
