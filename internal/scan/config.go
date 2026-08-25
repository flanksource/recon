package scan

import (
	"context"
	"fmt"

	"github.com/flanksource/recon/internal/engines"
)

// resolveConfig layers the run-only overrides over the stored profile and
// validates the result, so a run cannot use a configuration the engine's own
// catalog would reject.
func (r *Runtime) resolveConfig(ctx context.Context, spec engines.Spec, request Request) (map[string]any, error) {
	profile, err := r.Store.GetProfile(ctx, "scan:"+spec.Name+":"+request.Profile)
	if err != nil {
		return nil, err
	}
	if err := spec.ValidateOverrides(profile.Config, request.Overrides); err != nil {
		return nil, fmt.Errorf("scan configuration: %w", err)
	}

	config := engines.LayerOverrides(profile.Config, request.Overrides)
	if err := spec.ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("scan configuration: %w", err)
	}
	return config, nil
}
