package entities

import (
	"context"
	"fmt"

	"github.com/flanksource/recon/internal/missioncontrol"
)

type resourceConfigFlags struct{}

func (resourceConfigFlags) ClickyActionFlags() {}

func (r *Registry) resourceConfig(
	ctx context.Context,
	id string,
	_ resourceConfigFlags,
) (*missioncontrol.LinkedConfig, error) {
	st, err := r.store()
	if err != nil {
		return nil, err
	}
	resource, err := st.GetResource(ctx, id)
	if err != nil {
		return nil, err
	}
	if resource.ConfigID == "" {
		return nil, nil
	}
	linked, err := missioncontrol.LookupConfig(ctx, missioncontrol.ConfigLookupOptions{
		ID: resource.ConfigID, ExpectedServer: resource.ConfigServer,
		Method: resource.ConfigMatchMethod, RolledUp: resource.ConfigRolledUp,
	})
	if err != nil {
		return nil, fmt.Errorf("read config linked to resource %s: %w", id, err)
	}
	return linked, nil
}

type resourceConfigUnlinkResult struct {
	ResourceID string `json:"resourceId"`
	ConfigID   string `json:"configId"`
}

func (r *Registry) unlinkResourceConfig(
	ctx context.Context,
	id string,
	_ resourceConfigFlags,
) (resourceConfigUnlinkResult, error) {
	st, err := r.store()
	if err != nil {
		return resourceConfigUnlinkResult{}, err
	}
	configID, err := st.ClearConfigPin(ctx, id)
	if err != nil {
		return resourceConfigUnlinkResult{}, err
	}
	return resourceConfigUnlinkResult{ResourceID: id, ConfigID: configID}, nil
}
