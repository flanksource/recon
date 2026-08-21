package store

import (
	"reflect"

	"github.com/flanksource/recon/internal/api"
)

// normalizeTarget resolves defaults needed by direct Go callers before schema
// validation and persistence. Request bodies already arrive normalized through
// api.TargetFrom; observation code constructs host documents directly.
func normalizeTarget(target api.TargetDocument) api.TargetDocument {
	if target.Kind == "" {
		target.Kind = api.KindHost
	}
	if target.ID == "" && target.Host != "" {
		target.ID = target.Host
	}
	if target.Kind == api.KindProviderContext && target.Arguments == nil {
		target.Arguments = map[string]any{}
	}
	if target.Credentials != nil && target.Credentials.Empty() {
		target.Credentials = nil
	}
	return target
}

func normalizeNewTarget(target api.NewTarget) api.NewTarget {
	if target.Kind == "" {
		target.Kind = api.KindHost
	}
	if target.ID == "" && target.Host != "" {
		target.ID = target.Host
	}
	if target.Kind == api.KindProviderContext && target.Arguments == nil {
		target.Arguments = map[string]any{}
	}
	if target.Credentials != nil && target.Credentials.Empty() {
		target.Credentials = nil
	}
	return target
}

func stringRef(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func sameArguments(left, right map[string]any) bool {
	if left == nil {
		left = map[string]any{}
	}
	if right == nil {
		right = map[string]any{}
	}
	return reflect.DeepEqual(left, right)
}

func sameCredentials(left, right *api.ProviderCredentials) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return reflect.DeepEqual(left.Stored(), right.Stored())
}
