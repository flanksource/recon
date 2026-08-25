package entities

import (
	"context"
	"strings"

	"github.com/flanksource/clicky"
	clickyapi "github.com/flanksource/clicky/api"
	"github.com/flanksource/commons/logger"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/store"
)

func (r *Registry) registerConnection() {
	clicky.NewEntity[api.ConnectionReference, store.ConnectionOpts, api.ConnectionReference]("connection").
		Aliases("connections").
		ToolGroup("configuration").
		ListWithContext(bind(r, (*store.Store).ListConnectionReferences)).
		Filters(connectionReferenceFilter{registry: r}).
		Register()
}

type connectionReferenceFilter struct{ registry *Registry }

func (connectionReferenceFilter) Key() string   { return "connection" }
func (connectionReferenceFilter) Label() string { return "Connection" }
func (connectionReferenceFilter) Lookup(*store.ConnectionOpts) (map[string]clickyapi.Textable, error) {
	return nil, nil
}
func (f connectionReferenceFilter) Options(opts store.ConnectionOpts) map[string]clickyapi.Textable {
	return f.OptionsWithContext(context.Background(), opts)
}
func (f connectionReferenceFilter) OptionsWithContext(
	ctx context.Context, opts store.ConnectionOpts,
) map[string]clickyapi.Textable {
	options, _ := f.options(ctx, opts, "", 0)
	return options
}
func (f connectionReferenceFilter) OptionsWithQuery(
	opts store.ConnectionOpts, query string, limit int,
) (map[string]clickyapi.Textable, int) {
	return f.OptionsWithQueryAndContext(context.Background(), opts, query, limit)
}
func (f connectionReferenceFilter) OptionsWithQueryAndContext(
	ctx context.Context, opts store.ConnectionOpts, query string, limit int,
) (map[string]clickyapi.Textable, int) {
	return f.options(ctx, opts, query, limit)
}

func (f connectionReferenceFilter) options(
	ctx context.Context, opts store.ConnectionOpts, query string, limit int,
) (map[string]clickyapi.Textable, int) {
	st, err := f.registry.store()
	if err != nil {
		logger.Debugf("connection filter has no options: %v", err)
		return nil, 0
	}
	connections, err := st.ListConnectionReferences(ctx, opts)
	if err != nil {
		logger.Warnf("connection filter has no options: %v", err)
		return nil, 0
	}
	matched := make([]api.ConnectionReference, 0, len(connections))
	query = strings.ToLower(query)
	for _, connection := range connections {
		if query == "" || strings.Contains(strings.ToLower(connection.Reference), query) ||
			strings.Contains(strings.ToLower(connection.Name), query) {
			matched = append(matched, connection)
		}
	}
	total := len(matched)
	if limit > 0 && len(matched) > limit {
		matched = matched[:limit]
	}
	options := make(map[string]clickyapi.Textable, len(matched))
	for _, connection := range matched {
		options[connection.Reference] = clickyapi.Text{Content: connection.Reference}
	}
	return options, total
}
