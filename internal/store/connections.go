package store

import (
	"context"
	"fmt"
	"slices"
	"strings"

	dbcontext "github.com/flanksource/commons-db/context"
	commonsmodels "github.com/flanksource/commons-db/models"

	"github.com/flanksource/recon/internal/api"
)

type ConnectionOpts struct {
	Type  string `json:"type,omitempty" flag:"type" help:"Only this connection type"`
	Types string `json:"types,omitempty" flag:"types" help:"Only these comma-separated connection types"`
}

func (s *Store) ListConnectionReferences(ctx context.Context, opts ConnectionOpts) ([]api.ConnectionReference, error) {
	query := s.DB(ctx).Model(&commonsmodels.Connection{})
	types := connectionTypes(opts)
	if len(types) > 0 {
		query = query.Where("type IN ?", types)
	}
	var rows []commonsmodels.Connection
	if err := query.Order(`namespace COLLATE "C" ASC, name COLLATE "C" ASC`).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list connections: %w", err)
	}
	result := make([]api.ConnectionReference, 0, len(rows))
	for _, row := range rows {
		reference := "connection://" + row.Name
		if row.Namespace != "" {
			reference = "connection://" + row.Namespace + "/" + row.Name
		}
		result = append(result, api.ConnectionReference{
			ID: reference, Reference: reference, Name: row.Name, Namespace: row.Namespace, Type: row.Type,
		})
	}
	return result, nil
}

func (s *Store) ConnectionType(ctx context.Context, reference string) (string, error) {
	connection, err := dbcontext.FindConnectionByURL(
		dbcontext.NewContext(ctx).WithDB(s.DB(ctx), nil), reference)
	if err != nil {
		return "", err
	}
	if connection == nil {
		return "", NotFound("connection", reference)
	}
	return connection.Type, nil
}

func connectionTypes(opts ConnectionOpts) []string {
	values := []string{}
	if opts.Type != "" {
		values = append(values, opts.Type)
	}
	for _, value := range strings.Split(opts.Types, ",") {
		if value = strings.TrimSpace(value); value != "" && !slices.Contains(values, value) {
			values = append(values, value)
		}
	}
	slices.Sort(values)
	return values
}
