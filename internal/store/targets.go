package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/flanksource/recon/internal/api"
	credentialstore "github.com/flanksource/recon/internal/credentials"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/schema"
)

// targetOrder sorts stable IDs by byte value rather than the database's default
// collation, so lists are deterministic regardless of how the cluster was
// initialised.
const targetOrder = `id COLLATE "C" ASC`

// ListTargets returns the targets a selector matches, ordered by stable ID.
func (s *Store) ListTargets(ctx context.Context, opts TargetOpts) ([]api.TargetDocument, error) {
	query, err := opts.Scope(s.DB(ctx))
	if err != nil {
		return nil, err
	}

	var rows []models.Target
	if err := query.Order(targetOrder).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}

	documents := make([]api.TargetDocument, 0, len(rows))
	for _, row := range rows {
		document := row.Document()
		matches, err := opts.MatchesTags(document.Tags)
		if err != nil {
			return nil, err
		}
		if matches {
			documents = append(documents, document)
		}
	}
	return documents, nil
}

// GetTarget returns one target.
func (s *Store) GetTarget(ctx context.Context, id string) (api.TargetDocument, error) {
	var row models.Target
	err := s.DB(ctx).Where("id = ?", id).First(&row).Error
	if err != nil {
		if IsNotFound(err) {
			return api.TargetDocument{}, NotFound("target", id)
		}
		return api.TargetDocument{}, fmt.Errorf("get target %s: %w", id, err)
	}
	return row.Document(), nil
}

// SaveTarget writes a whole document, machine-owned sections included. This is
// the observation-merge path; user edits go through UpdateTarget.
func (s *Store) SaveTarget(ctx context.Context, document api.TargetDocument) error {
	document = normalizeTarget(document)
	if err := validate(document); err != nil {
		return err
	}
	if err := validateProviderContext(ctx, s.providerContextValidator, document); err != nil {
		return err
	}

	row := models.TargetFromDocument(document)
	err := s.DB(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"host", "kind", "provider", "credential_mode", "arguments", "credentials",
			"class", "app", "cluster", "source", "profiles", "ports", "tags",
			"notes", "reason", "observed", "network", "http", "tech", "tls",
			"scan", "updated_at",
		}),
	}).Create(&row).Error
	if err != nil {
		return fmt.Errorf("save target %s: %w", document.GetID(), err)
	}
	return nil
}

// CreateTarget adds a curated host or provider context to the inventory. An
// existing stable ID is refused rather than overwritten, because a create that
// silently replaced a curated record would discard someone's work.
func (s *Store) CreateTarget(ctx context.Context, target api.NewTarget) (api.TargetDocument, error) {
	target = normalizeNewTarget(target)
	id := target.ID
	document := normalizeTarget(api.TargetDocument{
		ID: id, Host: target.Host, Kind: target.Kind, Provider: target.Provider,
		CredentialMode: target.CredentialMode, Arguments: target.Arguments,
		Credentials: target.Credentials,
	})
	row := models.TargetFromDocument(document)
	row.ApplyCurated(target.Curated)

	document = row.Document()
	if err := validate(document); err != nil {
		return api.TargetDocument{}, err
	}
	if err := validateProfiles(s.DB(ctx), id, document.Profiles); err != nil {
		return api.TargetDocument{}, err
	}
	if err := validateProviderContext(ctx, s.providerContextValidator, document); err != nil {
		return api.TargetDocument{}, err
	}

	result := s.DB(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if result.Error != nil {
		return api.TargetDocument{}, fmt.Errorf("create target %s: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return api.TargetDocument{}, fmt.Errorf("target %s is already in the inventory", id)
	}
	return document, nil
}

// DeleteTarget removes a target from the inventory.
//
// Its history is deliberately left behind: no foreign key points at targets, so
// what a scan found stays in findings whether or not the host is still listed.
// Deleting the row does not unfind it.
//
// This is for a record that is wrong — a typo, a placeholder, a project that
// never existed. Retiring something real is a class, not a delete: `deactivated`
// keeps a host for subdomain-takeover coverage, and deleting a host discovery
// can still see only removes it until the next sweep puts it back.
func (s *Store) DeleteTarget(ctx context.Context, id string) error {
	result := s.DB(ctx).Where("id = ?", id).Delete(&models.Target{})
	if result.Error != nil {
		return fmt.Errorf("delete target %s: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return NotFound("target", id)
	}
	return nil
}

// EnsureDiscoveredTarget creates the conservative inventory record used for a
// newly observed identity, and returns an existing record unchanged.
func (s *Store) EnsureDiscoveredTarget(ctx context.Context, host string) (api.TargetDocument, error) {
	row := models.Target{ID: host, Host: stringRef(host)}
	row.ApplyCurated(api.Curated{
		Class: api.ClassUnclassified, Source: "discovery",
		Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
	})
	if err := validate(row.Document()); err != nil {
		return api.TargetDocument{}, err
	}
	if err := s.DB(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
		return api.TargetDocument{}, fmt.Errorf("ensure discovered target %s: %w", host, err)
	}
	return s.GetTarget(ctx, host)
}

// UpdateTarget atomically replaces curated fields and, for a provider context,
// any supplied credential mode and non-secret arguments. Stable identity fields
// remain fixed for the lifetime of the target.
func (s *Store) UpdateTarget(ctx context.Context, id string, update api.TargetUpdate) (api.TargetDocument, error) {
	var stored api.TargetDocument

	err := s.DB(ctx).Transaction(func(tx *gorm.DB) error {
		document, err := updateTarget(tx, id, update, s.providerContextValidator)
		if err != nil {
			return err
		}
		stored = document
		return nil
	})
	if err != nil {
		if IsNotFound(err) {
			return api.TargetDocument{}, err
		}
		return api.TargetDocument{}, fmt.Errorf("update target %s: %w", id, err)
	}
	return stored, nil
}

// updateTarget applies the edit to an existing row. Split out of UpdateTarget
// so an import can make the same edit inside the transaction it already holds:
// going back through the Store would use a second connection and drop the write
// out of the batch it is supposed to be part of.
func updateTarget(
	tx *gorm.DB,
	id string,
	update api.TargetUpdate,
	contextValidator ProviderContextValidator,
) (api.TargetDocument, error) {
	var row models.Target
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", id).First(&row).Error; err != nil {
		if IsNotFound(err) {
			return api.TargetDocument{}, NotFound("target", id)
		}
		return api.TargetDocument{}, err
	}

	if api.TargetKind(row.Kind) != api.KindProviderContext &&
		(update.CredentialMode != nil || update.Arguments != nil || update.CredentialsSet) {
		return api.TargetDocument{}, fmt.Errorf("host target %s cannot have provider configuration", id)
	}
	if update.CredentialMode != nil {
		row.CredentialMode = stringRef(string(*update.CredentialMode))
	}
	if update.Arguments != nil {
		arguments := *update.Arguments
		row.Arguments = models.JSON[map[string]any]{V: &arguments}
	}
	if update.CredentialsSet {
		existing := row.Credentials.V
		row.Credentials.V = nil
		if update.Credentials != nil && !update.Credentials.Empty() {
			credentials, err := mergeCredentialUpdate(existing, *update.Credentials)
			if err != nil {
				return api.TargetDocument{}, err
			}
			row.Credentials.V = &credentials
		}
	}

	row.ApplyCurated(update.Curated)
	document := row.Document()
	if err := validate(document); err != nil {
		return api.TargetDocument{}, err
	}
	if err := validateProfiles(tx, id, document.Profiles); err != nil {
		return api.TargetDocument{}, err
	}
	if err := validateProviderContext(tx.Statement.Context, contextValidator, document); err != nil {
		return api.TargetDocument{}, err
	}

	if err := tx.Model(&models.Target{}).Where("id = ?", id).Updates(map[string]any{
		"credential_mode": row.CredentialMode,
		"arguments":       row.Arguments,
		"credentials":     row.Credentials,
		"class":           row.Class,
		"app":             row.App,
		"cluster":         row.Cluster,
		"source":          row.Source,
		"profiles":        row.Profiles,
		"ports":           row.Ports,
		"tags":            row.Tags,
		"notes":           row.Notes,
		"reason":          row.Reason,
		"updated_at":      gorm.Expr("now()"),
	}).Error; err != nil {
		return api.TargetDocument{}, err
	}
	return document, nil
}

func mergeCredentialUpdate(
	existing *credentialstore.ProviderCredentials,
	incoming api.ProviderCredentials,
) (credentialstore.ProviderCredentials, error) {
	if err := incoming.ValidateWrite(); err != nil {
		return credentialstore.ProviderCredentials{}, err
	}
	result := incoming.Stored()
	for index, value := range incoming.EnvVars {
		if !value.Configured {
			continue
		}
		if existing == nil {
			return credentialstore.ProviderCredentials{}, fmt.Errorf(
				"credential %q configured marker has no stored value", value.Name)
		}
		found := false
		for _, stored := range existing.EnvVars {
			if stored.Name == value.Name && stored.ValueStatic != "" {
				result.EnvVars[index] = *stored.DeepCopy()
				found = true
				break
			}
		}
		if !found {
			return credentialstore.ProviderCredentials{}, fmt.Errorf(
				"credential %q configured marker has no stored inline value", value.Name)
		}
	}
	return result, nil
}

// ImportResult is what one import did, per outcome.
type ImportResult struct {
	// Created is the stable target IDs that were not in the inventory.
	Created []string `json:"created"`
	// Updated is the target IDs whose editable fields the import changed.
	Updated []string `json:"updated"`
	// Unchanged is the target IDs that already said exactly this. Reported rather
	// than folded into Updated so a re-import reads as the no-op it is.
	Unchanged []string `json:"unchanged"`
}

// ImportTargets applies a batch of curated definitions to the inventory.
//
// Curated fields plus provider-context configuration, deliberately. A target
// document also carries machine-owned observations, and importing those would
// assert that something saw a host answer when nothing did. A re-import is a
// no-op, so this is safe to run repeatedly.
//
// All or nothing: one transaction, so a file with a bad document halfway
// through leaves the inventory as it was rather than half-applied.
func (s *Store) ImportTargets(ctx context.Context, targets []api.NewTarget) (ImportResult, error) {
	var result ImportResult

	err := s.DB(ctx).Transaction(func(tx *gorm.DB) error {
		for _, target := range targets {
			target = normalizeNewTarget(target)
			outcome, err := importOne(tx, target, s.providerContextValidator)
			if err != nil {
				return err
			}
			switch outcome {
			case importCreated:
				result.Created = append(result.Created, target.ID)
			case importUpdated:
				result.Updated = append(result.Updated, target.ID)
			case importUnchanged:
				result.Unchanged = append(result.Unchanged, target.ID)
			}
		}
		return nil
	})
	if err != nil {
		return ImportResult{}, err
	}
	return result, nil
}

type importOutcome int

const (
	importCreated importOutcome = iota
	importUpdated
	importUnchanged
)

// importOne applies a single definition, creating the target or replacing its
// curated fields and mutable provider-context configuration.
//
// Profiles are validated on both branches. Discovery bypasses this path via
// EnsureDiscoveredTarget, while an import is a deliberate inventory statement.
func importOne(
	tx *gorm.DB,
	target api.NewTarget,
	contextValidator ProviderContextValidator,
) (importOutcome, error) {
	var row models.Target
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", target.ID).First(&row).Error

	switch {
	case err != nil && !IsNotFound(err):
		return 0, err

	case IsNotFound(err):
		fresh := models.TargetFromDocument(normalizeTarget(api.TargetDocument{
			ID: target.ID, Host: target.Host, Kind: target.Kind, Provider: target.Provider,
			CredentialMode: target.CredentialMode, Arguments: target.Arguments,
			Credentials: target.Credentials,
		}))
		fresh.ApplyCurated(target.Curated)
		document := fresh.Document()
		if err := validate(document); err != nil {
			return 0, err
		}
		if err := validateProfiles(tx, target.ID, document.Profiles); err != nil {
			return 0, err
		}
		if err := validateProviderContext(tx.Statement.Context, contextValidator, document); err != nil {
			return 0, err
		}
		if err := tx.Create(&fresh).Error; err != nil {
			return 0, fmt.Errorf("import target %s: %w", target.ID, err)
		}
		return importCreated, nil
	}

	// Kind is fixed when a target is created, for the same reason it is not
	// editable: changing it would repoint every future run at something else.
	// An import that disagrees is a mistake worth reporting, not applying.
	if kind := target.Kind.String(); kind != api.TargetKind(row.Kind).String() {
		return 0, fmt.Errorf(
			"import target %s: it is already a %s and cannot become a %s",
			target.ID, api.TargetKind(row.Kind).String(), kind)
	}
	if target.Provider != derefString(row.Provider) {
		return 0, fmt.Errorf("import target %s: provider is fixed when the target is created", target.ID)
	}

	before := row.Document()
	row.ApplyCurated(target.Curated)
	document := row.Document()
	contextChanged := target.Kind == api.KindProviderContext &&
		(target.CredentialMode != before.CredentialMode ||
			!sameArguments(target.Arguments, before.Arguments) ||
			(target.CredentialsSet && !sameCredentials(target.Credentials, before.Credentials)))
	if sameCuration(before, document) && !contextChanged {
		return importUnchanged, nil
	}

	update := api.TargetUpdate{Curated: target.Curated}
	if target.Kind == api.KindProviderContext {
		mode := target.CredentialMode
		arguments := target.Arguments
		update.CredentialMode = &mode
		update.Arguments = &arguments
		if target.CredentialsSet {
			update.Credentials = target.Credentials
			update.CredentialsSet = true
		}
	}
	if _, err := updateTarget(tx, target.ID, update, contextValidator); err != nil {
		return 0, err
	}
	return importUpdated, nil
}

// sameCuration compares only what an import can write, so an observation
// recorded since the last import does not make a document look changed.
func sameCuration(before, after api.TargetDocument) bool {
	encode := func(document api.TargetDocument) string {
		encoded, _ := json.Marshal(api.Curated{
			Class: document.Class, App: document.App, Cluster: document.Cluster,
			Source: document.Source, Profiles: document.Profiles,
			Ports: document.Ports, Tags: document.Tags,
			Notes: document.Notes, Reason: document.Reason,
		})
		return string(encoded)
	}
	return encode(before) == encode(after)
}

// CountTargets is the import verification's cheap check.
func (s *Store) CountTargets(ctx context.Context) (int64, error) {
	var count int64
	if err := s.DB(ctx).Model(&models.Target{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count targets: %w", err)
	}
	return count, nil
}

// TagVocabulary is every distinct tag in use, sorted. The UI offers it for
// filtering and bulk edits.
func (s *Store) TagVocabulary(ctx context.Context) ([]string, error) {
	return s.Vocabulary(ctx, TargetTags)
}

// Inventory assembles the listing the UI loads on start.
func (s *Store) Inventory(ctx context.Context) (api.Inventory, error) {
	rows, err := s.ListTargets(ctx, TargetOpts{})
	if err != nil {
		return api.Inventory{}, err
	}
	zones, err := s.ListZones(ctx)
	if err != nil {
		return api.Inventory{}, err
	}
	tags, err := s.TagVocabulary(ctx)
	if err != nil {
		return api.Inventory{}, err
	}
	return api.Inventory{
		Version:       api.TargetVersion,
		Zones:         zones,
		Rows:          rows,
		TagVocabulary: tags,
	}, nil
}

// validate runs the document through the JSON Schema before it reaches the
// database. The CHECK constraints are the backstop; this is what produces an
// error a human can act on, naming the offending field.
func validate(document api.TargetDocument) error {
	document = normalizeTarget(document)
	if document.Credentials != nil {
		if err := document.Credentials.ValidateWrite(); err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode target %s: %w", document.GetID(), err)
	}
	return schema.ValidateTargetJSON(document.GetID()+".json", encoded)
}

// ---------------------------------------------------------------------- zones

// ListZones returns the configured DNS zones, sorted.
func (s *Store) ListZones(ctx context.Context) ([]string, error) {
	var rows []models.Zone
	if err := s.DB(ctx).Order(`zone COLLATE "C" ASC`).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	zones := make([]string, 0, len(rows))
	for _, row := range rows {
		zones = append(zones, row.Zone)
	}
	return zones, nil
}

// ReplaceZones sets the zone list, removing any not named.
func (s *Store) ReplaceZones(ctx context.Context, zones []string) error {
	sorted := append([]string(nil), zones...)
	sort.Strings(sorted)

	return s.DB(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1 = 1").Delete(&models.Zone{}).Error; err != nil {
			return fmt.Errorf("clear zones: %w", err)
		}
		if len(sorted) == 0 {
			return nil
		}
		rows := make([]models.Zone, 0, len(sorted))
		for _, zone := range sorted {
			rows = append(rows, models.Zone{Zone: zone})
		}
		if err := tx.Create(&rows).Error; err != nil {
			return fmt.Errorf("insert zones: %w", err)
		}
		return nil
	})
}
