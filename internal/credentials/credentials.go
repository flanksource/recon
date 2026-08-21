// Package credentials contains the unredacted provider credential form stored
// in the database and handed to an engine in memory. It must never be used as
// an API response type.
package credentials

import (
	"reflect"

	"github.com/flanksource/commons-db/connection"
	"github.com/flanksource/commons-db/types"
)

// ProviderCredentials is the persistence and runtime credential contract.
// EnvVars deliberately uses the commons-db type so runtime resolution has one
// representation for inline values and external references.
type ProviderCredentials struct {
	EnvVars     []types.EnvVar              `json:"envVars,omitempty"`
	Connections *connection.ExecConnections `json:"connections,omitempty"`
}

// Empty reports whether no credential source has been configured.
func (c ProviderCredentials) Empty() bool {
	return len(c.EnvVars) == 0 &&
		(c.Connections == nil || reflect.DeepEqual(*c.Connections, connection.ExecConnections{}))
}
