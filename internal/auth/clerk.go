// Package auth owns Clerk configuration and the HTTP boundary that binds one
// Recon deployment to one Clerk organization.
package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/clerk/clerk-sdk-go/v2"
	clerkhttp "github.com/clerk/clerk-sdk-go/v2/http"
	"github.com/clerk/clerk-sdk-go/v2/jwks"
)

const (
	EnvPublishableKey = "CLERK_PUBLISHABLE_KEY"
	EnvSecretKey      = "CLERK_SECRET_KEY"
	EnvOrganizationID = "CLERK_ORG_ID"
)

// Config identifies the Clerk instance and the only organization allowed to
// use this deployment. All three values are optional together for local use.
type Config struct {
	PublishableKey string
	SecretKey      string
	OrganizationID string
}

// FromEnvironment reads the Clerk settings without retaining the lookup
// function, which keeps command setup deterministic in tests.
func FromEnvironment(lookup func(string) (string, bool)) (Config, error) {
	config := Config{
		PublishableKey: environmentValue(lookup, EnvPublishableKey),
		SecretKey:      environmentValue(lookup, EnvSecretKey),
		OrganizationID: environmentValue(lookup, EnvOrganizationID),
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// Enabled reports whether this process has opted into Clerk authentication.
func (c Config) Enabled() bool {
	return c.PublishableKey != "" || c.SecretKey != "" || c.OrganizationID != ""
}

// Validate prevents a partially configured deployment from silently serving
// either an unusable login page or an unprotected API.
func (c Config) Validate() error {
	if !c.Enabled() {
		return nil
	}

	missing := make([]string, 0, 3)
	if c.PublishableKey == "" {
		missing = append(missing, EnvPublishableKey)
	}
	if c.SecretKey == "" {
		missing = append(missing, EnvSecretKey)
	}
	if c.OrganizationID == "" {
		missing = append(missing, EnvOrganizationID)
	}
	if len(missing) > 0 {
		return fmt.Errorf("incomplete Clerk configuration: missing %s", strings.Join(missing, ", "))
	}
	return nil
}

// ConfigHandler exposes only the public values the browser needs to initialize
// Clerk and activate this deployment's organization.
func ConfigHandler(config Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Enabled        bool   `json:"enabled"`
			PublishableKey string `json:"publishableKey,omitempty"`
			OrganizationID string `json:"organizationId,omitempty"`
		}{
			Enabled:        config.Enabled(),
			PublishableKey: config.PublishableKey,
			OrganizationID: config.OrganizationID,
		})
	})
}

// Protect verifies a Clerk session and requires its active organization to be
// the organization assigned to this deployment. Membership is the only access
// policy here; every accepted member has the same Recon capabilities.
func Protect(config Config, next http.Handler) http.Handler {
	clientConfig := &clerk.ClientConfig{}
	clientConfig.Key = clerk.String(config.SecretKey)

	verified := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := clerk.SessionClaimsFromContext(r.Context())
		if !ok || claims == nil || claims.Subject == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if claims.ActiveOrganizationID != config.OrganizationID {
			writeError(w, http.StatusForbidden, "active Clerk organization is not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})

	return clerkhttp.WithHeaderAuthorization(
		clerkhttp.AuthorizationJWTExtractor(sessionToken),
		clerkhttp.JWKSClient(jwks.NewClient(clientConfig)),
		clerkhttp.AuthorizationFailureHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusUnauthorized, "invalid Clerk session")
		})),
	)(verified)
}

func environmentValue(lookup func(string) (string, bool), name string) string {
	value, _ := lookup(name)
	return strings.TrimSpace(value)
}

func sessionToken(r *http.Request) string {
	if header := strings.TrimSpace(r.Header.Get("Authorization")); header != "" {
		parts := strings.Fields(header)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return parts[1]
		}
		return ""
	}
	if cookie, err := r.Cookie("__session"); err == nil {
		return cookie.Value
	}
	return ""
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
