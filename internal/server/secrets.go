package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	dbcontext "github.com/flanksource/commons-db/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/flanksource/recon/internal/runtimecontext"
)

const (
	helmReleaseSecretType = "helm.sh/release.v1"
	secretPreviewMask     = "••••"
)

// OnePasswordCatalog lists safe 1Password metadata. Implementations must never
// return field values; the public commons-db implementation returns references.
type OnePasswordCatalog interface {
	Vaults(dbcontext.Context) ([]dbcontext.OnePasswordVault, error)
	Items(dbcontext.Context, string) ([]dbcontext.OnePasswordItem, error)
	Fields(dbcontext.Context, string, string) ([]dbcontext.OnePasswordField, error)
}

type contextOnePasswordCatalog struct{}

func (contextOnePasswordCatalog) Vaults(ctx dbcontext.Context) ([]dbcontext.OnePasswordVault, error) {
	return dbcontext.ListOnePasswordVaults(ctx)
}

func (contextOnePasswordCatalog) Items(ctx dbcontext.Context, vault string) ([]dbcontext.OnePasswordItem, error) {
	return dbcontext.ListOnePasswordItems(ctx, vault)
}

func (contextOnePasswordCatalog) Fields(
	ctx dbcontext.Context,
	vault string,
	item string,
) ([]dbcontext.OnePasswordField, error) {
	return dbcontext.ListOnePasswordFields(ctx, vault, item)
}

type secretCatalogOptions struct {
	Context     runtimecontext.Factory
	OnePassword OnePasswordCatalog
}

type secretResource struct {
	Name string   `json:"name"`
	Keys []string `json:"keys"`
}

type secretPreview struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func registerSecretCatalogs(mux *http.ServeMux, options secretCatalogOptions) {
	onePassword := options.OnePassword
	if onePassword == nil {
		onePassword = contextOnePasswordCatalog{}
	}

	mux.HandleFunc("GET /api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		ctx := options.Context(r.Context())
		client, err := ctx.LocalKubernetes()
		if err != nil {
			writeCatalogError(w, http.StatusServiceUnavailable, "kubernetes catalog unavailable", err)
			return
		}
		resources, err := listSecretResources(
			r.Context(), client, r.URL.Query().Get("kind"), ctx.GetNamespace())
		if err != nil {
			writeCatalogError(w, http.StatusInternalServerError, "list secret metadata", err)
			return
		}
		writeCatalogJSON(w, resources)
	})

	mux.HandleFunc("GET /api/v1/secrets/preview", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		ctx := options.Context(r.Context())
		client, err := ctx.LocalKubernetes()
		if err != nil {
			writeCatalogError(w, http.StatusServiceUnavailable, "kubernetes catalog unavailable", err)
			return
		}
		preview, err := previewSecretMetadata(
			ctx, client, r.URL.Query().Get("kind"), ctx.GetNamespace(), name)
		if err != nil {
			writeCatalogError(w, http.StatusInternalServerError, "preview secret metadata", err)
			return
		}
		writeCatalogJSON(w, preview)
	})

	mux.HandleFunc("GET /api/v1/secrets/onepassword/vaults", func(w http.ResponseWriter, r *http.Request) {
		payload, err := onePassword.Vaults(options.Context(r.Context()))
		writeOnePasswordCatalog(w, payload, err)
	})
	mux.HandleFunc("GET /api/v1/secrets/onepassword/items", func(w http.ResponseWriter, r *http.Request) {
		vault := strings.TrimSpace(r.URL.Query().Get("vault"))
		if vault == "" {
			http.Error(w, "vault is required", http.StatusBadRequest)
			return
		}
		payload, err := onePassword.Items(options.Context(r.Context()), vault)
		writeOnePasswordCatalog(w, payload, err)
	})
	mux.HandleFunc("GET /api/v1/secrets/onepassword/fields", func(w http.ResponseWriter, r *http.Request) {
		vault := strings.TrimSpace(r.URL.Query().Get("vault"))
		item := strings.TrimSpace(r.URL.Query().Get("item"))
		if vault == "" || item == "" {
			http.Error(w, "vault and item are required", http.StatusBadRequest)
			return
		}
		payload, err := onePassword.Fields(options.Context(r.Context()), vault, item)
		writeOnePasswordCatalog(w, payload, err)
	})
}

func listSecretResources(
	ctx context.Context,
	client kubernetes.Interface,
	kind string,
	namespace string,
) ([]secretResource, error) {
	resources := []secretResource{}
	switch kind {
	case "", "secret":
		list, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list secrets in %q: %w", namespace, err)
		}
		for _, secret := range list.Items {
			if secret.Type == helmReleaseSecretType {
				continue
			}
			resources = append(resources, secretResource{Name: secret.Name, Keys: sortedByteKeys(secret.Data)})
		}
	case "configmap":
		list, err := client.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list configmaps in %q: %w", namespace, err)
		}
		for _, configMap := range list.Items {
			keys := make([]string, 0, len(configMap.Data)+len(configMap.BinaryData))
			for key := range configMap.Data {
				keys = append(keys, key)
			}
			for key := range configMap.BinaryData {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			resources = append(resources, secretResource{Name: configMap.Name, Keys: keys})
		}
	case "helm":
		list, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
			FieldSelector: "type=" + helmReleaseSecretType, LabelSelector: "status=deployed",
		})
		if err != nil {
			return nil, fmt.Errorf("list helm releases in %q: %w", namespace, err)
		}
		seen := map[string]bool{}
		for _, release := range list.Items {
			name := release.Labels["name"]
			if release.Type != helmReleaseSecretType || release.Labels["status"] != "deployed" || name == "" || seen[name] {
				continue
			}
			seen[name] = true
			resources = append(resources, secretResource{Name: name, Keys: []string{}})
		}
	default:
		return nil, fmt.Errorf("unsupported secret kind %q", kind)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].Name < resources[j].Name })
	return resources, nil
}

func previewSecretMetadata(
	ctx dbcontext.Context,
	client kubernetes.Interface,
	kind string,
	namespace string,
	name string,
) ([]secretPreview, error) {
	var keys []string
	switch kind {
	case "", "secret":
		secret, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get secret %s/%s: %w", namespace, name, err)
		}
		keys = sortedByteKeys(secret.Data)
	case "configmap":
		configMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get configmap %s/%s: %w", namespace, name, err)
		}
		for key := range configMap.Data {
			keys = append(keys, key)
		}
		for key := range configMap.BinaryData {
			keys = append(keys, key)
		}
		sort.Strings(keys)
	case "helm":
		values, err := dbcontext.GetHelmValuesFromCache(ctx, namespace, name)
		if err != nil {
			return nil, err
		}
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
	default:
		return nil, fmt.Errorf("unsupported secret kind %q", kind)
	}

	preview := make([]secretPreview, len(keys))
	for i, key := range keys {
		preview[i] = secretPreview{Key: key, Value: secretPreviewMask}
	}
	return preview, nil
}

func sortedByteKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func writeOnePasswordCatalog(w http.ResponseWriter, payload any, err error) {
	if err != nil {
		writeCatalogError(w, http.StatusServiceUnavailable, "1password catalog unavailable", err)
		return
	}
	writeCatalogJSON(w, payload)
}

func writeCatalogError(w http.ResponseWriter, status int, message string, err error) {
	http.Error(w, fmt.Sprintf("%s: %v", message, err), status)
}

func writeCatalogJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		panic(fmt.Sprintf("encode secret catalog metadata: %v", err))
	}
}
