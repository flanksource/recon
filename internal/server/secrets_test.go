package server_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"

	dbcontext "github.com/flanksource/commons-db/context"
	"github.com/flanksource/commons-db/dbtest"
	dutykubernetes "github.com/flanksource/commons-db/kubernetes"
	"github.com/flanksource/commons/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/flanksource/recon/internal/cli"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/server"
	"github.com/flanksource/recon/internal/store"
)

const catalogMask = "••••"

type stubOnePasswordCatalog struct{}

func (stubOnePasswordCatalog) Vaults(dbcontext.Context) ([]dbcontext.OnePasswordVault, error) {
	return []dbcontext.OnePasswordVault{{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "Production"}}, nil
}

func (stubOnePasswordCatalog) Items(_ dbcontext.Context, vault string) ([]dbcontext.OnePasswordItem, error) {
	Expect(vault).To(Equal("aaaaaaaaaaaaaaaaaaaaaaaaaa"))
	return []dbcontext.OnePasswordItem{{ID: "bbbbbbbbbbbbbbbbbbbbbbbbbb", Name: "Database"}}, nil
}

func (stubOnePasswordCatalog) Fields(_ dbcontext.Context, vault, item string) ([]dbcontext.OnePasswordField, error) {
	Expect(vault).To(Equal("aaaaaaaaaaaaaaaaaaaaaaaaaa"))
	Expect(item).To(Equal("bbbbbbbbbbbbbbbbbbbbbbbbbb"))
	return []dbcontext.OnePasswordField{{
		ID: "password", Label: "Password", Reference: "op://Production/Database/password",
	}}, nil
}

type secretCatalogResource struct {
	Name string   `json:"name"`
	Keys []string `json:"keys"`
}

type secretCatalogPreview struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func helmRelease(namespace, name, revision string, values map[string]any) *corev1.Secret {
	record, err := json.Marshal(map[string]any{
		"chart":  map[string]any{"values": map[string]any{}},
		"config": values,
	})
	Expect(err).ToNot(HaveOccurred())

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, err = writer.Write(record)
	Expect(err).ToNot(HaveOccurred())
	Expect(writer.Close()).To(Succeed())

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sh.helm.release.v1." + name + ".v" + revision, Namespace: namespace,
			Labels: map[string]string{"name": name, "status": "deployed", "version": revision},
		},
		Type: corev1.SecretType("helm.sh/release.v1"),
		Data: map[string][]byte{"release": []byte(base64.StdEncoding.EncodeToString(compressed.Bytes()))},
	}
}

var _ = Describe("secret metadata catalogs", Label("db"), func() {
	It("uses the server namespace and never returns secret or config values", func() {
		if testing.Short() {
			Skip("needs a database")
		}
		const namespace = "tenant-a"
		client := fake.NewSimpleClientset(
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "database", Namespace: namespace},
				Data:       map[string][]byte{"password": []byte("do-not-return-secret")},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "other-namespace", Namespace: "tenant-b"},
				Data:       map[string][]byte{"password": []byte("cross-namespace-secret")},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "application", Namespace: namespace},
				Data:       map[string]string{"endpoint": "do-not-return-config-value"},
			},
			helmRelease(namespace, "payments", "1", map[string]any{
				"apiKey": "do-not-return-helm-value", "replicas": 2,
			}),
			helmRelease(namespace, "payments", "2", map[string]any{
				"apiKey": "rotated-do-not-return-helm-value", "replicas": 3,
			}),
		)
		kube := dutykubernetes.NewKubeClient(
			logger.GetLogger("secret-catalog-test"), client, &rest.Config{Host: "https://cluster.example.test"})

		database := dbtest.ForGinkgo(dbtest.Options{
			Name: "recon_secret_catalog", Provisioner: schema.NewProvisioner(),
		})
		factory := func(ctx context.Context) dbcontext.Context {
			return dbcontext.NewContext(ctx).WithNamespace(namespace).WithLocalKubernetes(kube)
		}
		suite := httptest.NewServer(server.Handler(server.Config{
			Host: "localhost", Root: commandTree(), Registry: cli.EntityRegistry(),
			Store: store.New(database.Gorm()), Namespace: namespace, ContextFactory: factory,
			OnePassword: stubOnePasswordCatalog{},
		}))
		DeferCleanup(suite.Close)
		document := getJSON[map[string]any](suite.URL + "/api/openapi.json")
		paths, _ := document["paths"].(map[string]any)
		for _, path := range []string{
			"/api/v1/secrets", "/api/v1/secrets/preview",
			"/api/v1/secrets/onepassword/vaults",
			"/api/v1/secrets/onepassword/items",
			"/api/v1/secrets/onepassword/fields",
		} {
			methods, _ := paths[path].(map[string]any)
			Expect(methods).To(HaveKey("get"), path)
		}

		Expect(getJSON[[]secretCatalogResource](suite.URL + "/api/v1/secrets?kind=secret")).To(Equal(
			[]secretCatalogResource{{Name: "database", Keys: []string{"password"}}}))
		Expect(getJSON[[]secretCatalogResource](
			suite.URL + "/api/v1/secrets?kind=secret&namespace=tenant-b")).To(Equal(
			[]secretCatalogResource{{Name: "database", Keys: []string{"password"}}}))
		Expect(getJSON[[]secretCatalogResource](suite.URL + "/api/v1/secrets?kind=configmap")).To(Equal(
			[]secretCatalogResource{{Name: "application", Keys: []string{"endpoint"}}}))
		Expect(getJSON[[]secretCatalogResource](suite.URL + "/api/v1/secrets?kind=helm")).To(Equal(
			[]secretCatalogResource{{Name: "payments", Keys: []string{}}}))

		for _, path := range []string{
			"/api/v1/secrets/preview?kind=secret&name=database",
			"/api/v1/secrets/preview?kind=configmap&name=application",
			"/api/v1/secrets/preview?kind=helm&name=payments",
		} {
			preview := getJSON[[]secretCatalogPreview](suite.URL + path)
			Expect(preview).ToNot(BeEmpty(), path)
			for _, field := range preview {
				Expect(field.Value).To(Equal(catalogMask), path)
			}
		}

		for _, forbidden := range []string{
			"do-not-return-secret", "cross-namespace-secret",
			"do-not-return-config-value", "do-not-return-helm-value",
		} {
			for _, path := range []string{
				"/api/v1/secrets?kind=secret",
				"/api/v1/secrets?kind=configmap",
				"/api/v1/secrets?kind=helm",
				"/api/v1/secrets/preview?kind=secret&name=database",
				"/api/v1/secrets/preview?kind=configmap&name=application",
				"/api/v1/secrets/preview?kind=helm&name=payments",
			} {
				Expect(string(get(suite.URL+path))).ToNot(ContainSubstring(forbidden), path)
			}
		}
	})

	It("serves 1Password vault, item, and field metadata without Kubernetes access", func() {
		if testing.Short() {
			Skip("needs a database")
		}
		database := dbtest.ForGinkgo(dbtest.Options{
			Name: "recon_onepassword_catalog", Provisioner: schema.NewProvisioner(),
		})
		factory := func(ctx context.Context) dbcontext.Context {
			return dbcontext.NewContext(ctx).WithNamespace("tenant-a")
		}
		suite := httptest.NewServer(server.Handler(server.Config{
			Host: "localhost", Root: commandTree(), Registry: cli.EntityRegistry(),
			Store: store.New(database.Gorm()), Namespace: "tenant-a", ContextFactory: factory,
			OnePassword: stubOnePasswordCatalog{},
		}))
		DeferCleanup(suite.Close)

		Expect(getJSON[[]dbcontext.OnePasswordVault](
			suite.URL + "/api/v1/secrets/onepassword/vaults")).To(HaveLen(1))
		Expect(getJSON[[]dbcontext.OnePasswordItem](
			suite.URL + "/api/v1/secrets/onepassword/items?vault=aaaaaaaaaaaaaaaaaaaaaaaaaa")).To(HaveLen(1))
		fields := getJSON[[]dbcontext.OnePasswordField](
			suite.URL + "/api/v1/secrets/onepassword/fields?vault=aaaaaaaaaaaaaaaaaaaaaaaaaa&item=bbbbbbbbbbbbbbbbbbbbbbbbbb")
		Expect(fields).To(Equal([]dbcontext.OnePasswordField{{
			ID: "password", Label: "Password", Reference: "op://Production/Database/password",
		}}))
	})
})
