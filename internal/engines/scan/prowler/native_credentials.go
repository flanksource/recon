package prowler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/flanksource/commons-db/connection"
	dbcontext "github.com/flanksource/commons-db/context"
	"github.com/flanksource/commons-db/types"

	"github.com/flanksource/recon/internal/engines/scan/prowler/auth"
)

type preparedCredentials struct {
	EnvVars   []types.EnvVar
	Sensitive []string
	Cleanup   func() error
	Native    bool
}

func prepareNativeCredentials(ctx dbcontext.Context, subject providerContext, workDir string) (preparedCredentials, error) {
	if subject.CredentialMode != "configured" || subject.Credentials == nil || subject.Credentials.Connections == nil {
		return preparedCredentials{}, nil
	}
	raw, err := credentialMap(subject.Credentials)
	if err != nil {
		return preparedCredentials{}, err
	}
	method, err := auth.Match(subject.Provider, subject.Arguments, raw)
	if err != nil {
		return preparedCredentials{}, err
	}
	if method.Connection == nil {
		return preparedCredentials{}, nil
	}

	connections := subject.Credentials.Connections.DeepCopy()
	switch method.Connection.Key {
	case "aws":
		return prepareAWSCredentials(ctx, connections.AWS, workDir)
	case "azure":
		return prepareAzureCredentials(ctx, connections.Azure)
	case "gcp":
		return prepareGCPCredentials(ctx, connections.GCP, workDir)
	default:
		return preparedCredentials{}, fmt.Errorf("unsupported Prowler native connection %q", method.Connection.Key)
	}
}

func prepareAWSCredentials(ctx dbcontext.Context, value *connection.AWSConnection, workDir string) (preparedCredentials, error) {
	if value == nil {
		return preparedCredentials{}, fmt.Errorf("AWS authentication requires connections.aws")
	}
	if err := value.Populate(ctx); err != nil {
		return preparedCredentials{}, fmt.Errorf("hydrate AWS connection: %w", err)
	}
	accessKey, secretKey := value.AccessKey.ValueStatic, value.SecretKey.ValueStatic
	if accessKey == "" || secretKey == "" {
		return preparedCredentials{}, fmt.Errorf("AWS connection requires access key and secret key")
	}
	content := "[default]\naws_access_key_id = " + accessKey + "\naws_secret_access_key = " + secretKey + "\n"
	if value.SessionToken.ValueStatic != "" {
		content += "aws_session_token = " + value.SessionToken.ValueStatic + "\n"
	}
	path, cleanup, err := writeCredentialFile(workDir, "aws", "credentials", []byte(content))
	if err != nil {
		return preparedCredentials{}, err
	}
	env := []types.EnvVar{
		{Name: "AWS_ACCESS_KEY_ID", ValueStatic: accessKey},
		{Name: "AWS_SECRET_ACCESS_KEY", ValueStatic: secretKey},
		{Name: "AWS_SHARED_CREDENTIALS_FILE", ValueStatic: path},
		{Name: "AWS_EC2_METADATA_DISABLED", ValueStatic: "true"},
	}
	if value.SessionToken.ValueStatic != "" {
		env = append(env, types.EnvVar{Name: "AWS_SESSION_TOKEN", ValueStatic: value.SessionToken.ValueStatic})
	}
	if value.Region != "" {
		env = append(env, types.EnvVar{Name: "AWS_DEFAULT_REGION", ValueStatic: value.Region})
	}
	return preparedCredentials{
		EnvVars: env, Sensitive: []string{accessKey, secretKey, value.SessionToken.ValueStatic, content}, Cleanup: cleanup, Native: true,
	}, nil
}

func prepareAzureCredentials(ctx dbcontext.Context, value *connection.AzureConnection) (preparedCredentials, error) {
	if value == nil {
		return preparedCredentials{}, fmt.Errorf("azure authentication requires connections.azure")
	}
	if err := value.HydrateConnection(ctx); err != nil {
		return preparedCredentials{}, fmt.Errorf("hydrate Azure connection: %w", err)
	}
	if value.ClientID == nil || value.ClientSecret == nil || value.ClientID.ValueStatic == "" || value.ClientSecret.ValueStatic == "" || value.TenantID == "" {
		return preparedCredentials{}, fmt.Errorf("azure connection requires client ID, client secret, and tenant ID")
	}
	env := []types.EnvVar{
		{Name: "AZURE_CLIENT_ID", ValueStatic: value.ClientID.ValueStatic},
		{Name: "AZURE_CLIENT_SECRET", ValueStatic: value.ClientSecret.ValueStatic},
		{Name: "AZURE_TENANT_ID", ValueStatic: value.TenantID},
	}
	return preparedCredentials{
		EnvVars: env, Sensitive: []string{value.ClientID.ValueStatic, value.ClientSecret.ValueStatic, value.TenantID},
		Cleanup: func() error { return nil }, Native: true,
	}, nil
}

func prepareGCPCredentials(ctx dbcontext.Context, value *connection.GCPConnection, workDir string) (preparedCredentials, error) {
	if value == nil {
		return preparedCredentials{}, fmt.Errorf("GCP authentication requires connections.gcp")
	}
	if err := value.HydrateConnection(ctx); err != nil {
		return preparedCredentials{}, fmt.Errorf("hydrate GCP connection: %w", err)
	}
	if value.Credentials == nil || value.Credentials.ValueStatic == "" {
		return preparedCredentials{}, fmt.Errorf("GCP connection requires service-account credentials")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(value.Credentials.ValueStatic)); err != nil {
		return preparedCredentials{}, fmt.Errorf("GCP connection credentials must be valid JSON: %w", err)
	}
	sensitive := []string{value.Credentials.ValueStatic, compact.String()}
	var document any
	if err := json.Unmarshal(compact.Bytes(), &document); err != nil {
		return preparedCredentials{}, fmt.Errorf("decode GCP connection credentials: %w", err)
	}
	sensitive = append(sensitive, jsonStringValues(document)...)
	path, cleanup, err := writeCredentialFile(workDir, "gcp", "service-account.json", compact.Bytes())
	if err != nil {
		return preparedCredentials{}, err
	}
	return preparedCredentials{
		EnvVars:   []types.EnvVar{{Name: "GOOGLE_APPLICATION_CREDENTIALS", ValueStatic: path}},
		Sensitive: sensitive, Cleanup: cleanup, Native: true,
	}, nil
}

func jsonStringValues(value any) []string {
	result := []string{}
	var collect func(any)
	collect = func(current any) {
		switch item := current.(type) {
		case map[string]any:
			for _, child := range item {
				collect(child)
			}
		case []any:
			for _, child := range item {
				collect(child)
			}
		case string:
			if item != "" {
				result = append(result, item)
			}
		}
	}
	collect(value)
	return result
}

func writeCredentialFile(workDir, provider, name string, content []byte) (string, func() error, error) {
	dir := filepath.Join(workDir, ".credentials", provider)
	cleanup := func() error { return os.RemoveAll(dir) }
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", cleanup, fmt.Errorf("create %s credential directory: %w", provider, err)
	}
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", cleanup, errors.Join(fmt.Errorf("create %s credential file: %w", provider, err), cleanup())
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return "", cleanup, errors.Join(fmt.Errorf("write %s credential file: %w", provider, err), cleanup())
	}
	if err := file.Close(); err != nil {
		return "", cleanup, errors.Join(fmt.Errorf("close %s credential file: %w", provider, err), cleanup())
	}
	return path, cleanup, nil
}
