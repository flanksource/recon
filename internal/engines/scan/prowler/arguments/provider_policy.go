package arguments

var providerPolicies = map[string]map[string]Policy{
	"alibabacloud": {
		"role_arn": credentialSelectorPolicy(false), "role_session_name": contextPolicy(false),
		"ecs_ram_role": credentialSelectorPolicy(false), "oidc_role_arn": credentialSelectorPolicy(false),
		"credentials_uri": credentialSelectorPolicy(true), "regions": contextPolicy(false),
	},
	"aws": {
		"profile": credentialSelectorPolicy(false), "role": credentialSelectorPolicy(false),
		"role_session_name": contextPolicy(false), "mfa": forbiddenPolicy(reasonInteractive, false),
		"session_duration": contextPolicy(false), "external_id": credentialPolicy(),
		"region": contextPolicy(false), "excluded_region": contextPolicy(false),
		"organizations_role":      contextPolicy(false),
		"security_hub":            forbiddenPolicy(reasonExternalWrite, false),
		"skip_sh_update":          forbiddenPolicy(reasonExternalWrite, false),
		"send_sh_only_fails":      forbiddenPolicy(reasonExternalWrite, false),
		"quick_inventory":         forbiddenPolicy(reasonOutputContract, false),
		"output_bucket":           forbiddenPolicy(reasonExternalWrite, false),
		"output_bucket_no_assume": forbiddenPolicy(reasonExternalWrite, false),
		"resource_tag":            profilePolicy(), "resource_arn": profilePolicy(),
		"aws_retries_max_attempts": profilePolicy(), "scan_unused_services": profilePolicy(),
		"fixer": forbiddenPolicy(reasonRemediation, false),
	},
	"azure": {
		"az_cli_auth": credentialSelectorPolicy(false), "sp_env_auth": credentialSelectorPolicy(false),
		"managed_identity_auth": credentialSelectorPolicy(false), "browser_auth": forbiddenPolicy(reasonInteractive, false),
		"subscription_id": contextPolicy(false), "tenant_id": contextPolicy(false),
		"azure_region": contextPolicy(false), "resource_groups": contextPolicy(false),
	},
	"cloudflare": {
		"account_id": contextPolicy(false), "region": contextPolicy(false),
	},
	"e2enetworks": {
		"e2e_networks_api_key": credentialPolicy(), "e2e_networks_auth_token": credentialPolicy(),
		"e2e_networks_project_id": contextPolicy(false), "region": contextPolicy(false),
	},
	"gcp": {
		"credentials_file": credentialSelectorPolicy(true), "impersonate_service_account": credentialSelectorPolicy(false),
		"organization_id": contextPolicy(false), "project_id": contextPolicy(false),
		"excluded_project_id": contextPolicy(false), "list_project_id": forbiddenPolicy(reasonListingControl, false),
		"gcp_retries_max_attempts": profilePolicy(), "skip_api_check": profilePolicy(),
	},
	"github": {
		"personal_access_token": credentialPolicy(), "oauth_app_token": credentialPolicy(),
		"github_app_id": credentialSelectorPolicy(false), "github_app_key": credentialSelectorPolicy(true),
		"repository": contextPolicy(false), "repo_list_file": forbiddenPolicy(reasonArbitraryFile, true),
		"organization": contextPolicy(false), "no_github_actions": profilePolicy(),
		"exclude_workflows": profilePolicy(),
	},
	"googleworkspace": {},
	"huaweicloud": {
		"regions": contextPolicy(false), "cloud": contextPolicy(false),
	},
	"iac": {
		"scan_path": contextPolicy(true), "scan_repository_url": contextPolicy(true),
		"scanners": profilePolicy(), "exclude_path": redactedProfilePolicy(),
		"github_username": credentialSelectorPolicy(false), "personal_access_token": credentialPolicy(),
		"oauth_app_token": credentialPolicy(), "provider_uid": forbiddenPolicy(reasonExternalWrite, false),
	},
	"image": {
		"images": contextPolicy(false), "image_list_file": forbiddenPolicy(reasonArbitraryFile, true),
		"scanners": profilePolicy(), "image_config_scanners": profilePolicy(),
		"trivy_severity": profilePolicy(), "ignore_unfixed": profilePolicy(), "timeout": profilePolicy(),
		"registry": contextPolicy(false), "registry_insecure": forbiddenPolicy("insecure registry transport is not accepted", false),
		"image_filter": profilePolicy(), "tag_filter": profilePolicy(), "max_images": profilePolicy(),
		"registry_list_images": forbiddenPolicy(reasonListingControl, false),
	},
	"kubernetes": {
		"kubeconfig_file": credentialSelectorPolicy(true), "context": credentialSelectorPolicy(false),
		"namespace": contextPolicy(false), "cluster_name": contextPolicy(false),
	},
	"linode": {"region": contextPolicy(false)},
	"llm":    {"max_concurrency": profilePolicy()},
	"m365": {
		"az_cli_auth": credentialSelectorPolicy(false), "sp_env_auth": credentialSelectorPolicy(false),
		"certificate_auth": credentialSelectorPolicy(false), "browser_auth": forbiddenPolicy(reasonInteractive, false),
		"certificate_path": credentialSelectorPolicy(true), "tenant_id": contextPolicy(false),
		"init_modules": forbiddenPolicy(reasonOutputContract, false), "region": contextPolicy(false),
	},
	"mongodbatlas": {
		"atlas_public_key": credentialSelectorPolicy(true), "atlas_private_key": credentialPolicy(),
		"atlas_project_id": contextPolicy(false),
	},
	"nhn": {
		"nhn_username": credentialSelectorPolicy(false), "nhn_password": credentialPolicy(), "nhn_tenant_id": contextPolicy(false),
	},
	"okta": {
		"okta_org_domain": credentialSelectorPolicy(false), "okta_client_id": credentialSelectorPolicy(false), "okta_scopes": profilePolicy(),
		"okta_retries_max_attempts": profilePolicy(), "okta_requests_per_second": profilePolicy(),
	},
	"openstack": {
		"clouds_yaml_file": credentialSelectorPolicy(true), "clouds_yaml_cloud": credentialSelectorPolicy(false),
		"os_auth_url": credentialSelectorPolicy(false), "os_username": credentialSelectorPolicy(false),
		"os_password": credentialPolicy(), "os_project_id": contextPolicy(false),
		"os_project_domain_name": contextPolicy(false), "os_user_domain_name": contextPolicy(false),
		"os_region_name": contextPolicy(false), "os_identity_api_version": contextPolicy(false),
	},
	"oraclecloud": {
		"oci_config_file": credentialSelectorPolicy(true), "profile": credentialSelectorPolicy(false),
		"use_instance_principal": credentialSelectorPolicy(false), "region": contextPolicy(false),
		"compartment_id": contextPolicy(false),
	},
	"scaleway": {
		"organization_id": contextPolicy(false), "project_id": contextPolicy(false), "region": contextPolicy(false),
	},
	"stackit": {
		"stackit_project_id": contextPolicy(false), "stackit_service_account_key_path": credentialSelectorPolicy(true),
		"stackit_service_account_key": credentialPolicy(), "stackit_region": contextPolicy(false),
		"scan_unused_services": profilePolicy(),
	},
	"vercel": {"project": contextPolicy(false)},
}
