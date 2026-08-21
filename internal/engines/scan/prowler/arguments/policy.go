package arguments

import "fmt"

const (
	reasonArbitraryFile  = "arbitrary host files are not accepted"
	reasonExternalWrite  = "external writes and integrations are not accepted"
	reasonInteractive    = "interactive authentication is not available in recon runs"
	reasonListingControl = "discovery controls are handled by generated catalogues"
	reasonOutputContract = "this option changes the machine-readable output contract"
	reasonRemediation    = "remediation is outside read-only scan scope"
)

var commonPolicies = map[string]Policy{
	"status":                       profilePolicy(),
	"output_formats":               profilePolicy(),
	"output_filename":              runnerPolicy(true),
	"output_directory":             runnerPolicy(true),
	"verbose":                      profilePolicy(),
	"ignore_exit_code_3":           runnerPolicy(false),
	"no_banner":                    runnerPolicy(false),
	"no_color":                     runnerPolicy(false),
	"unix_timestamp":               forbiddenPolicy(reasonOutputContract, false),
	"push_to_cloud":                forbiddenPolicy(reasonExternalWrite, false),
	"log_level":                    profilePolicy(),
	"log_file":                     runnerPolicy(true),
	"only_logs":                    forbiddenPolicy(reasonOutputContract, false),
	"excluded_check":               profilePolicy(),
	"excluded_checks_file":         forbiddenPolicy(reasonArbitraryFile, true),
	"excluded_service":             profilePolicy(),
	"check":                        profilePolicy(),
	"checks_file":                  forbiddenPolicy(reasonArbitraryFile, true),
	"service":                      profilePolicy(),
	"severity":                     profilePolicy(),
	"compliance":                   profilePolicy(),
	"category":                     profilePolicy(),
	"resource_group":               profilePolicy(),
	"checks_folder":                forbiddenPolicy(reasonArbitraryFile, true),
	"list_checks":                  forbiddenPolicy(reasonListingControl, false),
	"list_checks_json":             forbiddenPolicy(reasonListingControl, false),
	"list_services":                forbiddenPolicy(reasonListingControl, false),
	"list_compliance":              forbiddenPolicy(reasonListingControl, false),
	"list_compliance_requirements": forbiddenPolicy(reasonListingControl, false),
	"list_categories":              forbiddenPolicy(reasonListingControl, false),
	"list_resource_groups":         forbiddenPolicy(reasonListingControl, false),
	"list_fixer":                   forbiddenPolicy(reasonListingControl, false),
	"mutelist_file":                forbiddenPolicy(reasonArbitraryFile, true),
	"config_file":                  forbiddenPolicy(reasonArbitraryFile, true),
	"fixer_config":                 forbiddenPolicy(reasonRemediation, true),
	"scan_secrets_validate":        forbiddenPolicy("secret validation can call external services", false),
	"custom_checks_metadata_file":  forbiddenPolicy(reasonArbitraryFile, true),
	"shodan":                       forbiddenSensitivePolicy(reasonExternalWrite),
	"slack":                        forbiddenPolicy(reasonExternalWrite, false),
}

func (c *Catalogue) ApplyPolicies() error {
	for i := range c.Common {
		policy, ok := commonPolicies[c.Common[i].Destination]
		if !ok {
			return fmt.Errorf("unknown common argument destination %q", c.Common[i].Destination)
		}
		c.Common[i].Policy = policy
	}
	for providerIndex := range c.Providers {
		provider := &c.Providers[providerIndex]
		policies, ok := providerPolicies[provider.Name]
		if !ok {
			return fmt.Errorf("unsupported Prowler provider %q", provider.Name)
		}
		for argumentIndex := range provider.Arguments {
			argument := &provider.Arguments[argumentIndex]
			policy, found := policies[argument.Destination]
			if !found {
				return fmt.Errorf("unknown %s argument destination %q", provider.Name, argument.Destination)
			}
			argument.Policy = policy
		}
	}
	return nil
}

func profilePolicy() Policy {
	return Policy{Owner: OwnerProfile}
}

func redactedProfilePolicy() Policy {
	return Policy{Owner: OwnerProfile, Redact: true}
}

func contextPolicy(redact bool) Policy {
	return Policy{Owner: OwnerContext, Redact: redact}
}

func credentialSelectorPolicy(redact bool) Policy {
	return Policy{Owner: OwnerContext, Redact: redact, CredentialSelector: true}
}

func credentialPolicy() Policy {
	return Policy{Owner: OwnerCredential, Sensitive: true, Redact: true}
}

func runnerPolicy(redact bool) Policy {
	return Policy{Owner: OwnerRunner, Redact: redact}
}

func forbiddenPolicy(reason string, redact bool) Policy {
	return Policy{Owner: OwnerForbidden, Redact: redact, Reason: reason}
}

func forbiddenSensitivePolicy(reason string) Policy {
	return Policy{Owner: OwnerForbidden, Sensitive: true, Redact: true, Reason: reason}
}
