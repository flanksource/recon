// Package nuclei drives the ProjectDiscovery template scanner.
//
// Nuclei is linked in rather than spawned. That is what makes a profile
// answerable before it runs: the same template loader the scan uses can be
// asked which templates a configuration selects, without a subprocess and
// without a target.
package nuclei

import (
	"fmt"
	"strings"

	nucleiconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
)

// Engine is the nuclei scanner.
type Engine struct{}

var _ scan.Engine = Engine{}

func init() { scan.Register(Engine{}) }

// excludedTags never run, whatever a profile says. Denial-of-service, fuzzing,
// brute-force and intrusive templates are not something a profile should be able
// to switch on by accident against production.
var excludedTags = []string{"dos", "fuzz", "bruteforce", "intrusive"}

// Spec describes nuclei.
func (Engine) Spec() engines.Spec {
	return engines.Spec{
		Name:        "nuclei",
		Title:       "Nuclei",
		Description: "Template-driven vulnerability scanner.",
		DocsURL:     "https://github.com/projectdiscovery/nuclei",

		// Linked in, so there is no binary to provision and the version is
		// whatever recon was compiled against rather than a constraint to
		// resolve. What still has to be present is the template corpus.
		InProcess:       true,
		Version:         nucleiconfig.Version,
		Sections:        catalog,
		ValidateOptions: validateConfig,
		Defaults: engines.DefaultProfile{
			Name: "safe",
			Comment: "Non-intrusive baseline, safe to run against production.\n" +
				"No fuzzing, no DAST, no brute force. Rate limited so a scan cannot\n" +
				"become an outage.",
			Config: map[string]any{
				"severity":       []any{"low", "medium", "high", "critical"},
				"rate-limit":     50,
				"bulk-size":      25,
				"concurrency":    25,
				"timeout":        10,
				"retries":        1,
				"max-host-error": 30,
			},
		},
		Profiles: append([]engines.DefaultProfile{{
			Name: "full",
			Comment: "Intrusive assessment with DAST fuzzing and active payloads.\n" +
				"Requires explicit authorisation for production, public and unclassified targets.",
			Config: map[string]any{
				"templates":           []any{"dast/"},
				"severity":            []any{"info", "low", "medium", "high", "critical"},
				"type":                []any{"dns", "ssl", "tcp", "http", "javascript"},
				"dast":                true,
				"fuzzing-type":        "replace",
				"payload-concurrency": 25,
				"rate-limit":          150,
				"bulk-size":           25,
				"concurrency":         25,
				"timeout":             10,
				"retries":             1,
				"max-redirects":       5,
			},
		}}, allProfiles()...),
	}
}

// allProfiles are every profile beyond `safe` and `full`: the focused ones
// written here, then nuclei's own, imported from the templates release.
func allProfiles() []engines.DefaultProfile {
	return append(focusedProfiles(), communityProfiles...)
}

// safeLimits are the rate limits every non-intrusive profile inherits from
// `safe`. A focused profile narrows which templates run; it is not licence to
// hit a host harder.
func safeLimits() map[string]any {
	return map[string]any{
		"rate-limit":     50,
		"bulk-size":      25,
		"concurrency":    25,
		"timeout":        10,
		"retries":        1,
		"max-host-error": 30,
	}
}

// focused builds a profile from safe's limits plus its own selection.
func focused(name, comment string, selection map[string]any) engines.DefaultProfile {
	config := safeLimits()
	for key, value := range selection {
		config[key] = value
	}
	return engines.DefaultProfile{Name: name, Comment: comment, Config: config}
}

// focusedProfiles are the narrow profiles.
//
// `safe` and `full` are the two ends of a spectrum with nothing in between: one
// runs every non-intrusive template at every severity, the other sends attack
// payloads. Faced with only those, someone scanning a static site behind a CDN
// reaches for `full`. These name the common cases instead, so the answer to
// "which templates apply to this host" is a choice rather than a guess.
//
// Each is anchored on tags the template corpus actually uses — the counts in
// the comments are what they select against the release this was written for,
// and the preview reports the real number for whatever is installed.
func focusedProfiles() []engines.DefaultProfile {
	return []engines.DefaultProfile{
		focused("static",
			"Static sites and anything behind a CDN: TLS, security headers, cookies,\n"+
				"CORS, redirects, subdomain takeover and exposed buckets. No application\n"+
				"logic is exercised, so there is nothing here a cache can break.",
			map[string]any{
				"tags": []any{
					"headers", "cookie", "cors", "clickjacking", "redirect",
					"ssl", "tls", "takeover", "cdn", "bucket", "s3",
				},
			}),

		focused("dns",
			"DNS records only: SPF, DMARC, DNSSEC, zone transfers and dangling\n"+
				"records. Sends no HTTP at all, so it is safe against a host that\n"+
				"resolves but should not be reachable.",
			map[string]any{"type": []any{"dns"}}),

		focused("java",
			"Java stacks: Spring and Spring Boot, Tomcat, JBoss, Jetty, Struts,\n"+
				"Log4j and deserialization. Actuator and console exposure included.",
			map[string]any{
				"tags": []any{
					"java", "spring", "springboot", "tomcat", "jboss",
					"jetty", "log4j", "deserialization", "struts",
				},
			}),

		focused("go",
			"Go services and the infrastructure they usually ship with: Prometheus,\n"+
				"Grafana, Consul, Vault, etcd, Traefik and MinIO. Mostly exposed\n"+
				"dashboards and unauthenticated metrics endpoints.",
			map[string]any{
				"tags": []any{
					"go", "golang", "grafana", "prometheus", "consul",
					"vault", "etcd", "traefik", "minio",
				},
			}),

		focused("k8s",
			"Kubernetes and what surrounds it: exposed API servers and kubelets,\n"+
				"etcd, Argo CD, Rancher, Istio and open container registries.",
			map[string]any{
				"tags": []any{
					"k8s", "kubernetes", "kubelet", "etcd", "helm",
					"argocd", "docker", "registry", "rancher", "istio",
				},
			}),

		focused("public",
			"What matters most on an internet-facing host: known-exploited\n"+
				"vulnerabilities, subdomain takeover, exposures and unauthenticated\n"+
				"access, at critical and high severity only. The first scan to run on\n"+
				"something newly exposed.",
			map[string]any{
				"tags":     []any{"kev", "takeover", "exposure", "unauth"},
				"severity": []any{"critical", "high"},
			}),

		focused("app",
			"Web applications: admin panels, login pages, default credentials,\n"+
				"unauthenticated endpoints, exposed APIs and GraphQL. Broad, and the\n"+
				"slowest of these — narrow it by severity for a large estate.",
			map[string]any{
				"tags": []any{
					"panel", "login", "default-login", "unauth",
					"exposure", "api", "graphql", "auth-bypass",
				},
			}),
	}
}

func validateConfig(config map[string]any) error {
	automatic, _ := config["automatic-scan"].(bool)
	dast, _ := config["dast"].(bool)
	if automatic && dast {
		return fmt.Errorf("automatic-scan cannot be combined with dast: DAST excludes the technology-detection templates automatic-scan requires")
	}
	return nil
}

// Risk judges a configuration. DAST fuzzes live endpoints with attack payloads,
// so it is the line between "reads what an attacker sees" and "behaves like
// one".
func (Engine) Risk(config map[string]any) engines.Risk {
	if enabled, ok := config["dast"].(bool); ok && enabled {
		return engines.Intrusive("DAST sends fuzzing payloads (SQLi, XSS, SSTI, traversal) to live endpoints")
	}
	return engines.Safe()
}

// Command renders the `nuclei` invocation equivalent to a run.
//
// Nothing executes this — the scan happens in-process. It is recorded on the
// run and shown in the UI so a scan can be reproduced by hand and so "what did
// this actually do" has an answer in a form people already read. It is
// therefore documentation, and must be kept faithful to Options: a command that
// no longer matches what ran is worse than no command at all.
func (Engine) Command(run engines.Run) []string {
	args := []string{
		"nuclei",
		"-list", run.In,
		"-jsonl",
		"-output", run.Out,
		"-silent",
		"-no-color",
		"-disable-update-check",
	}
	args = append(args, engines.ConfigArgs(run.Config)...)
	return append(args, "-exclude-tags", strings.Join(excludedTags, ","))
}
