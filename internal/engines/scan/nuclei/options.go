package nuclei

import (
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/projectdiscovery/goflags"
	nucleiconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	templatetypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	nucleitypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// setter applies one profile value to nuclei's options struct.
//
// The mapping is a table rather than reflection because nuclei's options carry
// no flag tags: the CLI registers each flag imperatively, so the only place the
// flag name and the field are related is that registration. Writing the table
// out is the honest version of what reflection would have to guess at.
type setter func(*nucleitypes.Options, any) error

// options is every key the catalog offers, mapped to the field it drives.
//
// It is exhaustive by test: catalogCoverage asserts that every key in
// catalog_generated.go appears here or in runtimeKeys. Without that, adding a
// flag to the catalog would produce a profile the form accepts, the store
// validates, and the engine silently ignores.
var options = map[string]setter{
	// --- templates -----------------------------------------------------------
	"new-templates":              boolean(func(o *nucleitypes.Options, v bool) { o.NewTemplates = v }),
	"automatic-scan":             boolean(func(o *nucleitypes.Options, v bool) { o.AutomaticScan = v }),
	"templates":                  stringList(func(o *nucleitypes.Options, v []string) { o.Templates = append(o.Templates, v...) }),
	"workflows":                  stringList(func(o *nucleitypes.Options, v []string) { o.Workflows = append(o.Workflows, v...) }),
	"no-strict-syntax":           boolean(func(o *nucleitypes.Options, v bool) { o.NoStrictSyntax = v }),
	"code":                       boolean(func(o *nucleitypes.Options, v bool) { o.EnableCodeTemplates = v }),
	"file":                       boolean(func(o *nucleitypes.Options, v bool) { o.EnableFileTemplates = v }),
	"enable-self-contained":      boolean(func(o *nucleitypes.Options, v bool) { o.EnableSelfContainedTemplates = v }),
	"enable-global-matchers":     boolean(func(o *nucleitypes.Options, v bool) { o.EnableGlobalMatchersTemplates = v }),
	"disable-unsigned-templates": boolean(func(o *nucleitypes.Options, v bool) { o.DisableUnsignedTemplates = v }),
	"var":                        runtimeMap(func(o *nucleitypes.Options) *goflags.RuntimeMap { return &o.Vars }),

	// --- filtering -----------------------------------------------------------
	"author":             stringList(func(o *nucleitypes.Options, v []string) { o.Authors = append(o.Authors, v...) }),
	"tags":               stringList(func(o *nucleitypes.Options, v []string) { o.Tags = append(o.Tags, v...) }),
	"exclude-tags":       stringList(func(o *nucleitypes.Options, v []string) { o.ExcludeTags = append(o.ExcludeTags, v...) }),
	"include-tags":       stringList(func(o *nucleitypes.Options, v []string) { o.IncludeTags = append(o.IncludeTags, v...) }),
	"template-id":        stringList(func(o *nucleitypes.Options, v []string) { o.IncludeIds = append(o.IncludeIds, v...) }),
	"exclude-id":         stringList(func(o *nucleitypes.Options, v []string) { o.ExcludeIds = append(o.ExcludeIds, v...) }),
	"include-templates":  stringList(func(o *nucleitypes.Options, v []string) { o.IncludeTemplates = append(o.IncludeTemplates, v...) }),
	"exclude-templates":  stringList(func(o *nucleitypes.Options, v []string) { o.ExcludedTemplates = append(o.ExcludedTemplates, v...) }),
	"exclude-matchers":   stringList(func(o *nucleitypes.Options, v []string) { o.ExcludeMatchers = append(o.ExcludeMatchers, v...) }),
	"template-condition": stringList(func(o *nucleitypes.Options, v []string) { o.IncludeConditions = append(o.IncludeConditions, v...) }),
	"severity":           severities(func(o *nucleitypes.Options) *severity.Severities { return &o.Severities }),
	"exclude-severity":   severities(func(o *nucleitypes.Options) *severity.Severities { return &o.ExcludeSeverities }),
	"type":               protocols(func(o *nucleitypes.Options) *templatetypes.ProtocolTypes { return &o.Protocols }),
	"exclude-type":       protocols(func(o *nucleitypes.Options) *templatetypes.ProtocolTypes { return &o.ExcludeProtocols }),

	// --- network -------------------------------------------------------------
	"follow-redirects":              boolean(func(o *nucleitypes.Options, v bool) { o.FollowRedirects = v }),
	"follow-host-redirects":         boolean(func(o *nucleitypes.Options, v bool) { o.FollowHostRedirects = v }),
	"max-redirects":                 number(func(o *nucleitypes.Options, v int) { o.MaxRedirects = v }),
	"disable-redirects":             boolean(func(o *nucleitypes.Options, v bool) { o.DisableRedirects = v }),
	"header":                        stringList(func(o *nucleitypes.Options, v []string) { o.CustomHeaders = append(o.CustomHeaders, v...) }),
	"resolvers":                     text(func(o *nucleitypes.Options, v string) { o.ResolversFile = v }),
	"system-resolvers":              boolean(func(o *nucleitypes.Options, v bool) { o.SystemResolvers = v }),
	"disable-clustering":            boolean(func(o *nucleitypes.Options, v bool) { o.DisableClustering = v }),
	"passive":                       boolean(func(o *nucleitypes.Options, v bool) { o.OfflineHTTP = v }),
	"force-http2":                   boolean(func(o *nucleitypes.Options, v bool) { o.ForceAttemptHTTP2 = v }),
	"env-vars":                      boolean(func(o *nucleitypes.Options, v bool) { o.EnvironmentVariables = v }),
	"client-cert":                   text(func(o *nucleitypes.Options, v string) { o.ClientCertFile = v }),
	"client-key":                    text(func(o *nucleitypes.Options, v string) { o.ClientKeyFile = v }),
	"client-ca":                     text(func(o *nucleitypes.Options, v string) { o.ClientCAFile = v }),
	"sni":                           text(func(o *nucleitypes.Options, v string) { o.SNI = v }),
	"dialer-keep-alive":             duration(func(o *nucleitypes.Options, v time.Duration) { o.DialerKeepAlive = v }),
	"allow-local-file-access":       boolean(func(o *nucleitypes.Options, v bool) { o.AllowLocalFileAccess = v }),
	"restrict-local-network-access": boolean(func(o *nucleitypes.Options, v bool) { o.RestrictLocalNetworkAccess = v }),
	"interface":                     text(func(o *nucleitypes.Options, v string) { o.Interface = v }),
	"source-ip":                     text(func(o *nucleitypes.Options, v string) { o.SourceIP = v }),
	"response-size-read":            number(func(o *nucleitypes.Options, v int) { o.ResponseReadSize = v }),
	"response-size-save":            number(func(o *nucleitypes.Options, v int) { o.ResponseSaveSize = v }),
	"tls-impersonate":               boolean(func(o *nucleitypes.Options, v bool) { o.TlsImpersonate = v }),

	// --- fuzzing -------------------------------------------------------------
	"dast":                 boolean(func(o *nucleitypes.Options, v bool) { o.DAST = v }),
	"fuzzing-type":         text(func(o *nucleitypes.Options, v string) { o.FuzzingType = v }),
	"fuzzing-mode":         text(func(o *nucleitypes.Options, v string) { o.FuzzingMode = v }),
	"fuzz-param-frequency": number(func(o *nucleitypes.Options, v int) { o.FuzzParamFrequency = v }),
	"fuzz-aggression":      text(func(o *nucleitypes.Options, v string) { o.FuzzAggressionLevel = v }),
	"fuzz-scope":           stringList(func(o *nucleitypes.Options, v []string) { o.Scope = append(o.Scope, v...) }),
	"fuzz-out-scope":       stringList(func(o *nucleitypes.Options, v []string) { o.OutOfScope = append(o.OutOfScope, v...) }),
	"display-fuzz-points":  boolean(func(o *nucleitypes.Options, v bool) { o.DisplayFuzzPoints = v }),
	"attack-type":          text(func(o *nucleitypes.Options, v string) { o.AttackType = v }),

	// --- performance ---------------------------------------------------------
	"rate-limit":                   number(func(o *nucleitypes.Options, v int) { o.RateLimit = v }),
	"rate-limit-duration":          duration(func(o *nucleitypes.Options, v time.Duration) { o.RateLimitDuration = v }),
	"per-host-rate-limit":          boolean(func(o *nucleitypes.Options, v bool) { o.PerHostRateLimit = v }),
	"bulk-size":                    number(func(o *nucleitypes.Options, v int) { o.BulkSize = v }),
	"concurrency":                  number(func(o *nucleitypes.Options, v int) { o.TemplateThreads = v }),
	"headless-bulk-size":           number(func(o *nucleitypes.Options, v int) { o.HeadlessBulkSize = v }),
	"headless-concurrency":         number(func(o *nucleitypes.Options, v int) { o.HeadlessTemplateThreads = v }),
	"js-concurrency":               number(func(o *nucleitypes.Options, v int) { o.JsConcurrency = v }),
	"payload-concurrency":          number(func(o *nucleitypes.Options, v int) { o.PayloadConcurrency = v }),
	"probe-concurrency":            number(func(o *nucleitypes.Options, v int) { o.ProbeConcurrency = v }),
	"template-loading-concurrency": number(func(o *nucleitypes.Options, v int) { o.TemplateLoadingConcurrency = v }),
	"timeout":                      number(func(o *nucleitypes.Options, v int) { o.Timeout = v }),
	"retries":                      number(func(o *nucleitypes.Options, v int) { o.Retries = v }),
	"max-host-error":               number(func(o *nucleitypes.Options, v int) { o.MaxHostError = v }),
	"no-mhe":                       boolean(func(o *nucleitypes.Options, v bool) { o.NoHostErrors = v }),
	"stop-at-first-match":          boolean(func(o *nucleitypes.Options, v bool) { o.StopAtFirstMatch = v }),
	"stream":                       boolean(func(o *nucleitypes.Options, v bool) { o.Stream = v }),
	"scan-strategy":                text(func(o *nucleitypes.Options, v string) { o.ScanStrategy = v }),
	"input-read-timeout":           duration(func(o *nucleitypes.Options, v time.Duration) { o.InputReadTimeout = v }),
	"leave-default-ports":          boolean(func(o *nucleitypes.Options, v bool) { o.LeaveDefaultPorts = v }),
	"no-httpx":                     boolean(func(o *nucleitypes.Options, v bool) { o.DisableHTTPProbe = v }),
	"preflight-portscan":           boolean(func(o *nucleitypes.Options, v bool) { o.PreflightPortScan = v }),

	// --- headless ------------------------------------------------------------
	"headless":         boolean(func(o *nucleitypes.Options, v bool) { o.Headless = v }),
	"page-timeout":     number(func(o *nucleitypes.Options, v int) { o.PageTimeout = v }),
	"show-browser":     boolean(func(o *nucleitypes.Options, v bool) { o.ShowBrowser = v }),
	"headless-options": stringList(func(o *nucleitypes.Options, v []string) { o.HeadlessOptionalArguments = append(o.HeadlessOptionalArguments, v...) }),
	"system-chrome":    boolean(func(o *nucleitypes.Options, v bool) { o.UseInstalledChrome = v }),
	"cdp-endpoint":     text(func(o *nucleitypes.Options, v string) { o.CDPEndpoint = v }),

	// --- runtime -------------------------------------------------------------
	"stats-interval":     number(func(o *nucleitypes.Options, v int) { o.StatsInterval = v }),
	"metrics-port":       number(func(o *nucleitypes.Options, v int) { o.MetricsPort = v }),
	"honeypot-detect":    boolean(func(o *nucleitypes.Options, v bool) { o.HoneypotDetection = v }),
	"honeypot-threshold": number(func(o *nucleitypes.Options, v int) { o.HoneypotThreshold = v }),
	"suppress-honeypot":  boolean(func(o *nucleitypes.Options, v bool) { o.SuppressHoneypotResults = v }),
}

// runtimeKeys are catalog keys that drive the run rather than nuclei's options
// struct. They have no field to set, so they are listed here to stay accounted
// for — an unhandled key must be a test failure, not a silent no-op.
var runtimeKeys = map[string]string{
	// The CLI gets -max-time from goflags' common flags, which soft-kill the
	// process. In-process there is no process to kill, so buildRun turns it into
	// a context deadline instead.
	"max-time": "applied as a context deadline",

	// Both are engine construction options rather than fields: stats collection
	// is enabled through the SDK, and template auto-upgrade is a callback.
	"stats":                "enables the SDK stats writer",
	"disable-update-check": "disables the SDK template auto-upgrade",

	// nuclei's own field is read by its command-line runner, which recon does
	// not go through. Run wires the traffic counters into the SDK's output
	// writer instead, for every scan — so there is nothing left for a profile to
	// switch on.
	"http-stats": "traffic statistics are always collected in-process",
}

// Options translates a validated profile into nuclei's options.
//
// excluded is appended last and unconditionally, so a profile cannot re-enable
// a denial-of-service, fuzzing, brute-force or intrusive template by setting
// exclude-tags itself. This is the same guarantee the command line gave by
// appending -exclude-tags after the profile's own arguments.
func Options(config map[string]any) (*nucleitypes.Options, error) {
	opts := nucleitypes.DefaultOptions()
	applyCommandLineDefaults(opts)

	for _, key := range sortedKeys(config) {
		value := config[key]
		if value == nil {
			continue
		}
		if _, runtime := runtimeKeys[key]; runtime {
			continue
		}

		apply, known := options[key]
		if !known {
			return nil, fmt.Errorf("nuclei option %q has no mapping: the catalog and the option table disagree", key)
		}
		if err := apply(opts, value); err != nil {
			return nil, fmt.Errorf("nuclei option %q: %w", key, err)
		}
	}

	opts.ExcludeTags = append(opts.ExcludeTags, excludedTags...)

	// nuclei's own deny-list. Its tags are applied by the template loader, but
	// the file list — templates whose matchers are known to produce false
	// positives — is applied by nuclei's command-line runner, which recon no
	// longer goes through. Applying it here keeps a scan reporting what it
	// reported when it was a subprocess.
	opts.ExcludedTemplates = append(opts.ExcludedTemplates, ignoredTemplates()...)
	return opts, nil
}

// applyCommandLineDefaults fills in the defaults nuclei's flag parser supplies
// but types.DefaultOptions does not.
//
// These are not cosmetic. With no fuzzing aggression, every DAST template whose
// payloads are keyed by aggression level fails to compile and is skipped — so a
// `full` scan quietly ran a fraction of the templates it reported. The flag
// parser sets "low"; nothing does when the engine is constructed directly.
func applyCommandLineDefaults(opts *nucleitypes.Options) {
	if opts.FuzzAggressionLevel == "" {
		opts.FuzzAggressionLevel = "low"
	}
}

// ignoredTemplates resolves nuclei's ignore-file entries, which are recorded
// relative to the templates directory.
func ignoredTemplates() []string {
	files := nucleiconfig.ReadIgnoreFile().Files
	if len(files) == 0 {
		return nil
	}
	root := TemplatesDir()
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, filepath.Join(root, file))
	}
	return paths
}

func sortedKeys(config map[string]any) []string {
	keys := make([]string, 0, len(config))
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// --- value adapters ---------------------------------------------------------
//
// A profile arrives as decoded JSON, so a number is a float64 from the API and
// an int from a Go literal, and a list is []any from the API and []string from
// a built-in profile. Each adapter accepts both rather than making every call
// site normalise.

func boolean(set func(*nucleitypes.Options, bool)) setter {
	return func(o *nucleitypes.Options, value any) error {
		enabled, ok := value.(bool)
		if !ok {
			return fmt.Errorf("expected a boolean, got %T", value)
		}
		// A false boolean means "leave nuclei's default alone", matching how the
		// flag form worked: the flag's presence was the switch.
		if enabled {
			set(o, true)
		}
		return nil
	}
}

func text(set func(*nucleitypes.Options, string)) setter {
	return func(o *nucleitypes.Options, value any) error {
		str, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected a string, got %T", value)
		}
		if str != "" {
			set(o, str)
		}
		return nil
	}
}

func number(set func(*nucleitypes.Options, int)) setter {
	return func(o *nucleitypes.Options, value any) error {
		count, err := asInt(value)
		if err != nil {
			return err
		}
		set(o, count)
		return nil
	}
}

func duration(set func(*nucleitypes.Options, time.Duration)) setter {
	return func(o *nucleitypes.Options, value any) error {
		str, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected a duration string such as 30s, got %T", value)
		}
		if str == "" {
			return nil
		}
		parsed, err := time.ParseDuration(str)
		if err != nil {
			return fmt.Errorf("not a duration: %w", err)
		}
		set(o, parsed)
		return nil
	}
}

func stringList(set func(*nucleitypes.Options, []string)) setter {
	return func(o *nucleitypes.Options, value any) error {
		items, err := asStrings(value)
		if err != nil {
			return err
		}
		if len(items) > 0 {
			set(o, items)
		}
		return nil
	}
}

func severities(field func(*nucleitypes.Options) *severity.Severities) setter {
	return func(o *nucleitypes.Options, value any) error {
		items, err := asStrings(value)
		if err != nil {
			return err
		}
		for _, item := range items {
			if err := field(o).Set(item); err != nil {
				return fmt.Errorf("severity %q: %w", item, err)
			}
		}
		return nil
	}
}

func protocols(field func(*nucleitypes.Options) *templatetypes.ProtocolTypes) setter {
	return func(o *nucleitypes.Options, value any) error {
		items, err := asStrings(value)
		if err != nil {
			return err
		}
		for _, item := range items {
			if err := field(o).Set(item); err != nil {
				return fmt.Errorf("protocol type %q: %w", item, err)
			}
		}
		return nil
	}
}

func runtimeMap(field func(*nucleitypes.Options) *goflags.RuntimeMap) setter {
	return func(o *nucleitypes.Options, value any) error {
		items, err := asStrings(value)
		if err != nil {
			return err
		}
		for _, item := range items {
			if err := field(o).Set(item); err != nil {
				return fmt.Errorf("variable %q: %w", item, err)
			}
		}
		return nil
	}
}

func asInt(value any) (int, error) {
	switch typed := value.(type) {
	case int:
		return typed, nil
	case int64:
		return int(typed), nil
	case float64:
		if typed != float64(int(typed)) {
			return 0, fmt.Errorf("expected a whole number, got %v", typed)
		}
		return int(typed), nil
	default:
		return 0, fmt.Errorf("expected a number, got %T", value)
	}
}

func asStrings(value any) ([]string, error) {
	switch typed := value.(type) {
	case []string:
		return typed, nil
	case string:
		return []string{typed}, nil
	case []any:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("expected a list of strings, got a %T element", item)
			}
			items = append(items, str)
		}
		return items, nil
	default:
		return nil, fmt.Errorf("expected a list of strings, got %T", value)
	}
}

// CatalogKeys lists every option key nuclei's catalog declares. It exists for
// the coverage test, which is what keeps this table honest.
func CatalogKeys() []string {
	var keys []string
	for _, section := range catalog {
		for _, field := range section.Properties {
			keys = append(keys, field.Key)
		}
	}
	sort.Strings(keys)
	return keys
}
