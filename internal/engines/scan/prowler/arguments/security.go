package arguments

import (
	"fmt"
	"slices"
	"strings"
)

const RedactedValue = "REDACTED"

func (c Catalogue) ValidateSensitivity() error {
	if c.SensitiveFlags == nil {
		return fmt.Errorf("upstream sensitive flags are missing")
	}
	if _, ok := c.SensitiveFlags["common"]; !ok {
		return fmt.Errorf("upstream sensitive flags are missing common scope")
	}
	if err := validateSensitivityScope("common", c.Common, c.SensitiveFlags["common"]); err != nil {
		return err
	}
	knownScopes := map[string]bool{"common": true}
	for _, provider := range c.Providers {
		knownScopes[provider.Name] = true
		flags, ok := c.SensitiveFlags[provider.Name]
		if !ok {
			return fmt.Errorf("upstream sensitive flags are missing %s scope", provider.Name)
		}
		if err := validateSensitivityScope(provider.Name, provider.Arguments, flags); err != nil {
			return err
		}
	}
	for scope := range c.SensitiveFlags {
		if !knownScopes[scope] {
			return fmt.Errorf("upstream sensitive flags contain unknown scope %q", scope)
		}
	}
	return nil
}

func validateSensitivityScope(scope string, arguments []Argument, sensitiveFlags []string) error {
	byFlag := make(map[string]Argument)
	for _, argument := range arguments {
		for _, flag := range argument.Flags {
			byFlag[flag] = argument
		}
	}
	listed := make(map[string]bool, len(sensitiveFlags))
	for _, flag := range sensitiveFlags {
		if listed[flag] {
			return fmt.Errorf("upstream sensitive flag %q is duplicated in %s", flag, scope)
		}
		listed[flag] = true
		argument, ok := byFlag[flag]
		if !ok {
			return fmt.Errorf("upstream sensitive flag %q is unknown in %s", flag, scope)
		}
		if !argument.Policy.Sensitive || !argument.Policy.Redact {
			return fmt.Errorf("upstream sensitive flag %q is not classified sensitive and redacted", flag)
		}
	}
	return nil
}

func (c Catalogue) RejectSensitive(provider string, values map[string]any) error {
	if _, err := c.providerArguments(provider); err != nil {
		return err
	}
	for _, key := range sortedKeys(values) {
		argument, err := c.Lookup(provider, key)
		if err != nil {
			return err
		}
		if !valueIsActive(values[key]) {
			continue
		}
		if argument.Policy.Sensitive {
			return fmt.Errorf("sensitive argument %q cannot be persisted", key)
		}
	}
	return nil
}

func (c Catalogue) RedactArgv(provider string, argv []string) ([]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	canonicalProvider, err := NormalizeProvider(provider)
	if err != nil {
		return nil, err
	}
	if len(argv) == 0 {
		return nil, fmt.Errorf("argv must start with provider %q", provider)
	}
	argvProvider, err := NormalizeProvider(argv[0])
	if err != nil || argvProvider != canonicalProvider {
		return nil, fmt.Errorf("argv must start with provider %q", provider)
	}
	arguments, err := c.ArgumentsForProvider(canonicalProvider)
	if err != nil {
		return nil, err
	}
	byFlag := make(map[string]Argument)
	for _, argument := range arguments {
		for _, flag := range argument.Flags {
			byFlag[flag] = argument
		}
	}
	result := []string{argv[0]}
	for index := 1; index < len(argv); {
		next, consumed, redactErr := redactArgument(argv[index:], byFlag)
		if redactErr != nil {
			return nil, redactErr
		}
		result = append(result, next...)
		index += consumed
	}
	return result, nil
}

func redactArgument(argv []string, byFlag map[string]Argument) ([]string, int, error) {
	flag, _, hasInline := strings.Cut(argv[0], "=")
	argument, ok := byFlag[flag]
	if !ok {
		return nil, 0, fmt.Errorf("unknown flag %q", flag)
	}
	if argument.Action == ActionStoreTrue {
		if hasInline {
			return nil, 0, fmt.Errorf("boolean flag %q cannot have a value", flag)
		}
		return []string{flag}, 1, nil
	}
	count, err := argumentValueCount(argument, argv, byFlag, hasInline)
	if err != nil {
		return nil, 0, err
	}
	redacted := slices.Clone(argv[:count+1])
	if argument.Policy.Redact {
		if hasInline {
			redacted[0] = flag + "=" + RedactedValue
		}
		for index := 1; index < len(redacted); index++ {
			redacted[index] = RedactedValue
		}
	}
	return redacted, count + 1, nil
}

func argumentValueCount(argument Argument, argv []string, byFlag map[string]Argument, hasInline bool) (int, error) {
	if hasInline && (argument.NArgs == NArgsOne || argument.NArgs == NArgsOptional) {
		return 0, nil
	}
	if argument.NArgs == NArgsOne {
		if len(argv) < 2 {
			return 0, fmt.Errorf("flag %q requires a value", argv[0])
		}
		return 1, nil
	}
	if argument.NArgs == NArgsOptional {
		if hasInline || len(argv) < 2 {
			return 0, nil
		}
		candidate, _, _ := strings.Cut(argv[1], "=")
		if _, found := byFlag[candidate]; found {
			return 0, nil
		}
		if strings.HasPrefix(candidate, "-") {
			return 0, fmt.Errorf("unknown flag %q", candidate)
		}
		return 1, nil
	}
	count := 0
	if hasInline {
		count = 0
	}
	for index := 1; index < len(argv); index++ {
		candidate, _, _ := strings.Cut(argv[index], "=")
		if _, found := byFlag[candidate]; found {
			break
		}
		if strings.HasPrefix(candidate, "-") {
			return 0, fmt.Errorf("unknown flag %q", candidate)
		}
		count++
	}
	minimum := 0
	if argument.NArgs == NArgsOneOrMore && !hasInline {
		minimum = 1
	}
	if count < minimum {
		return 0, fmt.Errorf("flag %q requires at least one value", argv[0])
	}
	return count, nil
}
