package arguments

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type CredentialMode string

const (
	CredentialModeAmbient    CredentialMode = "ambient"
	CredentialModeConfigured CredentialMode = "configured"
)

type ProviderContextOptions struct {
	Mode               CredentialMode
	RuntimeCredentials bool
}

func (c Catalogue) Lookup(provider, key string) (Argument, error) {
	arguments, err := c.ArgumentsForProvider(provider)
	if err != nil {
		return Argument{}, err
	}
	for _, argument := range arguments {
		if argument.Key == key {
			return argument, nil
		}
	}
	return Argument{}, fmt.Errorf("unknown argument %q for provider %q", key, provider)
}

func (c Catalogue) ArgumentsForProvider(provider string) ([]Argument, error) {
	providerArguments, err := c.providerArguments(provider)
	if err != nil {
		return nil, err
	}
	providerArguments = slices.Clone(providerArguments)
	common := slices.Clone(c.Common)
	sort.Slice(providerArguments, func(i, j int) bool { return argumentLess(providerArguments[i], providerArguments[j]) })
	sort.Slice(common, func(i, j int) bool { return argumentLess(common[i], common[j]) })
	return append(providerArguments, common...), nil
}

func (c Catalogue) PartitionProviderContext(
	provider string,
	values map[string]any,
	options ProviderContextOptions,
) (Inputs, error) {
	if options.Mode != CredentialModeAmbient && options.Mode != CredentialModeConfigured {
		return Inputs{}, fmt.Errorf("unsupported credential mode %q", options.Mode)
	}
	if options.Mode == CredentialModeAmbient && options.RuntimeCredentials {
		return Inputs{}, fmt.Errorf("runtime credentials are not allowed in ambient credential mode")
	}
	if _, err := c.providerArguments(provider); err != nil {
		return Inputs{}, err
	}
	inputs := Inputs{Context: map[string]any{}, Credential: map[string]any{}}
	credentialSelector := false
	for _, key := range sortedKeys(values) {
		argument, err := c.Lookup(provider, key)
		if err != nil {
			return Inputs{}, err
		}
		switch argument.Policy.Owner {
		case OwnerContext:
			if argument.Policy.CredentialSelector && valueIsActive(values[key]) {
				if options.Mode == CredentialModeAmbient {
					return Inputs{}, fmt.Errorf("credential selector %q is not allowed in ambient credential mode", key)
				}
				credentialSelector = true
			}
			inputs.Context[key] = values[key]
		case OwnerCredential:
			return Inputs{}, fmt.Errorf("runtime-only credential argument %q cannot be supplied in provider context", key)
		case OwnerForbidden:
			return Inputs{}, fmt.Errorf("argument %q is forbidden: %s", key, argument.Policy.Reason)
		default:
			return Inputs{}, fmt.Errorf("argument %q belongs to %s, not provider context", key, argument.Policy.Owner)
		}
	}
	if options.Mode == CredentialModeConfigured && !credentialSelector && !options.RuntimeCredentials {
		return Inputs{}, fmt.Errorf("configured credential mode requires an explicit credential selector")
	}
	return inputs, nil
}

func (c Catalogue) BuildArgv(provider string, inputs Inputs) ([]string, error) {
	canonicalProvider, err := NormalizeProvider(provider)
	if err != nil {
		return nil, err
	}
	provider = canonicalProvider
	if err := c.Validate(); err != nil {
		return nil, err
	}
	arguments, err := c.ArgumentsForProvider(provider)
	if err != nil {
		return nil, err
	}
	values, err := c.collectValues(provider, inputs)
	if err != nil {
		return nil, err
	}
	if err := c.validateSelections(provider, arguments, values); err != nil {
		return nil, err
	}
	argv := []string{provider}
	for _, argument := range arguments {
		value, exists := values[argument.Key]
		if !exists {
			continue
		}
		emitted, emitErr := emitArgument(argument, value)
		if emitErr != nil {
			return nil, emitErr
		}
		argv = append(argv, emitted...)
	}
	return argv, nil
}

func (c Catalogue) collectValues(provider string, inputs Inputs) (map[string]any, error) {
	values := make(map[string]any)
	sources := []struct {
		owner  Owner
		values map[string]any
	}{{OwnerProfile, inputs.Profile}, {OwnerContext, inputs.Context}, {OwnerCredential, inputs.Credential}, {OwnerRunner, inputs.Runner}}
	for _, source := range sources {
		for _, key := range sortedKeys(source.values) {
			argument, err := c.Lookup(provider, key)
			if err != nil {
				return nil, err
			}
			if argument.Policy.Owner == OwnerForbidden {
				return nil, fmt.Errorf("argument %q is forbidden: %s", key, argument.Policy.Reason)
			}
			if argument.Policy.Owner != source.owner {
				return nil, fmt.Errorf("argument %q belongs to %s, not %s", key, argument.Policy.Owner, source.owner)
			}
			if _, duplicate := values[key]; duplicate {
				return nil, fmt.Errorf("argument %q was supplied more than once", key)
			}
			if source.values[key] == nil {
				return nil, fmt.Errorf("argument %q cannot be null", key)
			}
			values[key] = source.values[key]
		}
	}
	return values, nil
}

func (c Catalogue) validateSelections(provider string, arguments []Argument, values map[string]any) error {
	for _, argument := range arguments {
		if argument.Required && !valueIsActive(values[argument.Key]) {
			return fmt.Errorf("required argument %q is missing", argument.Key)
		}
	}
	mutexes := slices.Clone(c.CommonMutualExclusions)
	for _, candidate := range c.Providers {
		if candidate.Name == provider {
			mutexes = append(mutexes, candidate.MutualExclusions...)
			break
		}
	}
	for _, mutex := range mutexes {
		active := []string{}
		for _, key := range mutex.Keys {
			if valueIsActive(values[key]) {
				active = append(active, key)
			}
		}
		if len(active) > 1 {
			return fmt.Errorf("%s accepts only one of %s: got %s",
				mutex.Label(), strings.Join(mutex.Keys, ", "), strings.Join(active, ", "))
		}
		if mutex.Required && len(active) != 1 {
			return fmt.Errorf("%s requires exactly one of %s", mutex.Label(), strings.Join(mutex.Keys, ", "))
		}
	}
	return nil
}

func emitArgument(argument Argument, value any) ([]string, error) {
	if argument.Action == ActionStoreTrue {
		enabled, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("argument %q must be a boolean", argument.Key)
		}
		if !enabled {
			return nil, nil
		}
		return []string{argument.Canonical}, nil
	}
	if argument.Action == ActionAppend {
		return emitAppend(argument, value)
	}
	return emitStore(argument, value)
}

func emitStore(argument Argument, value any) ([]string, error) {
	if argument.NArgs == NArgsOne || argument.NArgs == NArgsOptional {
		encoded, err := encodeScalar(argument, value)
		if err != nil {
			return nil, err
		}
		return []string{argument.Canonical, encoded}, nil
	}
	values, ok := asSlice(value)
	if !ok {
		return nil, fmt.Errorf("argument %q must be an array", argument.Key)
	}
	if argument.NArgs == NArgsOneOrMore && len(values) == 0 {
		return nil, fmt.Errorf("argument %q requires at least one value", argument.Key)
	}
	if len(values) == 0 {
		return nil, nil
	}
	result := []string{argument.Canonical}
	for _, value := range values {
		encoded, err := encodeScalar(argument, value)
		if err != nil {
			return nil, err
		}
		result = append(result, encoded)
	}
	return result, nil
}

func emitAppend(argument Argument, value any) ([]string, error) {
	occurrences, ok := asSlice(value)
	if !ok {
		return nil, fmt.Errorf("append argument %q must be an array", argument.Key)
	}
	result := make([]string, 0, len(occurrences)*2)
	for _, occurrence := range occurrences {
		if argument.NArgs == NArgsOne || argument.NArgs == NArgsOptional {
			encoded, err := encodeScalar(argument, occurrence)
			if err != nil {
				return nil, err
			}
			result = append(result, argument.Canonical, encoded)
			continue
		}
		values, nested := asSlice(occurrence)
		if !nested {
			return nil, fmt.Errorf("append argument %q must be an array of arrays", argument.Key)
		}
		if argument.NArgs == NArgsOneOrMore && len(values) == 0 {
			return nil, fmt.Errorf("argument %q requires at least one value per occurrence", argument.Key)
		}
		result = append(result, argument.Canonical)
		for _, item := range values {
			encoded, err := encodeScalar(argument, item)
			if err != nil {
				return nil, err
			}
			result = append(result, encoded)
		}
	}
	return result, nil
}

func encodeScalar(argument Argument, value any) (string, error) {
	var encoded string
	switch argument.Type {
	case TypeString:
		stringValue, ok := value.(string)
		if !ok || stringValue == "" {
			return "", fmt.Errorf("argument %q must be a non-empty string", argument.Key)
		}
		encoded = stringValue
	case TypeInteger:
		var err error
		encoded, err = encodeInteger(value)
		if err != nil {
			return "", fmt.Errorf("argument %q must be an integer", argument.Key)
		}
	case TypeNumber:
		var err error
		encoded, err = encodeNumber(value)
		if err != nil {
			return "", fmt.Errorf("argument %q must be a number", argument.Key)
		}
	case TypeBoolean:
		boolean, ok := value.(bool)
		if !ok {
			return "", fmt.Errorf("argument %q must be a boolean", argument.Key)
		}
		encoded = strconv.FormatBool(boolean)
	default:
		return "", fmt.Errorf("argument %q has unsupported type %q", argument.Key, argument.Type)
	}
	if len(argument.Choices) > 0 && !slices.Contains(argument.Choices, encoded) {
		return "", fmt.Errorf("argument %q must be one of %v", argument.Key, argument.Choices)
	}
	return encoded, nil
}

func encodeInteger(value any) (string, error) {
	switch number := value.(type) {
	case int:
		return strconv.Itoa(number), nil
	case int8, int16, int32, int64:
		return strconv.FormatInt(reflect.ValueOf(number).Int(), 10), nil
	case uint, uint8, uint16, uint32, uint64:
		return strconv.FormatUint(reflect.ValueOf(number).Uint(), 10), nil
	case float64:
		if number != float64(int64(number)) {
			return "", fmt.Errorf("not integral")
		}
		return strconv.FormatInt(int64(number), 10), nil
	case json.Number:
		integer, err := number.Int64()
		return strconv.FormatInt(integer, 10), err
	default:
		return "", fmt.Errorf("not numeric")
	}
}

func encodeNumber(value any) (string, error) {
	switch number := value.(type) {
	case float32, float64:
		return strconv.FormatFloat(reflect.ValueOf(number).Convert(reflect.TypeOf(float64(0))).Float(), 'g', -1, 64), nil
	case json.Number:
		if _, err := number.Float64(); err != nil {
			return "", err
		}
		return number.String(), nil
	default:
		return encodeInteger(value)
	}
}

func asSlice(value any) ([]any, bool) {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() || (reflected.Kind() != reflect.Slice && reflected.Kind() != reflect.Array) {
		return nil, false
	}
	values := make([]any, reflected.Len())
	for index := range reflected.Len() {
		values[index] = reflected.Index(index).Interface()
	}
	return values, true
}

func valueIsActive(value any) bool {
	if value == nil {
		return false
	}
	if boolean, ok := value.(bool); ok {
		return boolean
	}
	if values, ok := asSlice(value); ok {
		return len(values) > 0
	}
	return true
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func argumentLess(left, right Argument) bool {
	if left.Order == right.Order {
		return left.Key < right.Key
	}
	return left.Order < right.Order
}

func (c Catalogue) providerArguments(provider string) ([]Argument, error) {
	canonical, err := NormalizeProvider(provider)
	if err != nil {
		return nil, err
	}
	for _, candidate := range c.Providers {
		if candidate.Name == canonical {
			return candidate.Arguments, nil
		}
	}
	return nil, fmt.Errorf("prowler argument catalogue is missing provider %q", canonical)
}
