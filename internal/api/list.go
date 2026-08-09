package api

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// StringList is a list field that accepts either wire form the two surfaces
// produce.
//
// One operation is served over HTTP and on the CLI, and they do not encode a
// list the same way: a JSON caller sends ["safe","full"], while a flag sends
// --profiles=safe,full. The HTTP body is flattened into flags before it reaches
// the handler, so even a JSON array arrives as a comma-joined string — an edit
// that set a profile failed with "cannot unmarshal string into []string" and
// the save was silently lost.
type StringList []string

func (l *StringList) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*l = list
		return nil
	}

	var joined string
	if err := json.Unmarshal(data, &joined); err != nil {
		return fmt.Errorf("expected a list or a comma-separated string, got %s", data)
	}
	*l = splitList(joined)
	return nil
}

func (l StringList) MarshalJSON() ([]byte, error) {
	if l == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]string(l))
}

// IntList is StringList for numeric fields, such as ports.
type IntList []int

func (l *IntList) UnmarshalJSON(data []byte) error {
	var list []int
	if err := json.Unmarshal(data, &list); err == nil {
		*l = list
		return nil
	}

	var joined string
	if err := json.Unmarshal(data, &joined); err != nil {
		return fmt.Errorf("expected a list or a comma-separated string, got %s", data)
	}

	parsed := make([]int, 0, len(splitList(joined)))
	for _, entry := range splitList(joined) {
		number, err := strconv.Atoi(entry)
		if err != nil {
			return fmt.Errorf("%q is not a port number", entry)
		}
		parsed = append(parsed, number)
	}
	*l = parsed
	return nil
}

func (l IntList) MarshalJSON() ([]byte, error) {
	if l == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]int(l))
}

// splitList drops empty entries so "safe," and "" do not become a list with a
// blank member, which would fail the schema's minLength on the way in.
func splitList(joined string) []string {
	var entries []string
	for _, entry := range strings.Split(joined, ",") {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			entries = append(entries, trimmed)
		}
	}
	return entries
}
