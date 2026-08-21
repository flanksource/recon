package server_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func errorOf(body []byte) string {
	var envelope struct {
		Message string `json:"message"`
	}
	Expect(json.Unmarshal(body, &envelope)).To(Succeed(),
		fmt.Sprintf("not an error envelope: %s", truncate(body)))
	Expect(envelope.Message).ToNot(BeEmpty(),
		fmt.Sprintf("expected an error, got %s", truncate(body)))
	return envelope.Message
}

func operationID(operation any) string {
	fields, _ := operation.(map[string]any)
	id, _ := fields["operationId"].(string)
	return id
}

func parameters(spec map[string]any, path, method string) []string {
	paths, _ := spec["paths"].(map[string]any)
	item, _ := paths[path].(map[string]any)
	operation, _ := item[method].(map[string]any)
	declared, _ := operation["parameters"].([]any)

	var names []string
	for _, parameter := range declared {
		fields, _ := parameter.(map[string]any)
		if name, ok := fields["name"].(string); ok {
			names = append(names, name)
		}
	}
	return names
}

func parameterRoles(spec map[string]any, path, method string) map[string]string {
	paths, _ := spec["paths"].(map[string]any)
	item, _ := paths[path].(map[string]any)
	operation, _ := item[method].(map[string]any)
	declared, _ := operation["parameters"].([]any)

	roles := map[string]string{}
	for _, parameter := range declared {
		fields, _ := parameter.(map[string]any)
		name, ok := fields["name"].(string)
		if !ok {
			continue
		}
		meta, _ := fields["x-clicky"].(map[string]any)
		role, _ := meta["role"].(string)
		roles[name] = role
	}
	return roles
}

type lookupFilter struct {
	Label   string                     `json:"label"`
	Multi   bool                       `json:"multi"`
	Total   int                        `json:"total"`
	Options map[string]json.RawMessage `json:"options"`
}

func (f lookupFilter) values() []string {
	values := make([]string, 0, len(f.Options))
	for value := range f.Options {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func lookup(url, search string) map[string]lookupFilter {
	response := getJSON[struct {
		Filters map[string]lookupFilter `json:"filters"`
	}](url + "?__lookup=filters" + search)
	return response.Filters
}

func get(url string) []byte {
	response, err := http.Get(url)
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(response.Body.Close)

	body, err := io.ReadAll(response.Body)
	Expect(err).ToNot(HaveOccurred())
	return body
}

func send(method, url, body string) []byte {
	request, err := http.NewRequest(method, url, strings.NewReader(body))
	Expect(err).ToNot(HaveOccurred())
	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(response.Body.Close)

	read, err := io.ReadAll(response.Body)
	Expect(err).ToNot(HaveOccurred())
	return read
}

func getJSON[T any](url string) T {
	body := get(url)
	var decoded T
	Expect(json.Unmarshal(body, &decoded)).To(Succeed(),
		fmt.Sprintf("%s returned %s", url, truncate(body)))
	return decoded
}

func truncate(body []byte) string {
	if len(body) > 400 {
		return string(body[:400]) + "…"
	}
	return string(body)
}
