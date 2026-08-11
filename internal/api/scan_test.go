package api_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

var _ = Describe("scan API", func() {
	It("emits exact invocation, runtime, statistics, and captured process evidence", func() {
		exitCode := 2
		encoded, err := json.Marshal(api.Scan{
			ID: "scan-1", Name: "nuclei-safe-1", Engine: "nuclei", EngineVersion: "3.4.10", Profile: "safe",
			Selector: map[string]any{"hosts": []string{"api.example.test"}}, SelectorLabel: "host api.example.test",
			EndpointCount: 3, Phase: api.PhaseFailed, StartedAt: "2026-08-10T12:00:00", FinishedAt: "2026-08-10T12:00:02",
			DurationMS: 2500, Command: []string{"/opt/recon/bin/nuclei", "-target", "api.example.test"}, ExitCode: &exitCode,
			Error: "engine exited 2", Findings: 1, Severities: map[string]int{"high": 1},
			Stats: &api.ScanStats{Requests: 40, Total: 60, Percent: 66.7, RPS: 12.3, Matched: 1, Errors: 2, Hosts: 3, Templates: 18, Duration: "2s"},
			Hosts: []string{"api.example.test"}, Result: "findings.jsonl", OutputCaptured: true,
			Stdout: "scan output\n", Stderr: "one warning\n", StdoutTruncated: true,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(encoded).To(MatchJSON(`{
			"id":"scan-1","name":"nuclei-safe-1","engine":"nuclei","engineVersion":"3.4.10","profile":"safe",
			"selector":{"hosts":["api.example.test"]},"selectorLabel":"host api.example.test","endpointCount":3,
			"phase":"failed","startedAt":"2026-08-10T12:00:00","finishedAt":"2026-08-10T12:00:02","durationMs":2500,
			"command":["/opt/recon/bin/nuclei","-target","api.example.test"],"exitCode":2,"error":"engine exited 2",
			"findings":1,"severities":{"high":1},
			"stats":{"requests":40,"total":60,"percent":66.7,"rps":12.3,"matched":1,"errors":2,"hosts":3,"templates":18,"duration":"2s"},
			"hosts":["api.example.test"],"resultPath":"findings.jsonl","outputCaptured":true,
			"stdout":"scan output\n","stderr":"one warning\n","stdoutTruncated":true
		}`))
	})
})
