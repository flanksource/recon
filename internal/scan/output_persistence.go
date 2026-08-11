package scan

import (
	"strings"

	"github.com/flanksource/clicky/task"

	"github.com/flanksource/recon/internal/models"
)

func retainedScanOutput(snapshot task.OutputSnapshot) models.ScanOutput {
	stdout, stdoutTruncated := retainedStream(snapshot.Stdout)
	stderr, stderrTruncated := retainedStream(snapshot.Stderr)
	return models.ScanOutput{
		Stdout: stdout, Stderr: stderr,
		StdoutTruncated: stdoutTruncated, StderrTruncated: stderrTruncated,
	}
}

func retainedStream(value string) (string, bool) {
	truncated := len(value) > task.SnapshotStreamLimit
	if truncated {
		value = value[len(value)-task.SnapshotStreamLimit:]
	}
	valid := strings.ToValidUTF8(value, "")
	return valid, truncated || valid != value
}
