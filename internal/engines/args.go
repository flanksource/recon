package engines

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// ConfigArgs turns a validated profile into command-line flags.
//
// Every engine here is a ProjectDiscovery tool sharing one flag convention:
// `-flag value`, a bare `-flag` for a true boolean, an omitted flag for false,
// and a repeated flag for a list. Keys are emitted in sorted order so a run's
// recorded command is stable and diffable rather than reordering per run.
//
// Config must already have been validated against the engine's catalog; this
// only translates.
func ConfigArgs(config map[string]any) []string {
	keys := make([]string, 0, len(config))
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var args []string
	for _, key := range keys {
		args = append(args, flagArgs(key, config[key])...)
	}
	return args
}

func flagArgs(key string, value any) []string {
	flag := "-" + key

	switch typed := value.(type) {
	case nil:
		return nil
	case bool:
		// A false boolean means "leave the engine's default alone", not
		// "-flag=false": these tools treat the flag's presence as the switch.
		if !typed {
			return nil
		}
		return []string{flag}
	case string:
		if typed == "" {
			return nil
		}
		return []string{flag, typed}
	case []any:
		var args []string
		for _, item := range typed {
			args = append(args, flagArgs(key, item)...)
		}
		return args
	case []string:
		var args []string
		for _, item := range typed {
			args = append(args, flag, item)
		}
		return args
	}

	if number, ok := asNumber(value); ok {
		return []string{flag, formatNumber(number)}
	}
	return []string{flag, fmt.Sprint(value)}
}

func formatNumber(value float64) string {
	if value == float64(int64(value)) {
		return strconv.FormatInt(int64(value), 10)
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// ParseFloat reads a number an engine reported as a string, yielding 0 when it
// is unparseable. Progress reporting is cosmetic — a malformed stats line should
// not fail a scan that is otherwise working.
func ParseFloat(value string) float64 {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0
	}
	return parsed
}

// maxLine bounds one line of engine output. A malformed or hostile response can
// otherwise make the scanner emit an unbounded line and exhaust memory here
// rather than in the tool that produced it.
const maxLine = 4 << 20 // 4 MiB

// maxReportedMalformed bounds the aggregated error. A wholly corrupt file
// should say so in a sentence, not reproduce itself.
const maxReportedMalformed = 5

// ScanJSONLines calls handle for each non-blank line. Blank lines are skipped
// rather than treated as errors: every one of these tools emits them.
//
// A line that opens like a record but is not valid JSON is counted and reported
// at the end rather than aborting the scan. Killing a run truncates whatever
// line the engine was mid-write on, and discarding a whole run's findings over
// its last few bytes is worse than reporting the damage — but discarding them
// silently, as the previous implementation did, is worse than both.
func ScanJSONLines(r io.Reader, handle func(line []byte) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLine)

	var malformed []error
	for number := 1; scanner.Scan(); number++ {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// Some tools interleave a banner or a warning with their JSON output.
		// Anything that is not an object is not a record.
		if line[0] != '{' {
			continue
		}
		if !json.Valid(line) {
			if len(malformed) < maxReportedMalformed {
				malformed = append(malformed, fmt.Errorf("line %d is not valid JSON", number))
			}
			continue
		}
		// A handler error is the caller's failure, not the engine's, so it
		// aborts rather than being collected.
		if err := handle(line); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read engine output: %w", err)
	}
	return errors.Join(malformed...)
}

// ScanLines calls handle for each non-blank line of plain-text output.
func ScanLines(r io.Reader, handle func(line string) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLine)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if err := handle(line); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read engine output: %w", err)
	}
	return nil
}
