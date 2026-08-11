package entities

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	_ "github.com/flanksource/recon/internal/engines/all" // populate the registry
)

var _ = Describe("decoding run-only engine configuration", func() {
	// The point of JSON over a repeatable key=value flag: these values keep the
	// types the engine's catalog declares. A rate limit that arrived as the
	// string "50" would be rejected by the same catalog that asked for a number.
	It("keeps numbers, booleans and lists typed", func() {
		Expect(scanOverrides(`{"rate-limit":50,"headless":true,"severity":["high","critical"]}`)).To(Equal(
			map[string]any{
				"rate-limit": float64(50),
				"headless":   true,
				"severity":   []any{"high", "critical"},
			},
		))
	})

	It("reads an unset override as no override at all", func() {
		Expect(scanOverrides("")).To(BeNil())
		Expect(scanOverrides("   ")).To(BeNil())
		Expect(discoveryOverrides("")).To(BeNil())
	})

	It("keys a sweep's overrides by engine", func() {
		Expect(discoveryOverrides(`{"naabu":{"top-ports":"full"},"httpx":{"title":true}}`)).To(Equal(
			map[string]map[string]any{
				"naabu": {"top-ports": "full"},
				"httpx": {"title": true},
			},
		))
	})

	It("refuses configuration that is not a JSON object", func() {
		_, err := scanOverrides(`rate-limit=50`)
		Expect(err).To(MatchError(ContainSubstring(`{"rate-limit":50}`)))
	})

	// Silently dropping it would report a sweep that ran with settings it never
	// used, which is worse than refusing the request.
	It("refuses an override aimed at an engine that does not exist", func() {
		_, err := discoveryOverrides(`{"nmap":{"top-ports":"full"}}`)
		Expect(err).To(MatchError(ContainSubstring("nmap")))
		Expect(err).To(MatchError(ContainSubstring("naabu")))
	})
})
