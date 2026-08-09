package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/flanksource/recon/internal/scan"
	"github.com/flanksource/recon/internal/schema"
)

// ScanController is the part of the scan runtime these routes need.
type ScanController interface {
	Status() scan.Status
	Cancel() error
}

// RegisterScan adds the two scan routes the entity layer cannot express.
//
// The event stream is one long-lived response rather than a request/response
// operation, and cancelling acts on whatever is running rather than on an
// addressed resource — neither is a CRUD verb over the scans table.
func RegisterScan(mux *http.ServeMux, control ScanController) {
	// The stream replays the latest frame to every new subscriber, so this exists
	// for the first paint and for clients without an EventSource.
	mux.HandleFunc("GET /api/scan/current", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, control.Status())
	})

	mux.HandleFunc("POST /api/scan/cancel", func(w http.ResponseWriter, r *http.Request) {
		if err := control.Cancel(); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeJSON(w, control.Status())
	})
}

// RegisterSchema serves the target edit-form schema.
//
// It is served whole rather than derived from the entity because the edit
// contract needs what a list description cannot carry: $defs, readOnly,
// additionalProperties:false, string formats, and the conditional rule that a
// deactivated target must give a reason.
//
// It is deliberately not at /api/v1/target/schema: that path would be shadowed
// by, or shadow, the entity's own /api/v1/target/{id}.
func RegisterSchema(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/schema/target", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/schema+json")
		_, _ = w.Write(schema.TargetSchemaJSON())
	})
}

// NotFound answers an unmatched API path as JSON.
//
// It exists so the SPA fallback cannot answer for the API: index.html with a
// 200 reads to a client as a successful call that returned nonsense.
func NotFound() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, errNoRoute{r.Method, r.URL.Path})
	})
}

type errNoRoute struct{ method, path string }

func (e errNoRoute) Error() string { return "no such route: " + e.method + " " + e.path }

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	// The frontend renders URLs and header values straight out of these
	// payloads; escaping < > & would corrupt them.
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
