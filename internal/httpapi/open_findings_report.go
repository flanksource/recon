package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/report"
	"github.com/flanksource/recon/internal/store"
)

type OpenFindingsReportSource interface {
	ListFindingStatesPaged(context.Context, store.FindingStateOpts) (api.FindingStatePage, error)
}

// RegisterOpenFindingsReport exports the entire outstanding posture. Interactive
// filters and pagination do not apply; open includes manual review, as in Findings.
func RegisterOpenFindingsReport(mux *http.ServeMux, source OpenFindingsReportSource, renderer ReportRenderer) {
	for _, format := range []report.Format{"", report.FormatPDF, report.FormatHTML} {
		path := "/api/findings/report"
		if format != "" {
			path += "." + string(format)
		}
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			if format != "" {
				if err := renderer.Available(); err != nil {
					writeError(w, http.StatusNotImplemented, err)
					return
				}
			}
			page, err := source.ListFindingStatesPaged(r.Context(), store.FindingStateOpts{
				Status: []string{api.StatusOpen},
				Limit:  0,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			if page.Data == nil {
				page.Data = []api.FindingState{}
			}
			payload := api.OpenFindingsReport{
				States: page.Data, GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			}
			if format == "" {
				writeJSON(w, payload)
				return
			}
			document, err := renderer.Render(r.Context(), format, payload)
			if err != nil {
				writeError(w, http.StatusBadGateway, err)
				return
			}
			w.Header().Set("Content-Type", format.ContentType())
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "open-findings-report."+string(format)))
			w.Header().Set("Content-Length", strconv.Itoa(len(document)))
			_, _ = w.Write(document)
		})
	}
}
