package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/flanksource/recon"
	"github.com/flanksource/recon/internal/db"
	"github.com/flanksource/recon/internal/server"
	"github.com/flanksource/recon/internal/store"
)

func newServeCommand() *cobra.Command {
	var (
		port int
		host string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the API and the web interface",
		Long: "Serves every entity as REST with an OpenAPI description at\n" +
			"/api/openapi.json — the same operations this CLI exposes, from the same\n" +
			"declaration.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withDatabase(cmd.Context(), databaseOptions{}, func(handle *db.Handle) error {
				st := store.New(handle.Gorm)

				seeded, err := st.SeedDefaultProfiles(cmd.Context())
				if err != nil {
					return err
				}
				if seeded > 0 {
					cmd.Printf("seeded %d default engine profiles\n", seeded)
				}

				return serve(cmd, st, host, port)
			})
		},
	}

	cmd.Flags().IntVar(&port, "port", 8280, "port to listen on")
	cmd.Flags().StringVar(&host, "host", "localhost", "address to listen on")
	return cmd
}

// serve builds the mux and runs until the context is cancelled.
func serve(cmd *cobra.Command, st *store.Store, host string, port int) error {
	handler := server.Handler(server.Config{
		Host: host, Port: port,
		Root: cmd.Root(), Registry: registry, Store: st, Scans: scans, Sweeps: sweeps,
		UI: recon.UI, UIDir: recon.UIDir,
	})

	httpServer := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", host, port),
		Handler: handler,
		// No WriteTimeout: it is an absolute deadline on the response, which
		// truncates a streaming endpoint mid-frame rather than timing out an
		// idle one.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		<-cmd.Context().Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()

	cmd.Printf("listening on http://%s:%d\n", host, port)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
