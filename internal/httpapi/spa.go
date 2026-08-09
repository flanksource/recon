package httpapi

import (
	"errors"
	"io/fs"
	"net/http"
	"strings"
)

// SPA serves the built single-page app.
//
// Any path that is not a real file falls back to index.html, because the router
// lives in the browser: a reload on /targets/example.test must serve the app,
// not 404.
func SPA(files fs.FS, dir string) http.Handler {
	root, err := fs.Sub(files, dir)
	if err != nil {
		return missing("the web interface was not embedded: " + err.Error())
	}
	if _, err := fs.Stat(root, "index.html"); err != nil {
		// A binary built without the UI is a normal state during development, so
		// say what to do about it rather than serving a bare 404 from the file
		// server that reads like a routing bug.
		return missing("the web interface has not been built: run `pnpm build` in app/")
	}

	fileServer := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")

		// Vite fingerprints everything under /assets/, so those URLs address one
		// immutable build and can be cached indefinitely. index.html must not be.
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}

		if name != "" {
			if _, err := fs.Stat(root, name); err == nil {
				fileServer.ServeHTTP(w, r)
				return
			} else if !errors.Is(err, fs.ErrNotExist) {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		r = r.Clone(r.Context())
		r.URL.Path = "/"
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, r)
	})
}

func missing(message string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, message, http.StatusNotFound)
	})
}
