package httpapi

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// DevProxy serves the web interface from a running Vite dev server instead of
// the embedded build.
//
// The point is that the served UI is always the working tree: the binary embeds
// app/dist at compile time, so without this a source change is invisible until
// both the bundle and the binary are rebuilt.
//
// Only plain HTTP is proxied. Vite's HMR socket is not: its client derives the
// socket URL from the dev server's own port, so the browser connects straight
// to Vite for that and never asks this handler to upgrade.
func DevProxy(target *url.URL) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			// Vite refuses requests whose Host it does not recognise, and this
			// server is reached on a different port than the one Vite bound.
			r.Out.Host = target.Host
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			// A dev server that died mid-session otherwise surfaces as an empty
			// 502 that reads like an application bug.
			http.Error(w, "vite dev server at "+target.String()+" is not answering: "+err.Error(),
				http.StatusBadGateway)
		},
	}
	return proxy
}
