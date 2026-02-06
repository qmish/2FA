package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
)

//go:embed static
var content embed.FS

// Handler serves the embedded UI assets.
func Handler() http.Handler {
	sub, err := fs.Sub(content, "static")
	if err != nil {
		return http.NotFoundHandler()
	}
	fileServer := http.FileServer(http.FS(sub))
	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqPath := r.URL.Path
		if reqPath == "" || reqPath == "/" {
			serveIndex(w, r)
			return
		}
		clean := path.Clean(reqPath)
		if clean == "." {
			clean = "/index.html"
		}
		if clean[0] == '/' {
			clean = clean[1:]
		}
		if _, err := sub.Open(clean); err != nil {
			serveIndex(w, r)
			return
		}
		r.URL.Path = "/" + clean
		fileServer.ServeHTTP(w, r)
	})
}
