package fixture

import (
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"
)

func Middleware(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_, _ = io.ReadAll(r.Body)
}

func CredentialedCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func Bounded(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	_, _ = io.ReadAll(r.Body)
}

func Routes(router Router) {
	if os.Getenv("DEBUG") == "1" {
		router.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
	}
}

func Run(handler http.Handler, tlsEnabled bool) {
	server := &http.Server{
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	if tlsEnabled {
		_ = server.ListenAndServeTLS("server.crt", "server.key")
	} else {
		_ = server.ListenAndServe()
	}
}
