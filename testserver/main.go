// Command testserver is the plain-HTTP workload the agent watches.
//
// Every request gets a 200 with a small JSON summary. The body is fully
// drained before replying so all request bytes pass through tcp_recvmsg,
// which is what capture.bpf.c hooks.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type reply struct {
	Status    string `json:"status"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	BodyBytes int64  `json:"body_bytes"`
}

func handle(w http.ResponseWriter, r *http.Request) {
	n, err := io.Copy(io.Discard, r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Log only method, path and size: this server stands in for a workload,
	// and header/query values are exactly what the agent must redact.
	log.Printf("%s %s body=%dB from=%s", r.Method, r.URL.Path, n, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reply{Status: "ok", Method: r.Method, Path: r.URL.Path, BodyBytes: n})
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           http.HandlerFunc(handle),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10, // matches reasm's MAX_HEADER_BYTES
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("testserver listening on %s (pid %d)", *addr, os.Getpid())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	log.Print("testserver stopped")
}
