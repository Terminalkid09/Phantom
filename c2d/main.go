// Command c2d is the Phantom C2 data plane: a single static binary that
// speaks the SAME wire protocol as the Python listener, so an unmodified
// C++ beacon cannot tell which backend answered.
//
// Scope: the beacon-facing surface (check-in, results, payloads, malleable
// catch-all) plus the operator REST endpoints. The shell, the automation
// agent, the task/artifact policy and the desktop API stay in Python — see
// README.md for the exact boundary.
//
// Nothing here is dynamic: no plugin loading, no shell-out, no interpreted
// input. The dependency set is the Go standard library only, which is the
// point (no pip, no venv, no OpenSSL to keep patched).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	logger := log.New(os.Stdout, "c2d ", log.LstdFlags|log.LUTC)
	if err := run(logger); err != nil {
		logger.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run(logger *log.Logger) error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	// Same refusal as the Python listener: a clear-text C2 on a non-loopback
	// bind is readable and hijackable by anyone on the path.
	if !cfg.SSL && !isLoopbackHost(cfg.Bind) && !cfg.AllowPlaintext {
		return fmt.Errorf("refusing a PLAINTEXT listener on non-loopback bind "+
			"%q: enable TLS (c2.ssl=true) or set c2.allow_plaintext=true for a "+
			"lab only", cfg.Bind)
	}

	store := NewStore(cfg.BeaconRegistry)
	server := NewServer(cfg, store, logger)

	httpSrv := &http.Server{
		Addr:              net.JoinHostPort(cfg.Bind, fmt.Sprint(cfg.Port)),
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if cfg.SSL {
		tlsConf, err := server.TLSConfig()
		if err != nil {
			return fmt.Errorf("tls setup: %w", err)
		}
		httpSrv.TLSConfig = tlsConf
	}

	scheme := "http"
	if cfg.SSL {
		scheme = "https"
	}
	logger.Printf("c2d listening on %s://%s (mtls=%v require_client_cert=%v "+
		"data=%s)", scheme, httpSrv.Addr, cfg.MTLS,
		cfg.MTLSRequireClientCert, cfg.DataDir)

	errCh := make(chan error, 1)
	go func() {
		if cfg.SSL {
			errCh <- httpSrv.ListenAndServeTLS("", "")
		} else {
			errCh <- httpSrv.ListenAndServe()
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-stop:
		logger.Printf("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(ctx)
	}
	return nil
}
