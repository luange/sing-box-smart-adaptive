package main

import (
	"errors"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
)

const runtimeDiagnosticsEnvironment = "SING_BOX_RUNTIME_DIAGNOSTICS"

// startRuntimeDiagnostics exposes Go runtime profiles only when explicitly
// requested for an isolated process. The fixed loopback listener prevents the
// diagnostic surface from being exposed by a production configuration.
func startRuntimeDiagnostics() (*http.Server, error) {
	configured := os.Getenv(runtimeDiagnosticsEnvironment)
	if configured == "" {
		return nil, nil
	}
	address := "127.0.0.1:6060"
	if configured != "1" && configured != "true" {
		address = configured
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid runtime diagnostics address")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("runtime diagnostics must listen on loopback")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: http.DefaultServeMux}
	go func() {
		serveErr := server.Serve(listener)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			_ = listener.Close()
		}
	}()
	return server, nil
}
