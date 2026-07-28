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
	if os.Getenv(runtimeDiagnosticsEnvironment) == "" {
		return nil, nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:6060")
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
