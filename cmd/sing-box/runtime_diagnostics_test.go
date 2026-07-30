package main

import "testing"

func TestRuntimeDiagnosticsAllowsOnlyConfigurableLoopback(t *testing.T) {
	t.Setenv(runtimeDiagnosticsEnvironment, "127.0.0.1:0")
	server, err := startRuntimeDiagnostics()
	if err != nil || server == nil {
		t.Fatalf("loopback diagnostics failed: server=%v err=%v", server, err)
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv(runtimeDiagnosticsEnvironment, "0.0.0.0:6060")
	if _, err = startRuntimeDiagnostics(); err == nil {
		t.Fatal("non-loopback diagnostics address was accepted")
	}
}
