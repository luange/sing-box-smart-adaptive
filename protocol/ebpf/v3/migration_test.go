package v3

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestNormalizeXDPDefaultsToAuto(t *testing.T) {
	got, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{Engine: EngineV3})
	if err != nil {
		t.Fatal(err)
	}
	if got.XDP.Mode != "auto" {
		t.Fatalf("xdp mode = %q, want auto", got.XDP.Mode)
	}
}

func TestNormalizeXDPRejectsV2(t *testing.T) {
	_, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{
		Engine: EngineV2,
		XDP:    option.EBPFXDPOptions{Enabled: true},
	})
	if err == nil {
		t.Fatal("xdp enabled on v2 must be rejected")
	}
}

func TestNormalizeXDPRejectsUnknownMode(t *testing.T) {
	_, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{
		Engine: EngineV3,
		XDP:    option.EBPFXDPOptions{Mode: "driver"},
	})
	if err == nil {
		t.Fatal("unknown xdp mode must be rejected")
	}
}
